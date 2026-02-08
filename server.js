const express = require('express');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const path = require('path');
const { isBlocked } = require('./blocklist');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_REDIRECTS = 10;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CSP for the Drift UI itself (static files)
const DRIFT_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "frame-src 'self'",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

app.use((req, res, next) => {
  // Only apply Drift CSP to non-proxy routes
  if (!req.path.startsWith('/proxy/')) {
    res.set('Content-Security-Policy', DRIFT_CSP);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'no-referrer');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

let blockedCount = 0;
let adBlockEnabled = true;

app.get('/blocked-count', (req, res) => {
  res.json({ count: blockedCount });
});

app.post('/adblock', (req, res) => {
  adBlockEnabled = req.body.enabled !== false;
  res.json({ enabled: adBlockEnabled });
});

function fetchWithRedirects(targetUrl, redirectCount, callback, options) {
  if (redirectCount > MAX_REDIRECTS) {
    return callback(new Error('Too many redirects'), null);
  }

  try {
    const parsedUrl = new URL(targetUrl);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const proxyReq = protocol.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': (options && options.accept) || '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'DNT': '1',
        'Sec-GPC': '1'
      }
    }, (proxyRes) => {
      const statusCode = proxyRes.statusCode;

      // Handle redirects (301, 302, 303, 307, 308)
      if (statusCode >= 300 && statusCode < 400 && proxyRes.headers.location) {
        proxyRes.resume(); // drain the response so the socket can be reused
        proxyReq.setTimeout(0); // cancel the timeout for this request
        const redirectUrl = new URL(proxyRes.headers.location, targetUrl).href;
        console.log(`Redirect ${statusCode}: ${targetUrl} -> ${redirectUrl}`);
        return fetchWithRedirects(redirectUrl, redirectCount + 1, callback, options);
      }

      let data = [];

      proxyRes.on('data', chunk => {
        data.push(chunk);
      });

      proxyRes.on('end', () => {
        callback(null, {
          statusCode,
          headers: proxyRes.headers,
          body: Buffer.concat(data),
          finalUrl: targetUrl
        });
      });
    });

    proxyReq.on('error', (err) => {
      callback(err, null);
    });

    proxyReq.setTimeout(10000, () => {
      proxyReq.destroy();
      callback(new Error('Request timed out'), null);
    });

  } catch (err) {
    callback(err, null);
  }
}

function rewriteUrls(html, baseUrl) {
  const base = new URL(baseUrl);

  function toProxyUrl(raw) {
    try {
      // Decode HTML entities before resolving (e.g. &amp; → &)
      raw = raw.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
      const resolved = new URL(raw, baseUrl).href;
      return '/proxy/' + encodeURIComponent(resolved);
    } catch {
      return raw;
    }
  }

  // Rewrite href, src, action attributes
  html = html.replace(
    /(<[^>]+\s)(href|src|action)\s*=\s*"([^"]*?)"/gi,
    (match, pre, attr, url) => {
      if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('#')) return match;
      return `${pre}${attr}="${toProxyUrl(url)}"`;
    }
  );
  html = html.replace(
    /(<[^>]+\s)(href|src|action)\s*=\s*'([^']*?)'/gi,
    (match, pre, attr, url) => {
      if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('#')) return match;
      return `${pre}${attr}='${toProxyUrl(url)}'`;
    }
  );

  // Rewrite srcset attributes
  html = html.replace(
    /srcset\s*=\s*"([^"]*)"/gi,
    (match, value) => {
      const rewritten = value.split(',').map(entry => {
        const parts = entry.trim().split(/\s+/);
        if (parts[0]) parts[0] = toProxyUrl(parts[0]);
        return parts.join(' ');
      }).join(', ');
      return `srcset="${rewritten}"`;
    }
  );

  // Rewrite url() in styles — but protect <script> blocks first
  // so we don't corrupt JavaScript strings containing url(...)
  const scripts = [];
  html = html.replace(/<script[\s\S]*?<\/script>/gi, (m) => {
    scripts.push(m);
    return `<!--DS${scripts.length - 1}-->`;
  });

  html = html.replace(
    /url\(\s*['"]?([^'")]+?)['"]?\s*\)/gi,
    (match, url) => {
      if (url.startsWith('data:')) return match;
      return `url('${toProxyUrl(url)}')`;
    }
  );

  // Restore <script> blocks
  html = html.replace(/<!--DS(\d+)-->/g, (_, i) => scripts[i]);

  return html;
}

function stripTrackingElements(html) {
  // Remove common tracking pixels (1x1 images)
  html = html.replace(/<img[^>]+(?:width|height)\s*=\s*["']?1["']?[^>]+(?:width|height)\s*=\s*["']?1["']?[^>]*\/?>/gi, '');

  // Remove known tracking script patterns
  html = html.replace(/<script[^>]*>[^<]*(?:google-analytics|googletagmanager|gtag|fbq|_gaq|ga\s*\(|analytics\.js|adsbygoogle|googlesyndication|doubleclick|hotjar|clarity|mixpanel|segment|amplitude|heap)[^<]*<\/script>/gi, '');

  // Remove tracking noscript pixels
  html = html.replace(/<noscript[^>]*>\s*<img[^>]+(?:facebook\.com\/tr|google-analytics|googletagmanager|bat\.bing|analytics)[^>]*\/?>\s*<\/noscript>/gi, '');

  return html;
}

function injectMetaScript(html, finalUrl) {
  const privacyTags = '<meta name="referrer" content="no-referrer"><meta http-equiv="Cache-Control" content="no-store">';

  const escaped = finalUrl.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const script = `<script>(function(){
    // ── Session isolation ──
    // Replace localStorage/sessionStorage with in-memory shims so
    // proxied pages cannot persist data across sessions
    var _mem={},_smem={};
    function makeStore(m){return{getItem:function(k){return m.hasOwnProperty(k)?m[k]:null},setItem:function(k,v){m[k]=''+v},removeItem:function(k){delete m[k]},clear:function(){for(var k in m)delete m[k]},get length(){return Object.keys(m).length},key:function(i){return Object.keys(m)[i]||null}};}
    try{Object.defineProperty(window,'localStorage',{get:function(){return makeStore(_mem)},configurable:false})}catch(e){}
    try{Object.defineProperty(window,'sessionStorage',{get:function(){return makeStore(_smem)},configurable:false})}catch(e){}
    // Block document.cookie reads/writes
    try{Object.defineProperty(document,'cookie',{get:function(){return ''},set:function(){},configurable:false})}catch(e){}
    // Disable IndexedDB, caches API, and service workers
    try{Object.defineProperty(window,'indexedDB',{get:function(){return undefined},configurable:false})}catch(e){}
    try{Object.defineProperty(window,'caches',{get:function(){return undefined},configurable:false})}catch(e){}
    if(navigator.serviceWorker){try{Object.defineProperty(navigator,'serviceWorker',{get:function(){return undefined},configurable:false})}catch(e){}}

    var BASE='${escaped}';
    // Make the page think it's at its original path so SPA routers work
    try{var _b=new URL(BASE);history.replaceState(null,'',_b.pathname+_b.search+_b.hash);}catch(e){}
    function toProxy(u){
      try{var url=new URL(u,BASE);return '/proxy/'+encodeURIComponent(url.href);}catch(e){return u;}
    }
    function isExternal(u){
      try{return new URL(u,BASE).origin!==location.origin;}catch(e){return false;}
    }
    // Intercept link clicks — proxy all links (external and relative)
    document.addEventListener('click',function(e){
      var a=e.target.closest('a');
      if(!a||!a.href)return;
      var h=a.getAttribute('href')||'';
      if(h.startsWith('#')||h.startsWith('javascript:')||h.startsWith('data:'))return;
      if(h.indexOf('/proxy/')!==-1||a.href.indexOf('/proxy/')!==-1)return;
      e.preventDefault();location.href=toProxy(h);
    },true);
    // Intercept form submissions
    document.addEventListener('submit',function(e){
      var f=e.target;if(!f||f.tagName!=='FORM')return;
      var action=f.getAttribute('action')||'';
      if(action.indexOf('/proxy/')!==-1)return;
      var resolved;try{resolved=new URL(action||location.href,BASE).href;}catch(x){return;}
      f.action=toProxy(resolved);
    },true);
    // Intercept window.open to route through proxy
    var _open=window.open;
    window.open=function(u){if(u&&isExternal(u)){return _open.call(window,toProxy(u));}return _open.apply(window,arguments);};
    // Intercept window.close to notify parent
    window.close=function(){window.parent.postMessage({type:'drift-close'},'*');};
    // Helper: should this URL be rewritten through the proxy?
    function needsProxy(u){
      if(!u)return false;
      if(u.indexOf('/proxy/')!==-1)return false;
      if(u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('javascript:')||u.startsWith('#')||u.startsWith('about:'))return false;
      return true;
    }
    // Intercept .src/.href property setters so the browser never fetches unproxied URLs
    // (MutationObserver fires too late — after the browser already starts fetching)
    function patchSrc(proto,prop){
      var d=Object.getOwnPropertyDescriptor(proto,prop);
      if(!d||!d.set)return;
      Object.defineProperty(proto,prop,{
        get:d.get,
        set:function(v){
          if(typeof v==='string'&&needsProxy(v))v=toProxy(v);
          d.set.call(this,v);
        },
        enumerable:d.enumerable,
        configurable:d.configurable
      });
    }
    try{patchSrc(HTMLScriptElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLImageElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLIFrameElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLSourceElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLVideoElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLAudioElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLEmbedElement.prototype,'src')}catch(e){}
    try{patchSrc(HTMLLinkElement.prototype,'href')}catch(e){}
    // Intercept fetch() so dynamic requests go through the proxy
    if(window.fetch){var _fetch=window.fetch;window.fetch=function(input,init){
      try{
        var u=typeof input==='string'?input:(input&&input.url)||'';
        if(needsProxy(u)){var p=toProxy(u);if(typeof input==='string')input=p;else input=new Request(p,input);}
      }catch(e){}
      return _fetch.call(window,input,init);
    };}
    // Intercept XMLHttpRequest.open so AJAX requests go through the proxy
    var _xhrOpen=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(){
      var url=arguments[1];
      if(typeof url==='string'&&needsProxy(url)){
        try{var a=Array.prototype.slice.call(arguments);a[1]=toProxy(url);return _xhrOpen.apply(this,a);}catch(e){}
      }
      return _xhrOpen.apply(this,arguments);
    };
    // Rewrite src/href on dynamically added elements (script, link, img, etc.)
    function _rwEl(el){
      if(!el||el.nodeType!==1)return;
      var tag=el.tagName;if(!tag)return;
      var attr=null;
      if(tag==='LINK')attr='href';
      else if(tag==='SCRIPT'||tag==='IMG'||tag==='IFRAME'||tag==='SOURCE'||tag==='VIDEO'||tag==='AUDIO'||tag==='EMBED')attr='src';
      if(!attr)return;
      var v=el.getAttribute(attr);
      if(v&&needsProxy(v)){try{el.setAttribute(attr,toProxy(v));}catch(e){}}
    }
    try{new MutationObserver(function(muts){muts.forEach(function(m){
      if(m.type==='childList'){m.addedNodes.forEach(function(n){
        _rwEl(n);
        if(n.querySelectorAll){try{n.querySelectorAll('script[src],link[href],img[src],source[src],video[src],audio[src],iframe[src],embed[src]').forEach(_rwEl);}catch(e){}}
      });}
      else if(m.type==='attributes'){_rwEl(m.target);}
    });}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['src','href']});}catch(e){}
    // Send metadata
    function send(){
      var fav='';
      var el=document.querySelector('link[rel~="icon"]')||document.querySelector('link[rel="shortcut icon"]');
      if(el)fav=el.href;
      else try{fav=new URL('/favicon.ico',BASE).href}catch(e){}
      window.parent.postMessage({type:'drift-meta',title:document.title||'',favicon:fav,url:BASE},'*');
    }
    if(document.readyState==='complete')send();
    else window.addEventListener('load',send);
  })()<\/script>`;

  // Inject at the very top of <head> so interceptors run before any page scripts
  const injection = privacyTags + script;
  if (/<head[^>]*>/i.test(html)) {
    return html.replace(/<head[^>]*>/i, '$&' + injection);
  }
  return injection + html;
}

app.get('/proxy/*', (req, res) => {
  let targetUrl = decodeURIComponent(req.params[0]);

  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing target URL' });
  }

  // Block ad/tracker domains (skip if ad blocking is disabled)
  if (adBlockEnabled) {
    try {
      const hostname = new URL(targetUrl).hostname;
      if (isBlocked(hostname)) {
        blockedCount++;
        console.log(`Blocked: ${hostname} (${blockedCount} total)`);
        return res.status(204).end();
      }
    } catch {}
  }

  // Append any query params (e.g. from form submissions like ?q=test) to the target
  const queryKeys = Object.keys(req.query);
  if (queryKeys.length > 0) {
    const parsed = new URL(targetUrl);
    for (const [key, value] of Object.entries(req.query)) {
      parsed.searchParams.append(key, value);
    }
    targetUrl = parsed.href;
  }

  let responded = false;
  const fetchOptions = { accept: req.headers.accept || '*/*' };
  fetchWithRedirects(targetUrl, 0, (err, response) => {
    if (responded) return;
    responded = true;
    if (err) {
      if (err.message === 'Too many redirects') {
        return res.status(508).json({ error: 'Too many redirects' });
      }
      if (err.message === 'Request timed out') {
        return res.status(504).json({ error: 'Request timed out' });
      }
      return res.status(500).json({ error: `Failed to fetch: ${err.message}` });
    }

    const contentType = response.headers['content-type'] || 'text/html';

    // Privacy: prevent browser from caching proxied content to disk,
    // strip cookies from the remote site, and block referrer leaks
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Referrer-Policy', 'no-referrer');
    res.set('X-Content-Type-Options', 'nosniff');
    // Don't forward remote site cookies to the user's browser
    res.removeHeader('Set-Cookie');
    // Strip headers that block iframe embedding
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy-Report-Only');
    // Apply a permissive CSP for proxied content — allows same-origin
    // resources (all URLs are rewritten to /proxy/*) and inline code,
    // but blocks plugins and restricts base-uri
    // Permissive CSP: rewritten URLs go through /proxy/* ('self'),
    // but dynamic JS-loaded resources may hit external origins
    res.set('Content-Security-Policy', [
      "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
      "img-src * data: blob:",
      "media-src * data: blob:",
      "font-src * data:",
      "connect-src * data: blob:",
      "object-src 'none'",
      "base-uri 'self'",
    ].join('; '));

    const finalUrl = response.finalUrl || targetUrl;

    // Rewrite URLs in HTML responses so links stay within the proxy
    if (contentType.includes('text/html')) {
      const charset = (contentType.match(/charset=([^\s;]+)/i) || [])[1] || 'utf-8';
      let html = response.body.toString(charset);
      html = stripTrackingElements(html);
      html = rewriteUrls(html, finalUrl);
      html = injectMetaScript(html, finalUrl);
      res.status(response.statusCode).send(html);
    } else if (contentType.includes('text/css')) {
      // Rewrite url() references in CSS so fonts/images stay proxied
      let css = response.body.toString('utf-8');
      css = css.replace(
        /url\(\s*['"]?([^'")]+?)['"]?\s*\)/gi,
        (match, url) => {
          if (url.startsWith('data:')) return match;
          try {
            const resolved = new URL(url, finalUrl).href;
            return `url('/proxy/${encodeURIComponent(resolved)}')`;
          } catch {
            return match;
          }
        }
      );
      res.status(response.statusCode).send(css);
    } else if (contentType.includes('javascript')) {
      // Rewrite relative paths in JS so ES module imports resolve correctly
      let js = response.body.toString('utf-8');

      function resolveJsPath(relPath) {
        try {
          const resolved = new URL(relPath, finalUrl).href;
          return '/proxy/' + encodeURIComponent(resolved);
        } catch {
          return relPath;
        }
      }

      // Rewrite static imports: from "./foo.js" / from './foo.js'
      js = js.replace(
        /(\bfrom\s*)(["'])(\.\.?\/[^"']+)\2/g,
        (match, prefix, quote, path) => `${prefix}${quote}${resolveJsPath(path)}${quote}`
      );

      // Rewrite side-effect imports: import "./foo.js" / import'./foo.js'
      js = js.replace(
        /(\bimport\s*)(["'])(\.\.?\/[^"']+)\2/g,
        (match, prefix, quote, path) => `${prefix}${quote}${resolveJsPath(path)}${quote}`
      );

      // Rewrite dynamic imports: import("./foo.js") / import('./foo.js')
      js = js.replace(
        /(\bimport\s*\(\s*)(["'])(\.\.?\/[^"']+)\2(\s*\))/g,
        (match, pre, quote, path, post) => `${pre}${quote}${resolveJsPath(path)}${quote}${post}`
      );

      // Rewrite Vite/webpack asset paths in string arrays like ["assets/foo.css"]
      // These are relative to site root, not the JS file
      js = js.replace(
        /(\[(?:\s*"(?:assets\/[^"]+)"(?:\s*,)?)+\s*\])/g,
        (match) => {
          return match.replace(/"(assets\/[^"]+)"/g, (m, path) => {
            try {
              const resolved = new URL('/' + path, finalUrl).href;
              return '"/proxy/' + encodeURIComponent(resolved) + '"';
            } catch {
              return m;
            }
          });
        }
      );

      // Rewrite url() in JS strings (e.g. CSS-in-JS)
      js = js.replace(
        /url\(\s*['"]?(\.\.?\/[^'")]+?)['"]?\s*\)/gi,
        (match, url) => {
          if (url.startsWith('data:')) return match;
          return `url('${resolveJsPath(url)}')`;
        }
      );

      // Rewrite new URL("path", import.meta.url) pattern used by Vite for workers/assets
      js = js.replace(
        /new\s+URL\(\s*(["'])([^"']+)\1\s*,\s*import\.meta\.url\s*\)/g,
        (match, quote, path) => {
          if (path.startsWith('data:') || path.startsWith('http:') || path.startsWith('https:') || path.startsWith('/proxy/')) return match;
          return `new URL(${quote}${resolveJsPath(path)}${quote}, import.meta.url)`;
        }
      );

      // Rewrite absolute path strings that reference known asset types (fonts, images, etc.)
      // This catches paths like "/Rubik-VariableWeight.woff2" used by FontFace in workers
      js = js.replace(
        /(["'])(\/[^"']*\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|svg|webp|avif|ico|mp[34]|webm|ogg|wav|json))\1/gi,
        (match, quote, path) => {
          if (path.startsWith('/proxy/')) return match;
          try {
            const resolved = new URL(path, finalUrl).href;
            return `${quote}/proxy/${encodeURIComponent(resolved)}${quote}`;
          } catch {
            return match;
          }
        }
      );

      res.status(response.statusCode).send(js);
    } else {
      res.status(response.statusCode).send(response.body);
    }
  }, fetchOptions);
});

app.listen(PORT, () => {
  console.log(`Proxy server running at http://localhost:${PORT}`);
});
