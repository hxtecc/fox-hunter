// ================================================================
// 银狐猎手 - 页面注入脚本（完整增强版 v3）
// 支持：小圆球UI + 拖动/悬停卡片/关闭菜单 + 扫描节流 + DNS劫持显示
//       + 政府网站标签扫描 + 手动刷新按钮 + 恢复显示按钮
// ================================================================

// ================================================================
// 第一部分：ICP 备案扫描引擎
// ================================================================

const ICP_PROVINCE_ABBREVIATIONS = [
  '京', '津', '沪', '渝', '冀', '豫', '云', '滇', '辽', '黑', '湘', '皖',
  '鲁', '新', '苏', '浙', '赣', '鄂', '桂', '甘', '陇', '晋', '蒙', '陕',
  '秦', '吉', '闽', '贵', '黔', '粤', '川', '蜀', '青', '藏', '琼', '宁'
];

const ICP_PROVINCE_PATTERN = ICP_PROVINCE_ABBREVIATIONS.join('|');

const ICP_BLACKLIST = new Set();
(function buildIcpBlacklist() {
  const provinces = [...'京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏琼宁'];
  for (const p of provinces) {
    ICP_BLACKLIST.add(p + 'ICP备10000000号');
    ICP_BLACKLIST.add(p + 'ICP证10000000号');
    ICP_BLACKLIST.add(p + 'ICP备10000000号-1');
    ICP_BLACKLIST.add(p + 'ICP备00000000号');
  }
})();

const ICP_REGEXES = [
  new RegExp('(' + ICP_PROVINCE_PATTERN + ')\\s*ICP\\s*[备证]\\s*\\d{6,12}\\s*号(?:\\s*-\\s*\\d+)?', 'gi'),
  new RegExp('(' + ICP_PROVINCE_PATTERN + ')\\s*ICP\\s*[备证]\\s*\\d{6,12}', 'gi'),
  new RegExp('(' + ICP_PROVINCE_PATTERN + ')\\s*[A-Za-z]\\d?\\s*-\\s*\\d{6,}(?:-\\d+)?', 'gi'),
  new RegExp('(' + ICP_PROVINCE_PATTERN + ')\\s*公网安备\\s*\\d{10,}\\s*号', 'gi')
];

function scanICPInPage() {
  var meta = document.querySelector('meta[name="icp"], meta[name="ICP"]');
  if (meta) {
    var content = meta.getAttribute('content') || '';
    if (content && /ICP[备证]/.test(content)) {
      var trimmed = content.trim();
      if (!ICP_BLACKLIST.has(trimmed)) return trimmed;
    }
  }

  var body = document.body;
  if (!body) return null;

  var walker = document.createTreeWalker(
    body, NodeFilter.SHOW_TEXT,
    {
      acceptNode: function(node) {
        var parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        var tag = parent.tagName.toLowerCase();
        if (['script', 'style', 'noscript', 'template', 'svg'].includes(tag)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  var allText = '';
  var node;
  var count = 0;
  var MAX_CHARS = 30000;
  while ((node = walker.nextNode()) && count < MAX_CHARS) {
    var text = node.textContent || '';
    if (text.trim()) {
      allText += text + '\n';
      count += text.length;
    }
  }

  if (allText.length < 100) {
    allText = body.innerText || '';
  }

  var candidates = [];
  for (var i = 0; i < ICP_REGEXES.length; i++) {
    ICP_REGEXES[i].lastIndex = 0;
    var match;
    while ((match = ICP_REGEXES[i].exec(allText)) !== null) {
      var full = match[0].trim();
      if (ICP_BLACKLIST.has(full)) continue;
      if (!candidates.includes(full)) {
        candidates.push(full);
      }
    }
  }

  return candidates.length > 0 ? candidates[0] : null;
}

// ================================================================
// 第二部分：下载链接扫描
// ================================================================

var DOWNLOAD_EXTS = new Set([
  '.exe', '.msi', '.msix', '.appx', '.appxbundle',
  '.zip', '.rar', '.7z', '.iso',
  '.apk', '.apks', '.xapk', '.aab',
  '.dmg', '.pkg',
  '.deb', '.rpm', '.AppImage', '.tar.gz', '.tar.bz2', '.sh',
  '.img', '.bin', '.jar', '.run',
  '.gz', '.tar', '.tgz', '.bz2', '.xz', '.zst'
]);

var SUSPICIOUS_KEYWORDS = [
  'wps', 'weixin', 'qq', 'office', 'download', 'soft', 'setup',
  'patch', 'crack', 'green', '破解', '下载', '免费', '安装'
];

function getDownloadExt(href) {
  var lower = href.toLowerCase();
  for (var ext of DOWNLOAD_EXTS) {
    if (lower.endsWith(ext)) return ext;
  }
  return null;
}

function isSuspiciousLink(href, text) {
  var lower = href.toLowerCase();
  for (var kw of SUSPICIOUS_KEYWORDS) {
    if (lower.includes(kw)) return true;
  }
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower)) return true;
  var t = (text || '').toLowerCase();
  for (var kw of SUSPICIOUS_KEYWORDS) {
    if (t.includes(kw)) return true;
  }
  return false;
}

function scanDownloadLinks() {
  var found = [];
  var suspicious = [];
  var pageDomain = location.hostname;

  // 递归扫描元素（包括 Shadow DOM 和同源 iframe）
  function scanElement(root) {
    if (!root) return;

    // 扫描所有可能包含下载链接的属性
    var selectors = 'a[href], [data-href], [data-url], [data-src], [data-download], [data-link], [download], area[href]';
    var elements = root.querySelectorAll ? root.querySelectorAll(selectors) : [];

    for (var el of elements) {
      // 检查所有可能的 URL 属性
      var urls = [];
      if (el.href) urls.push(el.href);
      if (el.dataset) {
        for (var key in el.dataset) {
          var val = el.dataset[key];
          if (val && (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('blob:') || val.startsWith('data:'))) {
            urls.push(val);
          }
        }
      }
      var dataHref = el.getAttribute('data-href') || el.getAttribute('data-url') || el.getAttribute('data-src') || el.getAttribute('data-download') || el.getAttribute('data-link');
      if (dataHref) urls.push(dataHref);

      for (var href of urls) {
        if (!href) continue;

        // 支持 http/https/blob/data 协议
        var isHttp = href.startsWith('http://') || href.startsWith('https://');
        var isBlob = href.startsWith('blob:');
        var isData = href.startsWith('data:');
        if (!isHttp && !isBlob && !isData) continue;

        var ext = getDownloadExt(href);
        // blob: 和 data: 协议如果没有扩展名，也视为潜在下载
        if (!ext && !isBlob && !isData) continue;
        if (!ext) ext = isBlob ? 'blob' : (isData ? 'data' : 'unknown');

        var text = el.textContent ? el.textContent.trim() : (el.title || el.getAttribute('aria-label') || '');
        var susp = isSuspiciousLink(href, text);

        // 检测跨域下载
        var isCrossDomain = false;
        if (isHttp) {
          try {
            var linkDomain = new URL(href).hostname;
            isCrossDomain = linkDomain !== pageDomain && !linkDomain.endsWith('.' + pageDomain);
          } catch (e) {}
        } else if (isBlob || isData) {
          isCrossDomain = false; // blob/data 不算跨域
        }

        var entry = {
          url: href,
          ext: ext,
          isSusp: susp,
          isCrossDomain: isCrossDomain,
          element: el,
          text: text,
          _id: href + '|' + ext
        };

        found.push(entry);
        if (susp) suspicious.push(entry);
      }
    }

    // 递归扫描 Shadow DOM
    var allElements = root.querySelectorAll ? root.querySelectorAll('*') : [];
    for (var elem of allElements) {
      if (elem.shadowRoot) {
        scanElement(elem.shadowRoot);
      }
    }
  }

  // 扫描主文档
  scanElement(document);

  // 扫描同源 iframe
  var iframes = document.querySelectorAll('iframe');
  for (var iframe of iframes) {
    try {
      var iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
      if (iframeDoc) scanElement(iframeDoc);
    } catch (e) {
      // 跨域 iframe，无法访问
    }
  }

  return { found: found, suspicious: suspicious };
}

function markSuspiciousLinks(suspiciousList) {
  for (var item of suspiciousList) {
    var el = item.element;
    if (el.dataset.foxMarked === 'true') continue;
    el.dataset.foxMarked = 'true';

    var borderColor = item.isCrossDomain ? '#ff6b35' : 'var(--danger, #ef5350)';
    el.style.border = '2px solid ' + borderColor;
    el.style.borderRadius = '4px';
    el.style.padding = '2px 6px';
    el.style.display = 'inline-block';
    el.style.backgroundColor = item.isCrossDomain ? 'rgba(255,107,53,0.10)' : 'rgba(239, 83, 80, 0.10)';

    var crossLabel = item.isCrossDomain ? ' [跨域下载]' : '';
    el.title = '银狐猎手：此下载链接存在可疑特征' + crossLabel + '，请谨慎确认来源！';

    if (!el.querySelector('.fox-warning-marker')) {
      var marker = document.createElement('span');
      marker.className = 'fox-warning-marker';
      marker.textContent = item.isCrossDomain ? '🌐⚠️' : '⚠️';
      marker.style.marginLeft = '4px';
      marker.style.fontSize = '13px';
      el.appendChild(marker);
    }
  }
}

function clearAllMarks() {
  document.querySelectorAll('[data-fox-marked="true"]').forEach(function(el) {
    el.dataset.foxMarked = 'false';
    el.style.border = '';
    el.style.borderRadius = '';
    el.style.padding = '';
    el.style.display = '';
    el.style.backgroundColor = '';
    el.title = '';
    var marker = el.querySelector('.fox-warning-marker');
    if (marker) marker.remove();
  });
}

// ================================================================
// 第二B部分：跳转链接检测 + 跳转拦截系统
// ================================================================

// ---- 跳转拦截：辅助函数 ----
var foxConfigCache = null;
var foxWhitelistCache = { builtin: new Set(), gov: [], download: new Set() };
var foxBlacklistCache = null;
var foxIgnoredDomainsCache = new Set();
var foxRedirectSuppress = new Map(); // domain -> timestamp (1h)

function getMainDomain(domain) {
  if (!domain) return '';
  var parts = domain.split('.');
  if (parts.length <= 2) return domain;
  // 处理 co.cn / com.cn 等二级后缀
  var twoLevel = ['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'co.uk', 'com.au'];
  var last2 = parts.slice(-2).join('.');
  if (twoLevel.includes(last2)) {
    return parts.length >= 3 ? parts.slice(-3).join('.') : domain;
  }
  return parts.slice(-2).join('.');
}

async function loadFoxConfig() {
  if (foxConfigCache) return foxConfigCache;
  try {
    var resp = await fetch(chrome.runtime.getURL('config.json'));
    foxConfigCache = await resp.json();
    var wl = foxConfigCache.whitelist || {};
    foxWhitelistCache.builtin = new Set(wl.builtin || []);
    foxWhitelistCache.gov = wl.govSuffixes || [];
    foxWhitelistCache.download = new Set(wl.downloadSites || []);
  } catch (e) {}
  return foxConfigCache;
}

async function loadFoxBlacklist() {
  try {
    var result = await chrome.storage.local.get(['foxLogs']);
    // 从站点黑名单模块获取
    var resp = await chrome.runtime.sendMessage({ type: 'getSiteBlacklist' });
    if (resp && resp.success) {
      foxBlacklistCache = new Set((resp.data || []).map(function(item) { return item.domain || item; }));
    }
  } catch (e) {}
  if (!foxBlacklistCache) foxBlacklistCache = new Set();
  return foxBlacklistCache;
}

async function refreshIgnoredDomains() {
  try {
    var result = await chrome.storage.local.get(['foxIgnoredDomains']);
    foxIgnoredDomainsCache = new Set(result.foxIgnoredDomains || []);
  } catch (e) {}
}

function isBuiltinWhitelistLocal(domain) {
  return foxWhitelistCache.builtin.has(domain) ||
    Array.from(foxWhitelistCache.builtin).some(function(d) { return domain.endsWith('.' + d); });
}

function isGovSuffixLocal(domain) {
  var normalized = domain.toLowerCase();
  return foxWhitelistCache.gov.some(function(s) { return normalized === s || normalized.endsWith('.' + s); });
}

function isDownloadSiteLocal(domain) {
  return foxWhitelistCache.download.has(domain);
}

function isUserWhitelistedLocal(domain) {
  // 需要异步检查，但跳转拦截中用缓存
  return false; // 在异步版本中处理
}

async function isUserWhitelistedAsync(domain) {
  try {
    var result = await chrome.storage.local.get(['whitelist']);
    var list = result.whitelist || [];
    return list.includes(domain);
  } catch (e) { return false; }
}

async function isSiteBlacklistedAsync(domain) {
  if (!foxBlacklistCache) await loadFoxBlacklist();
  return foxBlacklistCache.has(domain) || foxBlacklistCache.has(getMainDomain(domain));
}

function isRedirectSuppressed(domain) {
  var ts = foxRedirectSuppress.get(domain);
  if (ts && Date.now() - ts < 3600000) return true;
  foxRedirectSuppress.delete(domain);
  return false;
}

function suppressRedirectForDomain(domain) {
  foxRedirectSuppress.set(domain, Date.now());
}

async function shouldInterceptRedirect(targetUrl) {
  try {
    var targetDomain = new URL(targetUrl).hostname;
    var currentDomain = location.hostname;

    // 同一注册域 → 放行
    if (getMainDomain(currentDomain) === getMainDomain(targetDomain)) return false;

    // 目标在白名单中 → 放行
    if (isBuiltinWhitelistLocal(targetDomain) ||
        isGovSuffixLocal(targetDomain) ||
        isDownloadSiteLocal(targetDomain)) return false;

    // 用户白名单
    if (await isUserWhitelistedAsync(targetDomain)) return false;

    // 1小时内不提示
    if (isRedirectSuppressed(targetDomain)) return false;

    // 在黑名单中 → 直接阻止
    if (await isSiteBlacklistedAsync(targetDomain)) return 'blocked';

    // 其他 → 需要确认
    return true;
  } catch (e) {
    return false;
  }
}

function openRedirectWarning(targetUrl, triggerType) {
  // 记录日志
  var logEntry = {
    source: location.href,
    target: targetUrl,
    trigger: triggerType,
    time: Date.now(),
    userAction: 'pending'
  };

  // 通知 background 记录日志
  chrome.runtime.sendMessage({
    type: 'redirectWarning',
    data: logEntry
  }).catch(function() {});

  // 打开警告页面
  chrome.runtime.sendMessage({
    type: 'openRedirectWarning',
    target: targetUrl,
    source: location.href
  }).catch(function() {});
}

function blockRedirect(targetUrl, triggerType) {
  chrome.runtime.sendMessage({
    type: 'addSiteBlacklist',
    domain: new URL(targetUrl).hostname,
    source: 'redirect_intercept'
  }).catch(function() {});

  showToast('已阻止跳转到可疑网站: ' + new URL(targetUrl).hostname, 'danger');
}

// 预加载配置
loadFoxConfig();
refreshIgnoredDomains();
loadFoxBlacklist();

// 原始跳转检测扫描（保留）
function scanRedirectLinks() {
  var redirects = [];

  // 扫描内联脚本中的跳转模式
  var scripts = document.querySelectorAll('script:not([src])');
  for (var s of scripts) {
    var code = s.textContent || '';
    var locMatches = code.match(/window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/g);
    if (locMatches) {
      for (var m of locMatches) {
        var urlMatch = m.match(/['"]([^'"]+)['"]/);
        if (urlMatch && urlMatch[1]) {
          var url = urlMatch[1];
          if (url.startsWith('http://') || url.startsWith('https://')) {
            redirects.push({ type: 'window.location', url: url, source: 'inline-script' });
          }
        }
      }
    }
    var openMatches = code.match(/window\.open\s*\(\s*['"]([^'"]+)['"]/g);
    if (openMatches) {
      for (var m of openMatches) {
        var urlMatch = m.match(/['"]([^'"]+)['"]/);
        if (urlMatch && urlMatch[1]) {
          var url = urlMatch[1];
          if (url.startsWith('http://') || url.startsWith('https://')) {
            redirects.push({ type: 'window.open', url: url, source: 'inline-script' });
          }
        }
      }
    }
    var replaceMatches = code.match(/location\.replace\s*\(\s*['"]([^'"]+)['"]/g);
    if (replaceMatches) {
      for (var m of replaceMatches) {
        var urlMatch = m.match(/['"]([^'"]+)['"]/);
        if (urlMatch && urlMatch[1]) {
          var url = urlMatch[1];
          if (url.startsWith('http://') || url.startsWith('https://')) {
            redirects.push({ type: 'location.replace', url: url, source: 'inline-script' });
          }
        }
      }
    }
    var assignMatches = code.match(/location\.assign\s*\(\s*['"]([^'"]+)['"]/g);
    if (assignMatches) {
      for (var m of assignMatches) {
        var urlMatch = m.match(/['"]([^'"]+)['"]/);
        if (urlMatch && urlMatch[1]) {
          var url = urlMatch[1];
          if (url.startsWith('http://') || url.startsWith('https://')) {
            redirects.push({ type: 'location.assign', url: url, source: 'inline-script' });
          }
        }
      }
    }
  }

  // 扫描 meta refresh 标签
  var metaRefreshTags = document.querySelectorAll('meta[http-equiv="refresh"]');
  for (var meta of metaRefreshTags) {
    var content = meta.getAttribute('content') || '';
    var urlMatch = content.match(/url=(.+)/i);
    if (urlMatch && urlMatch[1]) {
      var url = urlMatch[1].trim().replace(/^['"]/, '').replace(/['"]$/, '');
      if (url.startsWith('http://') || url.startsWith('https://')) {
        redirects.push({ type: 'meta-refresh', url: url, source: 'meta-tag' });
      }
    }
  }

  // 扫描 onclick 中的跳转
  var autoLinks = document.querySelectorAll('a[onclick*="location"], a[onclick*="open"], [onclick*="location.href"]');
  for (var a of autoLinks) {
    var onclick = a.getAttribute('onclick') || '';
    var urlMatch = onclick.match(/['"](https?:\/\/[^'"]+)['"]/);
    if (urlMatch && urlMatch[1]) {
      redirects.push({ type: 'onclick-redirect', url: urlMatch[1], source: 'onclick' });
    }
  }

  return redirects;
}

// 运行时跳转拦截（拦截 window.location.assign/replace 和 window.open）
var runtimeRedirects = [];
var redirectHooksActivated = false;

function activateRedirectHooks() {
  if (redirectHooksActivated) return;
  redirectHooksActivated = true;

  // 检查跳转拦截是否启用
  chrome.storage.local.get(['settings'], function(result) {
    var settings = result.settings || {};
    if (settings.redirect && settings.redirect.enabled === false) return;

    // 拦截 window.location.assign
    var originalAssign = window.location.assign;
    try {
      window.location.assign = function(url) {
        if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
          runtimeRedirects.push({ type: 'location.assign', url: url, source: 'runtime-hook', time: Date.now() });
          // 异步检查是否需要拦截
          shouldInterceptRedirect(url).then(function(result) {
            if (result === 'blocked') {
              blockRedirect(url, 'location.assign');
            } else if (result === true) {
              openRedirectWarning(url, 'location.assign');
            }
          });
        }
        return originalAssign.call(window.location, url);
      };
    } catch (e) {}

    // 拦截 window.location.replace
    var originalReplace = window.location.replace;
    try {
      window.location.replace = function(url) {
        if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
          runtimeRedirects.push({ type: 'location.replace', url: url, source: 'runtime-hook', time: Date.now() });
          shouldInterceptRedirect(url).then(function(result) {
            if (result === 'blocked') {
              blockRedirect(url, 'location.replace');
            } else if (result === true) {
              openRedirectWarning(url, 'location.replace');
            }
          });
        }
        return originalReplace.call(window.location, url);
      };
    } catch (e) {}

    // 拦截 window.open
    var originalOpen = window.open;
    window.open = function(url) {
      if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
        runtimeRedirects.push({ type: 'window.open', url: url, source: 'runtime-hook', time: Date.now() });
        shouldInterceptRedirect(url).then(function(result) {
          if (result === 'blocked') {
            blockRedirect(url, 'window.open');
          } else if (result === true) {
            openRedirectWarning(url, 'window.open');
          }
        });
      }
      return originalOpen.apply(window, arguments);
    };

    // 拦截 <a> 标签点击（target="_blank" 除外）
    document.addEventListener('click', function(e) {
      var anchor = e.target;
      while (anchor && anchor.tagName !== 'A') {
        anchor = anchor.parentElement;
      }
      if (!anchor || !anchor.href) return;

      var target = anchor.target || '';
      // target="_blank" 不拦截
      if (target === '_blank') return;

      var href = anchor.href;
      if (!href.startsWith('http://') && !href.startsWith('https://')) return;

      shouldInterceptRedirect(href).then(function(result) {
        if (result === 'blocked') {
          e.preventDefault();
          e.stopPropagation();
          blockRedirect(href, 'link-click');
        } else if (result === true) {
          e.preventDefault();
          e.stopPropagation();
          openRedirectWarning(href, 'link-click');
        }
      });
    }, true);

    // 监控 <meta http-equiv="refresh"> 标签
    function checkMetaRefresh() {
      var metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
      for (var meta of metaTags) {
        var content = meta.getAttribute('content') || '';
        var urlMatch = content.match(/url=(.+)/i);
        if (urlMatch && urlMatch[1]) {
          var url = urlMatch[1].trim().replace(/^['"]/, '').replace(/['"]$/, '');
          if (url.startsWith('http://') || url.startsWith('https://')) {
            shouldInterceptRedirect(url).then(function(result) {
              if (result === 'blocked' || result === true) {
                // 移除 meta refresh 标签
                meta.remove();
                if (result === 'blocked') {
                  blockRedirect(url, 'meta-refresh');
                } else {
                  openRedirectWarning(url, 'meta-refresh');
                }
              }
            });
          }
        }
      }
    }
    // 初始检查
    checkMetaRefresh();
    // 定期检查新的 meta refresh 标签
    setInterval(checkMetaRefresh, 2000);
  });
}

function notifyRedirectDetected(url, source) {
  // 立即通知 background 有新的跳转检测
  chrome.runtime.sendMessage({
    type: 'redirectDetected',
    url: url,
    source: source,
    fromPage: location.href
  }).catch(function() {});
}

// ================================================================
// 第三部分：页面指纹采集
// ================================================================

function collectPageFingerprint() {
  var allElements = document.querySelectorAll('*');
  var domCount = allElements.length;

  var externalResourceCount = 0;
  var externalTags = document.querySelectorAll('img[src], script[src], link[href], iframe[src], video[src], audio[src], source[src], embed[src], object[data]');
  for (var el of externalTags) {
    var src = el.src || el.href || el.getAttribute('data') || '';
    if (src && (src.startsWith('http://') || src.startsWith('https://'))) {
      externalResourceCount++;
    }
  }

  var buttonSelectors = 'button, a, input[type="button"], input[type="submit"], [role="button"], .btn, .button, .download';
  var buttons = document.querySelectorAll(buttonSelectors);
  var installKeywords = ['下载', '安装', '立即下载', '免费下载', 'download', 'install', 'get', '立即安装', '一键安装'];
  var hasInstallButton = false;
  for (var btn of buttons) {
    var text = (btn.textContent || '').trim().toLowerCase();
    for (var kw of installKeywords) {
      if (text.includes(kw.toLowerCase())) {
        hasInstallButton = true;
        break;
      }
    }
    if (hasInstallButton) break;
  }

  var hasLoginForm = false;
  var forms = document.querySelectorAll('form');
  for (var form of forms) {
    var inputs = form.querySelectorAll('input[type="password"]');
    if (inputs.length > 0) { hasLoginForm = true; break; }
  }

  var hasCaptcha = false;
  var captchaKeywords = ['captcha', '验证码', 'geetest', 'recaptcha', 'hcaptcha', '滑动验证'];
  var pageHTML = document.documentElement.innerHTML.toLowerCase();
  for (var kw of captchaKeywords) {
    if (pageHTML.includes(kw)) { hasCaptcha = true; break; }
  }

  var frameworkMarkers = [];
  var htmlStr = document.documentElement.outerHTML;
  if (htmlStr.includes('vue') || htmlStr.includes('Vue')) frameworkMarkers.push('vue');
  if (htmlStr.includes('react') || htmlStr.includes('React')) frameworkMarkers.push('react');
  if (htmlStr.includes('angular') || htmlStr.includes('Angular')) frameworkMarkers.push('angular');
  if (htmlStr.includes('jquery') || htmlStr.includes('jQuery')) frameworkMarkers.push('jquery');
  if (htmlStr.includes('bootstrap')) frameworkMarkers.push('bootstrap');
  if (htmlStr.includes('element-ui') || htmlStr.includes('element-plus')) frameworkMarkers.push('element-ui');
  if (htmlStr.includes('antd') || htmlStr.includes('ant-design')) frameworkMarkers.push('antd');

  var bodyText = document.body ? document.body.innerText : '';
  var emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu;
  var emojiMatches = bodyText.match(emojiRegex) || [];
  var emojiDensity = bodyText.length > 0 ? (emojiMatches.length / bodyText.length * 1000) : 0;

  return {
    domCount: domCount,
    externalResourceCount: externalResourceCount,
    hasInstallButton: hasInstallButton,
    hasLoginForm: hasLoginForm,
    hasCaptcha: hasCaptcha,
    frameworkMarkers: frameworkMarkers,
    pageTitle: document.title || '',
    pageText: (document.body ? document.body.innerText : '').slice(0, 5000),
    emojiDensity: emojiDensity
  };
}

// ================================================================
// 第三B部分：政府网站标签扫描（动态识别白名单）
// ================================================================

function scanGovSiteLabels() {
  var govKeywords = ['党政机关', '政府网站', '政府网站找错', '政府机构', '人民政府'];
  var govLinks = ['www.gov.cn', 'gov.cn'];
  var found = false;

  // 扫描 footer 区域
  var footer = document.querySelector('footer');
  if (footer) {
    var footerText = footer.textContent || '';
    for (var kw of govKeywords) {
      if (footerText.includes(kw)) { found = true; break; }
    }
    if (!found) {
      var footerLinks = footer.querySelectorAll('a[href]');
      for (var a of footerLinks) {
        var href = a.href || '';
        for (var gl of govLinks) {
          if (href.includes(gl)) { found = true; break; }
        }
        if (found) break;
      }
    }
  }

  // 扫描页面底部 div
  if (!found) {
    var bottomDivs = document.querySelectorAll('div.copyright, div.footer, div#footer, div.bottom');
    for (var div of bottomDivs) {
      var text = div.textContent || '';
      for (var kw of govKeywords) {
        if (text.includes(kw)) { found = true; break; }
      }
      if (found) break;
    }
  }

  return found;
}

// ================================================================
// 第四部分：小圆球 UI（悬浮球）
// ================================================================

// 默认设置
var DEFAULT_BALL_SETTINGS = {
  safeColor: '#10b981',
  warningColor: '#f59e0b',
  dangerColor: '#ef5350',
  safeThreshold: 50,
  dangerThreshold: 100,
  size: 56,
  opacity: 0.8
};

var ballSettings = Object.assign({}, DEFAULT_BALL_SETTINGS);
var ballElement = null;
var ballTooltip = null;
var ballMenu = null;
var restoreButton = null;
var isBallHidden = false;
var isDragging = false;
var dragOffset = { x: 0, y: 0 };
var hoverTimer = null;
var currentScore = 0;
var currentLevel = 'safe';
var currentRules = [];
var currentDomain = '';
var currentICP = '';
var currentDNSIP = '';
var isDNSHijacked = false;
var currentSSLStatus = null; // { valid, expired, selfSigned, issuer }
var currentICPValidation = null; // { valid, formatOk, unitName }

// 加载用户设置
function loadBallSettings() {
  chrome.storage.local.get(['settings'], function(result) {
    var settings = result.settings || {};
    var ball = settings.ball || {};
    ballSettings = Object.assign({}, DEFAULT_BALL_SETTINGS, ball);
    updateBallAppearance();
  });
}

// 创建小圆球
function createBall() {
  if (ballElement) return;

  // 主圆球容器 - 注入到 html 而非 body，防止 SPA 框架替换 body 时丢失
  ballElement = document.createElement('div');
  ballElement.id = 'fox-hunter-ball';
  ballElement.innerHTML = getBallSVG();
  applyBallStyles();
  var injectTarget = document.documentElement || document.body;
  injectTarget.appendChild(ballElement);

  // 悬停卡片
  ballTooltip = document.createElement('div');
  ballTooltip.id = 'fox-hunter-tooltip';
  ballTooltip.style.cssText = 'position:fixed !important;z-index:2147483646 !important;display:none;' +
    'background:rgba(20,20,31,0.95) !important;backdrop-filter:blur(8px) !important;' +
    'border:1px solid rgba(240,192,96,0.3) !important;border-radius:12px !important;' +
    'padding:16px !important;min-width:280px !important;max-width:360px !important;' +
    'font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif !important;' +
    'font-size:13px !important;color:#e8e8f0 !important;box-shadow:0 8px 32px rgba(0,0,0,0.5) !important;' +
    'pointer-events:none !important;transition:opacity 0.2s ease !important;' +
    'will-change:transform !important;';
  injectTarget.appendChild(ballTooltip);

  // 关闭菜单
  ballMenu = document.createElement('div');
  ballMenu.id = 'fox-hunter-menu';
  ballMenu.style.cssText = 'position:fixed !important;z-index:2147483646 !important;display:none;' +
    'background:rgba(20,20,31,0.95) !important;backdrop-filter:blur(8px) !important;' +
    'border:1px solid rgba(240,192,96,0.3) !important;border-radius:10px !important;' +
    'padding:8px 0 !important;min-width:180px !important;' +
    'font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif !important;' +
    'font-size:13px !important;color:#e8e8f0 !important;box-shadow:0 8px 32px rgba(0,0,0,0.5) !important;' +
    'pointer-events:auto !important;';
  injectTarget.appendChild(ballMenu);

  // 恢复按钮（小圆球隐藏时显示）
  restoreButton = document.createElement('div');
  restoreButton.id = 'fox-hunter-restore';
  restoreButton.textContent = '+';
  restoreButton.style.cssText = 'position:fixed !important;z-index:2147483646 !important;display:none;' +
    'width:40px !important;height:40px !important;border-radius:50% !important;' +
    'background:rgba(20,20,31,0.6) !important;backdrop-filter:blur(4px) !important;' +
    'border:1px solid rgba(240,192,96,0.3) !important;' +
    'font-size:24px !important;color:rgba(240,192,96,0.7) !important;' +
    'align-items:center !important;justify-content:center !important;' +
    'cursor:pointer !important;transition:all 0.3s ease !important;' +
    'bottom:20px !important;right:20px !important;' +
    'pointer-events:auto !important;will-change:transform !important;';
  restoreButton.addEventListener('click', restoreBall);
  restoreButton.addEventListener('mouseenter', function() {
    this.style.background = 'rgba(240,192,96,0.2)';
    this.style.color = '#f0c060';
  });
  restoreButton.addEventListener('mouseleave', function() {
    this.style.background = 'rgba(20,20,31,0.6)';
    this.style.color = 'rgba(240,192,96,0.7)';
  });
  injectTarget.appendChild(restoreButton);

  // 启动小圆球保护机制（防止被 SPA 框架移除）
  protectBallElement();

  // 绑定事件
  bindBallEvents();

  // 恢复位置
  restoreBallPosition();
}

function getBallSVG() {
  var size = ballSettings.size;
  var radius = (size - 8) / 2;
  var circumference = 2 * Math.PI * radius;
  var maxScore = 200;
  var scorePercent = Math.min(currentScore / maxScore, 1);
  var dashOffset = circumference * (1 - scorePercent);
  var color = getLevelColor(currentLevel);
  var displayScore = currentScore > 200 ? '200+' : (isDNSHijacked ? '⛔' : currentScore);

  return '<svg width="' + size + '" height="' + size + '" style="position:absolute;top:0;left:0;">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + radius + '" ' +
    'fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="3"/>' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + radius + '" ' +
    'fill="none" stroke="' + color + '" stroke-width="3" ' +
    'stroke-dasharray="' + circumference + '" stroke-dashoffset="' + dashOffset + '" ' +
    'stroke-linecap="round" transform="rotate(-90 ' + (size/2) + ' ' + (size/2) + ')" ' +
    'style="transition:stroke-dashoffset 0.6s ease,stroke 0.6s ease;"/>' +
    '</svg>' +
    '<span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);' +
    'font-size:' + (size * 0.28) + 'px;font-weight:800;color:' + color + ';' +
    'font-family:-apple-system,"PingFang SC",sans-serif;' +
    'transition:color 0.6s ease;">' + displayScore + '</span>';
}

function getLevelColor(level) {
  if (isDNSHijacked) return ballSettings.dangerColor;
  if (level === 'danger') return ballSettings.dangerColor;
  if (level === 'warning') return ballSettings.warningColor;
  return ballSettings.safeColor;
}

function getLevelFromScore(score) {
  if (score >= ballSettings.dangerThreshold) return 'danger';
  if (score >= ballSettings.safeThreshold) return 'warning';
  return 'safe';
}

function applyBallStyles() {
  if (!ballElement) return;
  var size = ballSettings.size;
  var bgColor = getLevelColor(currentLevel);
  ballElement.style.cssText = 'position:fixed !important;z-index:2147483645 !important;' +
    'width:' + size + 'px !important;height:' + size + 'px !important;border-radius:50% !important;' +
    'background:' + bgColor + '20 !important;backdrop-filter:blur(4px) !important;' +
    'opacity:' + ballSettings.opacity + ' !important;' +
    'cursor:grab !important;user-select:none !important;' +
    'display:flex !important;align-items:center !important;justify-content:center !important;' +
    'transition:background-color 0.6s ease,opacity 0.3s ease !important;' +
    'box-shadow:0 4px 16px rgba(0,0,0,0.3) !important;' +
    'pointer-events:auto !important;will-change:transform !important;' +
    (isDNSHijacked ? 'animation:foxBlink 0.5s infinite !important;' : '');
}

// 小圆球保护机制：防止被 SPA 框架移除
var ballProtectionObserver = null;
var ballReinjectTimers = [];

function protectBallElement() {
  if (ballProtectionObserver) ballProtectionObserver.disconnect();

  // MutationObserver 监控 html 节点，检测小圆球是否被移除
  ballProtectionObserver = new MutationObserver(function(mutations) {
    if (!ballElement) return;
    for (var m of mutations) {
      if (m.type === 'childList') {
        var removed = m.removedNodes;
        for (var i = 0; i < removed.length; i++) {
          if (removed[i] === ballElement || removed[i].id === 'fox-hunter-ball') {
            // 小圆球被移除，立即重新插入
            reinjectBall();
            return;
          }
        }
      }
    }
  });

  var observeTarget = document.documentElement || document.body;
  if (observeTarget) {
    ballProtectionObserver.observe(observeTarget, { childList: true, subtree: true });
  }

  // 定时检查（兜底，每 3 秒一次）
  setInterval(function() {
    if (!document.getElementById('fox-hunter-ball') && !isBallHidden) {
      createBall();
    } else if (ballElement && !document.contains(ballElement)) {
      reinjectBall();
    }
  }, 3000);
}

function reinjectBall() {
  var target = document.documentElement || document.body;
  if (!target) return;
  if (ballElement && !document.contains(ballElement)) {
    target.appendChild(ballElement);
  }
  if (ballTooltip && !document.contains(ballTooltip)) {
    target.appendChild(ballTooltip);
  }
  if (ballMenu && !document.contains(ballMenu)) {
    target.appendChild(ballMenu);
  }
  if (restoreButton && !document.contains(restoreButton) && isBallHidden) {
    target.appendChild(restoreButton);
  }
}

function updateBallAppearance() {
  if (!ballElement) return;
  ballElement.innerHTML = getBallSVG();
  applyBallStyles();
}

function updateBallScore(score, level, rules, domain, icp, dnsIP, hijacked, sslStatus, icpValidation) {
  currentScore = score;
  currentLevel = level || getLevelFromScore(score);
  currentRules = rules || [];
  currentDomain = domain || '';
  currentICP = icp || '';
  currentDNSIP = dnsIP || '';
  isDNSHijacked = hijacked || false;
  currentSSLStatus = sslStatus || null;
  currentICPValidation = icpValidation || null;
  throttledBallUpdate(score, currentLevel, currentRules, currentDomain, currentICP, currentDNSIP, isDNSHijacked);
}

// 悬停卡片内容
function updateTooltip() {
  if (!ballTooltip) return;
  var levelText = currentLevel === 'danger' ? '高危' : currentLevel === 'warning' ? '可疑' : '安全';
  var levelColor = getLevelColor(currentLevel);

  var html = '<div style="margin-bottom:8px;">' +
    '<strong style="font-size:15px;color:#f0c060;">' + escapeHtml(currentDomain || location.hostname) + '</strong>' +
    (currentICP ? '<div style="font-size:12px;color:#8888aa;margin-top:2px;">ICP备案: ' + escapeHtml(currentICP) + '</div>' : '') +
    '</div>';

  html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
    '<span style="font-size:20px;font-weight:800;color:' + levelColor + ';">' + currentScore + '</span>' +
    '<span style="padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;' +
    'background:' + levelColor + '20;color:' + levelColor + ';border:1px solid ' + levelColor + '40;">' +
    levelText + '</span></div>';

  if (currentRules.length > 0) {
    html += '<div style="margin-bottom:8px;"><div style="font-size:11px;color:#8888aa;margin-bottom:4px;">命中规则:</div>';
    var sortedRules = currentRules.slice().sort(function(a, b) { return (b.score || 0) - (a.score || 0); });
    for (var r of sortedRules) {
      html += '<div style="font-size:12px;color:#ccc;">• ' + escapeHtml(r.rule || r) +
        (r.score ? ' <span style="color:#f59e0b;">+' + r.score + '</span>' : '') + '</div>';
    }
    html += '</div>';
  }

  if (currentDNSIP) {
    html += '<div style="font-size:12px;color:#40d4c0;">🌐 DNS解析IP: ' + currentDNSIP + '</div>';
  }

  // SSL 证书状态
  if (currentSSLStatus) {
    if (currentSSLStatus.valid && !currentSSLStatus.expired && !currentSSLStatus.selfSigned) {
      html += '<div style="font-size:12px;color:#10b981;">🔒 SSL证书：有效</div>';
    } else if (currentSSLStatus.expired) {
      html += '<div style="font-size:12px;color:#f59e0b;">⚠️ SSL证书：已过期</div>';
    } else if (currentSSLStatus.selfSigned) {
      html += '<div style="font-size:12px;color:#f59e0b;">⚠️ SSL证书：自签名</div>';
    } else {
      html += '<div style="font-size:12px;color:#ef5350;">❌ SSL证书：无效</div>';
    }
  }

  // ICP 备案验证状态
  if (currentICPValidation) {
    if (currentICPValidation.valid) {
      html += '<div style="font-size:12px;color:#10b981;">✅ ICP备案：有效' +
        (currentICPValidation.unitName ? '（备案主体：' + escapeHtml(currentICPValidation.unitName) + '）' : '') + '</div>';
    } else if (currentICPValidation.formatOk === false) {
      html += '<div style="font-size:12px;color:#f59e0b;">⚠️ ICP备案：可疑（格式异常）</div>';
    } else {
      html += '<div style="font-size:12px;color:#ef5350;">❌ ICP备案：虚假（无法核验）</div>';
    }
  } else if (currentICP) {
    html += '<div style="font-size:12px;color:#8888aa;">📋 ICP: ' + escapeHtml(currentICP) + '</div>';
  }

  if (isDNSHijacked) {
    html += '<div style="margin-top:8px;padding:8px;background:rgba(239,83,80,0.15);border-radius:6px;' +
      'border:1px solid rgba(239,83,80,0.3);color:#ef5350;font-size:12px;font-weight:600;">' +
      '⚠️ DNS解析异常，可能存在劫持</div>';
  }

  ballTooltip.innerHTML = html;
}

// 关闭菜单内容
function showBallMenu() {
  if (!ballMenu || !ballElement) return;
  var rect = ballElement.getBoundingClientRect();

  ballMenu.innerHTML = '';
  var items = [
    { text: '🔇 1小时内不再提示', action: 'silent1h' },
    { text: '🚫 本网站不再提示', action: 'ignoreSite' },
    { text: '📋 查看详情', action: 'showDetail' },
    { text: '🔄 恢复显示', action: 'restore', showWhenHidden: true }
  ];

  for (var item of items) {
    var div = document.createElement('div');
    div.style.cssText = 'padding:8px 16px;cursor:pointer;transition:background 0.2s;';
    div.textContent = item.text;
    div.addEventListener('mouseenter', function() { this.style.background = 'rgba(240,192,96,0.1)'; });
    div.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
    div.addEventListener('click', (function(action) {
      return function() {
        handleMenuAction(action);
        ballMenu.style.display = 'none';
      };
    })(item.action));
    ballMenu.appendChild(div);
  }

  ballMenu.style.display = 'block';
  ballMenu.style.left = (rect.left - 190) + 'px';
  ballMenu.style.top = rect.top + 'px';
}

function handleMenuAction(action) {
  switch (action) {
    case 'silent1h':
      // 直接设置静默截止时间
      var until = Date.now() + 3600 * 1000;
      chrome.storage.local.set({ foxSilentUntil: until });
      hideBall();
      break;
    case 'ignoreSite':
      var domain = location.hostname;
      chrome.storage.local.get(['foxIgnoredDomains'], function(result) {
        var list = result.foxIgnoredDomains || [];
        if (!list.includes(domain)) {
          list.push(domain);
          chrome.storage.local.set({ foxIgnoredDomains: list });
        }
      });
      hideBall();
      break;
    case 'showDetail':
      // 尝试打开 popup，失败则通知 background
      if (chrome.action && chrome.action.openPopup) {
        chrome.action.openPopup().catch(function() {
          chrome.runtime.sendMessage({ type: 'openPopup' });
        });
      } else {
        chrome.runtime.sendMessage({ type: 'openPopup' });
      }
      break;
    case 'restore':
      restoreBall();
      break;
  }
}

function hideBall() {
  if (ballElement) ballElement.style.display = 'none';
  if (ballTooltip) ballTooltip.style.display = 'none';
  if (ballMenu) ballMenu.style.display = 'none';
  isBallHidden = true;
  if (restoreButton) restoreButton.style.display = 'flex';
}

function restoreBall() {
  isBallHidden = false;
  if (ballElement) ballElement.style.display = 'flex';
  if (restoreButton) restoreButton.style.display = 'none';
  // 清除该域名的忽略状态和全局静默
  var domain = location.hostname;
  chrome.storage.local.get(['foxIgnoredDomains', 'foxSilentUntil'], function(result) {
    var list = (result.foxIgnoredDomains || []).filter(function(d) { return d !== domain; });
    chrome.storage.local.set({ foxIgnoredDomains: list, foxSilentUntil: 0 });
  });
}

// 绑定小圆球事件
function bindBallEvents() {
  if (!ballElement) return;

  // 拖动
  ballElement.addEventListener('mousedown', function(e) {
    isDragging = true;
    var rect = ballElement.getBoundingClientRect();
    dragOffset.x = e.clientX - rect.left;
    dragOffset.y = e.clientY - rect.top;
    ballElement.style.cursor = 'grabbing';
    e.preventDefault();
  });

  document.addEventListener('mousemove', function(e) {
    if (!isDragging) return;
    var x = e.clientX - dragOffset.x;
    var y = e.clientY - dragOffset.y;
    // 限制在视口内
    x = Math.max(0, Math.min(x, window.innerWidth - ballSettings.size));
    y = Math.max(0, Math.min(y, window.innerHeight - ballSettings.size));
    ballElement.style.left = x + 'px';
    ballElement.style.top = y + 'px';
    ballElement.style.right = 'auto';
    ballElement.style.bottom = 'auto';
  });

  document.addEventListener('mouseup', function() {
    if (!isDragging) return;
    isDragging = false;
    ballElement.style.cursor = 'grab';
    // 保存位置
    saveBallPosition();
  });

  // 悬停显示卡片
  ballElement.addEventListener('mouseenter', function() {
    if (isDragging) return;
    hoverTimer = setTimeout(function() {
      updateTooltip();
      showTooltip();
    }, 300);
  });

  ballElement.addEventListener('mouseleave', function() {
    if (hoverTimer) clearTimeout(hoverTimer);
    if (ballTooltip) ballTooltip.style.display = 'none';
  });

  // 右键显示菜单
  ballElement.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    showBallMenu();
  });

  // 点击显示/隐藏关闭按钮
  var closeBtn = document.createElement('span');
  closeBtn.textContent = '×';
  closeBtn.style.cssText = 'position:absolute;top:-4px;right:-4px;width:18px;height:18px;' +
    'border-radius:50%;background:rgba(0,0,0,0.5);color:#fff;font-size:12px;' +
    'display:none;align-items:center;justify-content:center;cursor:pointer;' +
    'opacity:0.6;transition:opacity 0.2s;z-index:1;';
  closeBtn.addEventListener('mouseenter', function() { this.style.opacity = '1'; });
  closeBtn.addEventListener('mouseleave', function() { this.style.opacity = '0.6'; });
  closeBtn.addEventListener('click', function(e) {
    e.stopPropagation();
    showBallMenu();
  });
  ballElement.appendChild(closeBtn);

  ballElement.addEventListener('mouseenter', function() {
    closeBtn.style.display = 'flex';
  });
  ballElement.addEventListener('mouseleave', function() {
    if (!ballMenu || ballMenu.style.display === 'none') {
      closeBtn.style.display = 'none';
    }
  });
}

function showTooltip() {
  if (!ballTooltip || !ballElement) return;
  var rect = ballElement.getBoundingClientRect();
  var tooltipWidth = 300;
  var left = rect.left - tooltipWidth - 10;
  var top = rect.top;

  if (left < 10) left = rect.right + 10;
  if (top + 200 > window.innerHeight) top = window.innerHeight - 220;

  ballTooltip.style.left = left + 'px';
  ballTooltip.style.top = Math.max(10, top) + 'px';
  ballTooltip.style.display = 'block';
}

function saveBallPosition() {
  if (!ballElement) return;
  var rect = ballElement.getBoundingClientRect();
  try {
    localStorage.setItem('foxBallPosition', JSON.stringify({ x: rect.left, y: rect.top }));
  } catch (e) {}
}

function restoreBallPosition() {
  if (!ballElement) return;
  try {
    var saved = localStorage.getItem('foxBallPosition');
    if (saved) {
      var pos = JSON.parse(saved);
      ballElement.style.left = pos.x + 'px';
      ballElement.style.top = pos.y + 'px';
      ballElement.style.right = 'auto';
      ballElement.style.bottom = 'auto';
      return;
    }
  } catch (e) {}
  // 默认位置：右下角
  ballElement.style.right = '20px';
  ballElement.style.bottom = '20px';
}

// ================================================================
// 第五部分：L0 前置过滤 + 完整扫描 & 上报
// ================================================================

var scanTimer = null;
var scanInterval = null;
var observer = null;
var lastScanHash = '';
var currentIcp = null;
var icpRetryCount = 0;
var MAX_ICP_RETRIES = 3;
var icpRetryTimers = [];
var lastRiskLevel = null;
var alertBarEl = null;
var manualRefreshBtn = null;

// 获取扫描间隔（从设置中读取）
function getScanInterval() {
  chrome.storage.local.get(['settings'], function(result) {
    var settings = result.settings || {};
    var interval = settings.scanInterval || 3;
    setupScanInterval(interval);
  });
}

function setupScanInterval(seconds) {
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }
  if (manualRefreshBtn) {
    manualRefreshBtn.style.display = 'none';
  }

  if (seconds <= 0 || seconds === 'off') {
    // 手动模式：显示刷新按钮
    showManualRefreshButton();
    return;
  }

  scanInterval = setInterval(function() {
    performFullScan();
  }, seconds * 1000);
}

function showManualRefreshButton() {
  if (!manualRefreshBtn) {
    manualRefreshBtn = document.createElement('div');
    manualRefreshBtn.textContent = '🔄';
    manualRefreshBtn.style.cssText = 'position:fixed;z-index:2147483645;' +
      'width:32px;height:32px;border-radius:50%;' +
      'background:rgba(20,20,31,0.8);backdrop-filter:blur(4px);' +
      'border:1px solid rgba(240,192,96,0.3);' +
      'font-size:16px;display:flex;align-items:center;justify-content:center;' +
      'cursor:pointer;transition:all 0.3s ease;';
    manualRefreshBtn.addEventListener('click', function() {
      lastScanHash = '';
      performFullScan();
    });
    document.body.appendChild(manualRefreshBtn);
  }
  // 定位在小圆球旁边
  if (ballElement) {
    var rect = ballElement.getBoundingClientRect();
    manualRefreshBtn.style.left = (rect.left - 40) + 'px';
    manualRefreshBtn.style.top = rect.top + 'px';
  } else {
    manualRefreshBtn.style.right = '80px';
    manualRefreshBtn.style.bottom = '20px';
  }
  manualRefreshBtn.style.display = 'flex';
}

// L0 前置检测
function hasDownloadOrRedirectLinks() {
  var downloadResult = scanDownloadLinks();
  var redirectLinks = scanRedirectLinks();
  return {
    hasDownloads: downloadResult.found.length > 0,
    hasRedirects: redirectLinks.length > 0,
    downloadResult: downloadResult,
    redirectLinks: redirectLinks
  };
}

function performFullScan() {
  var links = document.querySelectorAll('a[href]');
  var hash = '';
  for (var i = 0; i < Math.min(links.length, 50); i++) {
    hash += links[i].href + '|';
  }
  if (hash === lastScanHash && currentIcp !== null) return;
  lastScanHash = hash;

  var l0Result = hasDownloadOrRedirectLinks();

  // 无论 L0 是否通过，都始终执行完整扫描（采集 ICP、指纹等）
  var icp = scanICPInPage();
  if (icp) currentIcp = icp;

  clearAllMarks();
  var downloadResult = l0Result.downloadResult;
  markSuspiciousLinks(downloadResult.suspicious);

  var redirectLinks = l0Result.redirectLinks;
  // 合并运行时检测到的跳转
  var allRedirects = redirectLinks.concat(runtimeRedirects.map(function(r) {
    return { type: r.type, url: r.url, source: r.source };
  }));

  var fingerprint = collectPageFingerprint();

  // 政府网站标签扫描
  var isGovSite = scanGovSiteLabels();

  window.__foxHunter = {
    downloadLinks: downloadResult.found,
    suspiciousLinks: downloadResult.suspicious,
    redirectLinks: allRedirects,
    icp: icp,
    pageFingerprint: fingerprint,
    l0Passed: !l0Result.hasDownloads && !l0Result.hasRedirects,
    l0Reason: (!l0Result.hasDownloads && !l0Result.hasRedirects) ? 'no_links' : null,
    isGovSite: isGovSite
  };

  chrome.runtime.sendMessage({
    type: 'pageData',
    url: location.href,
    icp: icp,
    downloadLinks: downloadResult.found.map(function(l) { return { url: l.url, ext: l.ext, isSusp: l.isSusp, text: l.text, isCrossDomain: l.isCrossDomain }; }),
    suspiciousLinks: downloadResult.suspicious.map(function(l) { return { url: l.url, ext: l.ext, text: l.text, isCrossDomain: l.isCrossDomain }; }),
    redirectLinks: allRedirects.map(function(r) { return { type: r.type, url: r.url, source: r.source }; }),
    pageFingerprint: fingerprint,
    l0Passed: !l0Result.hasDownloads && !l0Result.hasRedirects,
    l0Reason: (!l0Result.hasDownloads && !l0Result.hasRedirects) ? 'no_links' : null,
    isGovSite: isGovSite
  }).catch(function() {});

  // 请求评分更新（含 SSL 和 ICP 验证）
  chrome.runtime.sendMessage({ type: 'evaluateRiskForTab' }).then(function(response) {
    if (response && response.success && response.data) {
      var data = response.data;
      updateBallScore(
        data.score || 0,
        data.level || 'safe',
        data.ruleResults || [],
        data.domain || location.hostname,
        data.icpNumber || currentIcp || '',
        data.dnsResolvedIP || '',
        data.dnsHijacked || false,
        data.sslStatus || null,
        data.icpValidation || null
      );
    }
  }).catch(function() {});
}

// ================================================================
// 第六部分：动态 ICP 扫描（重试机制）
// ================================================================

function startICPRetries() {
  for (var t of icpRetryTimers) {
    clearTimeout(t);
  }
  icpRetryTimers = [];
  icpRetryCount = 0;

  icpRetryTimers.push(setTimeout(function() {
    if (currentIcp) return;
    var icp = scanICPInPage();
    if (icp) handleICPFound(icp);
  }, 1500));

  icpRetryTimers.push(setTimeout(function() {
    if (currentIcp) return;
    var icp = scanICPInPage();
    if (icp) handleICPFound(icp);
  }, 3500));
}

function handleICPFound(icp) {
  if (currentIcp === icp) return;
  currentIcp = icp;
  icpRetryCount = MAX_ICP_RETRIES;

  chrome.runtime.sendMessage({
    type: 'icp',
    icp: icp,
    url: location.href
  }).catch(function() {});
}

// ================================================================
// 第七部分：动态监听（MutationObserver + 滚动 + SPA 路由）
// ================================================================

function startObserver() {
  if (observer) {
    observer.disconnect();
    observer = null;
  }

  var pendingScan = false;

  observer = new MutationObserver(function(mutations) {
    var needsScan = false;
    var addedCount = 0;

    for (var mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        addedCount += mutation.addedNodes.length;
        for (var node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            // 检查新增元素是否为下载链接或包含下载链接
            if (node.tagName === 'A' ||
                node.querySelector && node.querySelector('a') ||
                node.matches && node.matches('.download, .btn-download, [download]')) {
              needsScan = true;
              break;
            }
            // 增强：检查新元素的 href/src/data-* 属性是否指向可执行文件
            if (checkElementForDownloads(node)) {
              needsScan = true;
              break;
            }
          }
        }
      }
      if (mutation.type === 'attributes' &&
          (mutation.attributeName === 'href' || mutation.attributeName === 'download' ||
           mutation.attributeName === 'src' || mutation.attributeName.startsWith('data-'))) {
        needsScan = true;
        break;
      }
    }

    if (!currentIcp) {
      for (var mutation of mutations) {
        if (mutation.type === 'childList' && mutation.target) {
          var target = mutation.target;
          if (target.tagName && (target.tagName.toLowerCase() === 'footer' ||
              target.classList && (target.classList.contains('footer') || target.classList.contains('copyright')))) {
            needsScan = true;
            var icp = scanICPInPage();
            if (icp) handleICPFound(icp);
            break;
          }
        }
      }
    }

    if (needsScan && !pendingScan) {
      pendingScan = true;
      var delay = addedCount > 10 ? 800 : 400;
      scheduleScan(delay);
      setTimeout(function() { pendingScan = false; }, delay + 100);
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['href', 'download', 'src', 'data-href', 'data-url', 'data-src', 'data-download', 'data-link']
  });
}

// 增强：检查新添加元素是否包含下载链接
function checkElementForDownloads(element) {
  if (!element || !element.getAttribute) return false;

  // 检查元素自身的属性
  var attrs = ['href', 'src', 'data-href', 'data-url', 'data-src', 'data-download', 'data-link'];
  for (var attr of attrs) {
    var val = element.getAttribute(attr);
    if (val && getDownloadExt(val)) return true;
  }

  // 检查 download 属性
  if (element.hasAttribute('download')) return true;

  // 检查子元素
  if (element.querySelectorAll) {
    var downloadLinks = element.querySelectorAll('a[href*=".exe"], a[href*=".msi"], a[href*=".zip"], a[href*=".dmg"], a[href*=".apk"], a[download]');
    if (downloadLinks.length > 0) return true;
  }

  return false;
}

function scheduleScan(delay) {
  if (delay === undefined) delay = 300;
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(function() {
    performFullScan();
    scanTimer = null;
  }, delay);
}

var scrollTimeout = null;
var lastScrollY = window.scrollY;

function onScroll() {
  if (scrollTimeout) return;
  scrollTimeout = setTimeout(function() {
    var currentScrollY = window.scrollY;
    if (Math.abs(currentScrollY - lastScrollY) > 200) {
      scheduleScan(400);
      lastScrollY = currentScrollY;
    }
    scrollTimeout = null;
  }, 300);
}

// ================================================================
// 第八部分：辅助函数
// ================================================================

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type, duration) {
  var colors = {
    info: 'var(--cyan, #40d4c0)',
    warning: 'var(--warning, #f59e0b)',
    danger: 'var(--danger, #ef5350)',
    success: 'var(--success, #10b981)'
  };
  var toast = document.createElement('div');
  toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
    'background:rgba(20,20,31,0.95);color:#e8e8f0;' +
    'padding:10px 22px;border-radius:10px;font-size:14px;' +
    'font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;' +
    'z-index:999999;box-shadow:0 8px 32px rgba(0,0,0,0.5);' +
    'border:1px solid ' + (colors[type] || '#2a2a4a') + ';' +
    'border-left:4px solid ' + (colors[type] || '#f0c060') + ';' +
    'max-width:80%;text-align:center;transition:opacity 0.4s ease,transform 0.4s ease;opacity:1;pointer-events:none;';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(function() {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(-50%) translateY(12px)';
    setTimeout(function() { toast.remove(); }, 450);
  }, duration || 5000);
}

// ================================================================
// 动态下载 Hook & 节流控制
// ================================================================

var downloadHooksActivated = false;

function activateDownloadHooks() {
  if (downloadHooksActivated) return;
  downloadHooksActivated = true;

  chrome.storage.local.get(['settings'], function(result) {
    var settings = result.settings || {};
    var downloadHookSettings = settings.downloadHook || {};
    if (downloadHookSettings.enabled === false) return;

    var originalBlob = window.Blob;
    window.Blob = function(parts, options) {
      var blob = new originalBlob(parts, options);
      if (options && options.type && /application\/(octet-stream|zip|exe|msi|dmg)/i.test(options.type)) {
        onDynamicDownloadDetected('blob_constructor', blob.size);
      }
      return blob;
    };

    var originalCreateObjectURL = URL.createObjectURL;
    URL.createObjectURL = function(blob) {
      if (blob && blob.size > 100000 && blob.type && /application\/(octet-stream|zip|exe|msi|dmg)/i.test(blob.type)) {
        onDynamicDownloadDetected('create_object_url', blob.size);
      }
      return originalCreateObjectURL.call(URL, blob);
    };

    var originalFetch = window.fetch;
    window.fetch = function() {
      return originalFetch.apply(this, arguments).then(function(response) {
        var contentType = response.headers.get('content-type') || '';
        var contentDisposition = response.headers.get('content-disposition') || '';
        if (/attachment/i.test(contentDisposition) || /application\/(octet-stream|zip|exe|msi|dmg)/i.test(contentType)) {
          onDynamicDownloadDetected('fetch_download', 0);
        }
        return response;
      });
    };

    var originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.addEventListener('load', function() {
        var contentType = this.getResponseHeader('content-type') || '';
        var contentDisposition = this.getResponseHeader('content-disposition') || '';
        if (/attachment/i.test(contentDisposition) || /application\/(octet-stream|zip|exe|msi|dmg)/i.test(contentType)) {
          onDynamicDownloadDetected('xhr_download', 0);
        }
      });
      return originalXHROpen.apply(this, arguments);
    };
  });
}

function onDynamicDownloadDetected(source, size) {
  var downloadInfo = {
    url: location.href,
    ext: 'exe',
    isSusp: true,
    text: '动态下载 (' + source + ')'
  };

  if (!window.__foxHunter) window.__foxHunter = {};
  if (!window.__foxHunter.downloadLinks) window.__foxHunter.downloadLinks = [];
  window.__foxHunter.downloadLinks.push(downloadInfo);

  chrome.runtime.sendMessage({
    type: 'pageData',
    url: location.href,
    icp: currentIcp,
    downloadLinks: [downloadInfo],
    suspiciousLinks: [downloadInfo],
    redirectLinks: [],
    pageFingerprint: collectPageFingerprint()
  }).catch(function() {});

  chrome.runtime.sendMessage({ type: 'evaluateRiskForTab' }).then(function(response) {
    if (response && response.success && response.data) {
      var data = response.data;
      updateBallScore(
        data.score || 0,
        data.level || 'safe',
        data.ruleResults || [],
        data.domain || location.hostname,
        data.icpNumber || currentIcp || '',
        data.dnsResolvedIP || '',
        data.dnsHijacked || false,
        data.sslStatus || null,
        data.icpValidation || null
      );
    }
  }).catch(function() {});
}

var lastBallUpdate = 0;
var pendingBallUpdate = null;

function throttledBallUpdate(score, level, ruleResults, domain, icpNumber, dnsResolvedIP, dnsHijacked) {
  var now = Date.now();
  if (now - lastBallUpdate >= 3000) {
    lastBallUpdate = now;
    updateBallAppearance();
  } else {
    clearTimeout(pendingBallUpdate);
    pendingBallUpdate = setTimeout(function() {
      lastBallUpdate = Date.now();
      updateBallAppearance();
    }, 3000 - (now - lastBallUpdate));
  }
}

// 带重试的小圆球创建（应对 SPA 页面 DOM 未就绪的情况）
function createBallWithRetry() {
  var delays = [0, 100, 300, 1000];
  var attempt = 0;

  function tryCreate() {
    if (ballElement) return; // 已创建
    var target = document.documentElement || document.body;
    if (target) {
      createBall();
    } else if (attempt < delays.length - 1) {
      attempt++;
      setTimeout(tryCreate, delays[attempt]);
    }
  }

  tryCreate();
}

// SPA 路由变化后检查小圆球是否存在
function checkBallAfterRoute() {
  setTimeout(function() {
    if (!ballElement && !isBallHidden) {
      chrome.storage.local.get(['settings'], function(result) {
        var settings = result.settings || {};
        var ballSettings = settings.ball || {};
        if (ballSettings.enabled !== false) {
          createBallWithRetry();
        }
      });
    }
  }, 300);
}

// ================================================================
// 第九部分：初始化 & 消息监听
// ================================================================

function init() {
  // 先读取用户设置，再决定是否创建小圆球
  chrome.storage.local.get(['settings'], function(result) {
    var settings = result.settings || {};
    var ballSettings = settings.ball || {};

    // 只有用户启用小圆球时才创建
    if (ballSettings.enabled !== false) {
      createBallWithRetry();
      loadBallSettings();
    }

    // 检查是否被忽略或静默
    checkIgnoreStatus();

    // 延迟 3 秒后再首次扫描，避免阻塞页面渲染
    setTimeout(function() {
      performFullScan();
    }, 3000);

    // 加载扫描间隔
    getScanInterval();

    // 延迟重扫
    setTimeout(function() { performFullScan(); }, 8000);

    // 启动 ICP 重试
    startICPRetries();

    // 启动 MutationObserver
    if (document.body) {
      startObserver();
    } else {
      document.addEventListener('DOMContentLoaded', startObserver);
    }

    // 滚动监听
    window.addEventListener('scroll', onScroll, { passive: true });

    // 页面可见性变化
    document.addEventListener('visibilitychange', function() {
      if (!document.hidden) scheduleScan(600);
    });

    // SPA 路由变化
    window.addEventListener('popstate', function() { scheduleScan(400); checkBallAfterRoute(); });
    window.addEventListener('hashchange', function() { scheduleScan(400); checkBallAfterRoute(); });

    var originalPushState = history.pushState;
    var originalReplaceState = history.replaceState;
    history.pushState = function() {
      originalPushState.apply(this, arguments);
      scheduleScan(500);
      checkBallAfterRoute();
    };
    history.replaceState = function() {
      originalReplaceState.apply(this, arguments);
      scheduleScan(500);
      checkBallAfterRoute();
    };

    // 激活动态下载 Hook（拦截 Blob / URL.createObjectURL 等）
    activateDownloadHooks();

    // 激活运行时跳转拦截
    activateRedirectHooks();
  });
}

function checkIgnoreStatus() {
  var domain = location.hostname;
  chrome.storage.local.get(['foxIgnoredDomains', 'foxSilentUntil'], function(result) {
    var ignoredDomains = result.foxIgnoredDomains || [];
    var silentUntil = result.foxSilentUntil || 0;

    if (ignoredDomains.includes(domain) || silentUntil > Date.now()) {
      hideBall();
    }
  });
}

// 执行初始化
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// 消息监听
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === 'getPageInfo') {
    var data = window.__foxHunter || { downloadLinks: [], suspiciousLinks: [], redirectLinks: [], icp: null };
    sendResponse(data);
    return true;
  }
  if (message.type === 'rescanPage') {
    lastScanHash = '';
    currentIcp = null;
    lastRiskLevel = null;
    performFullScan();
    sendResponse({ status: 'ok' });
    return true;
  }
  if (message.type === 'scoreUpdate') {
    var d = message.data || {};
    updateBallScore(
      d.score || 0,
      d.level || 'safe',
      d.ruleResults || [],
      currentDomain || location.hostname,
      currentICP,
      currentDNSIP,
      isDNSHijacked
    );
    sendResponse({ status: 'ok' });
    return true;
  }
  if (message.type === 'dnsHijackAlert') {
    isDNSHijacked = true;
    updateBallAppearance();
    sendResponse({ status: 'ok' });
    return true;
  }
  if (message.type === 'settingsUpdated') {
    loadBallSettings();
    if (message.settings && message.settings.scanInterval !== undefined) {
      setupScanInterval(message.settings.scanInterval);
    }
    // 检查小圆球开关
    if (message.settings && message.settings.ball) {
      if (message.settings.ball.enabled === false) {
        // 完全移除小圆球
        if (ballElement) { ballElement.remove(); ballElement = null; }
        if (ballTooltip) { ballTooltip.remove(); ballTooltip = null; }
        if (ballMenu) { ballMenu.remove(); ballMenu = null; }
        if (restoreButton) { restoreButton.remove(); restoreButton = null; }
        isBallHidden = true;
      } else if (!ballElement) {
        // 重新创建
        isBallHidden = false;
        createBallWithRetry();
        loadBallSettings();
      }
    }
    sendResponse({ status: 'ok' });
    return true;
  }
  // 处理 SSL/ICP 验证数据推送
  if (message.type === 'sslStatusUpdate') {
    currentSSLStatus = message.data || null;
    updateTooltip();
    sendResponse({ status: 'ok' });
    return true;
  }
  if (message.type === 'icpValidationUpdate') {
    currentICPValidation = message.data || null;
    updateTooltip();
    sendResponse({ status: 'ok' });
    return true;
  }
  sendResponse({});
  return true;
});

// 注入 CSS 动画
var styleEl = document.createElement('style');
styleEl.textContent = '@keyframes foxBlink{0%,100%{opacity:1;}50%{opacity:0.5;}}';
document.head.appendChild(styleEl);
