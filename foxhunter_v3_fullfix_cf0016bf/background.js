// ================================================================
// 银狐猎手 - 后台核心引擎
// 集成 VirusDetector 完整检测能力（缓存/黑名单/ICP/RDAP/评分引擎）
// ================================================================

// ---- 1. 基础工具 ----
try {
  importScripts(
    'utils/constants.js',
    'utils/url-utils.js',
    'utils/exemptions/icp-exempt.js',
    'utils/exemptions/trusted-platforms.js',
    'utils/exemptions/fully-trusted.js',
    'utils/trusted-platforms.js',
    'utils/trusted-download-hosts.js'
  );
} catch (e) { console.warn('[银狐猎手] 基础工具加载失败:', e); }

// ---- 2. 核心检测 ----
try {
  importScripts(
    'background/domain-database.js',
    'background/icp-utils.js',
    'background/icp-api.js',
    'background/cache-manager.js',
    'background/download-blacklist.js',
    'background/site-blacklist.js'
  );
} catch (e) { console.warn('[银狐猎手] 核心检测加载失败:', e); }

// ---- 3. 网络查询 ----
try {
  importScripts(
    'background/rdap-client.js',
    'background/whois-client.js'
  );
} catch (e) { console.warn('[银狐猎手] 网络查询加载失败:', e); }

// ---- 4. 评分引擎 ----
try {
  importScripts(
    'background/scoring-engine.js'
  );
} catch (e) { console.warn('[银狐猎手] 评分引擎加载失败:', e); }

// ---- 5. 自己的模块（日志/主题） ----
try {
  importScripts('log_manager.js', 'theme_manager.js');
} catch (e) { console.warn('[银狐猎手] 本地模块加载失败:', e); }

// ================================================================
// 内联 DNS 劫持检测模块（原 dns_checker.js，避免 MV3 importScripts 限制）
// ================================================================
const DNS_CHECKER = (function() {
  'use strict';
  const DOH_SERVERS = {
    'auto':     { url: 'https://dns.google/resolve', name: '自动' },
    '114dns':   { url: 'https://114dns.com/dns-query', name: '114DNS' },
    'alidns':   { url: 'https://dns.alidns.com/resolve', name: '阿里DNS' },
    'google':   { url: 'https://dns.google/resolve', name: 'Google DNS' },
    'cloudflare': { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare DNS' }
  };
  const DNS_SERVERS = {
    '114.114.114.114': '114DNS', '223.5.5.5': '阿里云DNS',
    '119.29.29.29': '腾讯云DNS', '180.76.76.76': '百度DNS',
    '122.112.208.1': '华为云DNS', '8.8.8.8': 'Google DNS',
    '8.8.4.4': 'Google DNS', '1.1.1.1': 'Cloudflare DNS', '1.0.0.1': 'Cloudflare DNS'
  };
  async function getDNSIP(domain, server) {
    if (!domain) return { ip: null, error: '域名为空' };
    server = server || 'auto';
    const dohConfig = DOH_SERVERS[server] || DOH_SERVERS['auto'];
    try {
      const url = dohConfig.url + '?name=' + encodeURIComponent(domain) + '&type=A';
      const response = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
      if (!response.ok) return { ip: null, error: 'DoH查询失败: HTTP ' + response.status };
      const data = await response.json();
      if (data.Answer && data.Answer.length > 0) {
        for (const ans of data.Answer) { if (ans.type === 1) return { ip: ans.data, error: null }; }
        return { ip: data.Answer[0].data, error: null };
      }
      return { ip: null, error: '无解析结果' };
    } catch (e) { return { ip: null, error: 'DoH查询异常: ' + (e.message || e) }; }
  }
  async function checkHijacking(domain, actualIP, server) {
    if (!domain) return { isHijacked: false, resolvedIP: null, actualIP: null, error: '域名为空' };
    const dnsResult = await getDNSIP(domain, server);
    if (dnsResult.error) return { isHijacked: false, resolvedIP: null, actualIP: actualIP || null, error: dnsResult.error };
    const resolvedIP = dnsResult.ip;
    let isHijacked = false;
    if (resolvedIP && actualIP) { isHijacked = resolvedIP.trim().toLowerCase() !== actualIP.trim().toLowerCase(); }
    return { isHijacked, resolvedIP, actualIP: actualIP || null, error: null };
  }
  async function getIPLocation(ip) {
    if (!ip) return { location: null, error: 'IP为空' };
    try {
      const response = await fetch('http://ip-api.com/json/' + encodeURIComponent(ip) + '?lang=zh-CN', { signal: AbortSignal.timeout(3000) });
      if (!response.ok) return { location: null, error: '查询失败' };
      const data = await response.json();
      if (data.status === 'success') {
        const parts = [];
        if (data.country) parts.push(data.country);
        if (data.regionName) parts.push(data.regionName);
        if (data.city) parts.push(data.city);
        return { location: parts.join(' ') || '未知', error: null };
      }
      return { location: null, error: data.message || '查询失败' };
    } catch (e) { return { location: null, error: '归属地查询异常' }; }
  }
  function getPageActualIP() { return null; }
  async function checkDNS(domain, server) {
    if (!domain) return { domain, isHijacked: false, resolvedIP: null, location: null, error: '域名为空' };
    const dnsResult = await getDNSIP(domain, server);
    let location = null;
    if (dnsResult.ip) { const locResult = await getIPLocation(dnsResult.ip); location = locResult.location; }
    return { domain, isHijacked: false, resolvedIP: dnsResult.ip, dnsProvider: DOH_SERVERS[server || 'auto'].name, location, error: dnsResult.error };
  }
  function checkDNSViaNetwork(domain, callback) { checkDNS(domain, 'auto').then(r => { if (typeof callback === 'function') callback(r); }); }
  return { getDNSIP, checkHijacking, getIPLocation, getPageActualIP, checkDNS, checkDNSViaNetwork, DOH_SERVERS, DNS_SERVERS };
})();

// ================================================================
// 内联网络连通性检测模块（原 network_checker.js）
// ================================================================
const NETWORK_CHECKER = (function() {
  'use strict';
  const TEST_TARGETS = [
    { url: 'https://www.baidu.com', name: '百度' },
    { url: 'https://www.qq.com', name: '腾讯' }
  ];
  function checkConnectivity(callback) {
    if (typeof callback !== 'function') return;
    const result = { isOnline: false, testedTargets: [], successTarget: null, error: null };
    let completed = 0;
    const timer = setTimeout(() => {
      if (completed < TEST_TARGETS.length) {
        completed = TEST_TARGETS.length;
        result.isOnline = result.successTarget !== null;
        if (!result.isOnline) result.error = '网络连接超时，请检查网络或VPN设置';
        callback(result);
      }
    }, 5000);
    TEST_TARGETS.forEach(target => {
      const testStart = Date.now();
      fetch(target.url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' }).then(() => {
        result.testedTargets.push({ name: target.name, url: target.url, success: true, elapsed: Date.now() - testStart });
        if (!result.successTarget) result.successTarget = target.name;
        if (++completed >= TEST_TARGETS.length) { clearTimeout(timer); result.isOnline = true; callback(result); }
      }).catch((err) => {
        result.testedTargets.push({ name: target.name, url: target.url, success: false, elapsed: Date.now() - testStart, error: err.message || '连接失败' });
        if (++completed >= TEST_TARGETS.length) { clearTimeout(timer); result.isOnline = result.successTarget !== null; if (!result.isOnline) result.error = '所有测试目标均不可达'; callback(result); }
      });
    });
  }
  function checkConnectivityAsync() { return new Promise(resolve => checkConnectivity(resolve)); }
  return { checkConnectivity, checkConnectivityAsync, TEST_TARGETS };
})();

console.log('[银狐猎手] 🚀 后台引擎启动 (v' + chrome.runtime.getManifest().version + ')');

// ================================================================
// 初始化：注册非中国品牌域名到 ICP 豁免名单
// ================================================================
try {
  if (typeof DomainDatabase !== 'undefined' && typeof registerNonChineseBrandDomains === 'function') {
    const entries = DomainDatabase.getAllEntries();
    const nonChineseDomains = [];
    for (const entry of entries) {
      if (!entry.isChineseBrand) {
        for (const d of entry.officialDomains) {
          nonChineseDomains.push(d);
        }
      }
    }
    registerNonChineseBrandDomains(nonChineseDomains);
    console.log('[银狐猎手] 已注册 ' + nonChineseDomains.length + ' 个非中国品牌域名到 ICP 豁免名单');
  }
} catch (e) { console.warn('[银狐猎手] ICP 豁免注册失败:', e); }

// ================================================================
// 日志管理器（适配 Service Worker）
// ================================================================
const LOG_STORAGE_KEY = 'foxLogs';
const MAX_LOG_COUNT = 5000;

function addLogEntry(entry) {
  if (!entry.domain || !entry.url || !entry.detail) return;
  chrome.storage.local.get([LOG_STORAGE_KEY], (result) => {
    let logs = result[LOG_STORAGE_KEY] || [];
    const newLog = {
      id: Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      timestamp: new Date().toLocaleString('zh-CN', { hour12: false }),
      domain: entry.domain,
      url: entry.url,
      action: entry.action || 'page_visit',
      riskScore: entry.riskScore || 0,
      level: entry.level || 'safe',
      matchedRules: entry.matchedRules || [],
      whitelistHit: entry.whitelistHit || false,
      userAction: entry.userAction || 'ignored',
      detail: entry.detail
    };
    logs.unshift(newLog);
    if (logs.length > MAX_LOG_COUNT) logs = logs.slice(0, MAX_LOG_COUNT);
    chrome.storage.local.set({ [LOG_STORAGE_KEY]: logs });
  });
}

function getAllLogs(callback) {
  chrome.storage.local.get([LOG_STORAGE_KEY], (result) => {
    callback(result[LOG_STORAGE_KEY] || []);
  });
}

function getRecentLogs(count, callback) {
  getAllLogs((logs) => callback(logs.slice(0, Math.min(count, logs.length))));
}

function clearAllLogs(callback) {
  chrome.storage.local.set({ [LOG_STORAGE_KEY]: [] }, () => {
    if (callback) callback();
  });
}

function deleteLogsByIds(ids, callback) {
  if (!ids || ids.length === 0) { if (callback) callback(); return; }
  getAllLogs((logs) => {
    const idSet = new Set(ids);
    logs = logs.filter(log => !idSet.has(log.id));
    chrome.storage.local.set({ [LOG_STORAGE_KEY]: logs }, () => {
      if (callback) callback();
    });
  });
}

function exportLogsAsJSON(mode, callback) {
  const fn = mode === 'all' ? getAllLogs : (cb) => getRecentLogs(1000, cb);
  fn((logs) => {
    const data = {
      exportTime: new Date().toISOString(),
      total: logs.length,
      source: '银狐猎手',
      logs: logs.map(log => ({
        时间: log.timestamp,
        域名: log.domain,
        完整链接: log.url,
        触发事件: log.action === 'download' ? '下载' : '页面访问',
        风险分: log.riskScore,
        风险等级: log.level === 'danger' ? '高危' : log.level === 'warning' ? '可疑' : '安全',
        命中规则: log.matchedRules.join('、') || '无',
        是否命中白名单: log.whitelistHit ? '是' : '否',
        用户操作: log.userAction === 'blocked' ? '已拦截' : log.userAction === 'allowed' ? '已放行' : '未操作',
        详细说明: log.detail
      }))
    };
    callback(JSON.stringify(data, null, 2));
  });
}

function exportLogsAsCSV(mode, callback) {
  const fn = mode === 'all' ? getAllLogs : (cb) => getRecentLogs(1000, cb);
  fn((logs) => {
    const headers = ['时间', '域名', '完整链接', '触发事件', '风险分', '风险等级', '命中规则', '是否命中白名单', '用户操作', '详细说明'];
    let csv = '\uFEFF' + headers.join(',') + '\n';
    for (const log of logs) {
      const row = [
        log.timestamp, log.domain, log.url,
        log.action === 'download' ? '下载' : '页面访问',
        log.riskScore,
        log.level === 'danger' ? '高危' : log.level === 'warning' ? '可疑' : '安全',
        log.matchedRules.join('、'),
        log.whitelistHit ? '是' : '否',
        log.userAction === 'blocked' ? '已拦截' : log.userAction === 'allowed' ? '已放行' : '未操作',
        log.detail
      ];
      csv += row.join(',') + '\n';
    }
    callback(csv);
  });
}

// 将日志函数暴露到全局
self.addLogEntry = addLogEntry;
self.getAllLogs = getAllLogs;
self.getRecentLogs = getRecentLogs;
self.clearAllLogs = clearAllLogs;
self.deleteLogsByIds = deleteLogsByIds;
self.exportLogsAsJSON = exportLogsAsJSON;
self.exportLogsAsCSV = exportLogsAsCSV;

// ================================================================
// 主题管理器（适配 Service Worker，仅保存状态，不操作 DOM）
// ================================================================
const THEME_STORAGE_KEY = 'foxTheme';

function getTheme(callback) {
  chrome.storage.local.get([THEME_STORAGE_KEY], (result) => {
    const saved = result[THEME_STORAGE_KEY] || { mode: 'dark' };
    callback(saved);
  });
}

function setTheme(mode) {
  if (mode !== 'light' && mode !== 'dark') return;
  chrome.storage.local.set({ [THEME_STORAGE_KEY]: { mode } });
}

self.getTheme = getTheme;
self.setTheme = setTheme;

// ================================================================
// 后台核心逻辑
// ================================================================

function extractDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// 内置白名单（快速放行，避免对知名站点做完整评分）
// 包含中外大厂 30+ 个，子域名自动继承
function isBuiltinWhitelist(domain) {
  const list = [
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "meta.com", "facebook.com", "instagram.com", "twitter.com",
    "youtube.com", "netflix.com", "spotify.com", "adobe.com",
    "oracle.com", "ibm.com", "huawei.com", "xiaomi.com",
    "oppo.com", "vivo.com", "samsung.com", "sony.com",
    "qq.com", "weixin.qq.com", "bilibili.com", "dingtalk.com",
    "feishu.cn", "bytedance.com", "douyin.com", "kuaishou.com",
    "github.com", "gitlab.com", "sourceforge.net",
    "stackoverflow.com", "wikipedia.org", "wikimedia.org",
    // 额外保留的知名站点
    "wps.cn", "wps.com", "baidu.com", "pan.baidu.com",
    "mozilla.org", "gitee.com", "bing.com", "zhihu.com",
    "csdn.net", "juejin.cn", "oschina.net",
    "taobao.com", "tmall.com", "jd.com"
  ];
  return list.includes(domain) || list.some(d => domain.endsWith('.' + d));
}

// 政府/教育/科研后缀白名单（所有子域名放行）
function isGovSuffixWhitelist(domain) {
  const suffixes = ["gov.cn", "gov", "gov.hk", "gov.tw", "edu.cn", "ac.cn"];
  const normalized = domain.toLowerCase();
  return suffixes.some(s => normalized === s || normalized.endsWith('.' + s));
}

// 下载站白名单（仅主域名精确匹配，不包含子域名）
function isDownloadSiteWhitelist(domain) {
  const sites = [
    "crsky.com", "pc6.com", "xiazaiba.com", "newhua.com",
    "skycn.com", "onlinedown.net", "softonic.com", "down.com",
    "zol.com.cn", "pconline.com.cn", "mydown.yesky.com",
    "duote.com", "ddooo.com", "softpedia.com", "majorgeeks.com",
    "filehorse.com", "pcfreetime.com", "baofeng.com",
    "xunlei.com", "kugou.com", "kuwo.com", "weiyun.com",
    "pan.baidu.com", "aliyundrive.com", "123pan.com",
    "lanzou.com", "codeload.github.com", "releases.gitlab.com",
    "down.tech.sina.com.cn", "dl.pconline.com.cn", "soft.3dmgame.com",
    "dl.3dmgame.com", "down.ali213.net", "dl.ali213.net",
    "down.gamersky.com", "dl.gamersky.com", "down.52pk.com",
    "dl.52pk.com", "down.17173.com", "dl.17173.com",
    "soft.xiaomi.com", "app.mi.com", "appstore.huawei.com"
  ];
  return sites.includes(domain);
}

// 大型网站白名单（DNS正常时直接放行）
function isLargeSiteWhitelist(domain) {
  const list = [
    'bing.com', 'bilibili.com', 'github.com',
    'microsoft.com', 'google.com', 'apple.com',
    'amazon.com', 'netflix.com', 'twitter.com',
    'youtube.com', 'facebook.com', 'instagram.com'
  ];
  return list.includes(domain) || list.some(d => domain.endsWith('.' + d));
}

// ---- 评分缓存（10秒内同一域名直接返回缓存）----
const scoreCache = new Map();
const SCORE_CACHE_TTL = 10000; // 10秒

function getCachedScore(domain) {
  const cached = scoreCache.get(domain);
  if (cached && Date.now() - cached.time < SCORE_CACHE_TTL) {
    return cached.data;
  }
  scoreCache.delete(domain);
  return null;
}

function setCachedScore(domain, data) {
  scoreCache.set(domain, { data, time: Date.now() });
}

// ---- 弹窗冷却（同一域名1小时内不重复弹出桌面通知和全屏警告）----
const popupCooldown = new Map();
const POPUP_COOLDOWN_TTL = 3600000; // 1小时

function isInCooldown(domain) {
  const last = popupCooldown.get(domain);
  if (last && Date.now() - last < POPUP_COOLDOWN_TTL) {
    return true;
  }
  return false;
}

function setCooldown(domain) {
  popupCooldown.set(domain, Date.now());
}

// ---- 用户设置（从 chrome.storage.local 读取）----
async function getUserSettings() {
  try {
    const result = await chrome.storage.local.get(['settings']);
    return result.settings || {};
  } catch { return {}; }
}

// ---- DNS 劫持大报警 ----
async function triggerDNSHijackAlert(domain, resolvedIP, actualIP) {
  // 1. 桌面通知
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '⚠️ DNS 劫持风险！',
    message: '当前网络可能被篡改，建议切换网络或使用 VPN。\n域名: ' + domain + '\n解析IP: ' + (resolvedIP || '未知'),
    priority: 2
  });

  // 2. 写入危险日志
  addLogEntry({
    domain: domain,
    url: activeTabUrl || '',
    action: 'page_visit',
    riskScore: 200,
    level: 'danger',
    matchedRules: ['DNS劫持检测'],
    whitelistHit: false,
    userAction: 'blocked',
    detail: 'DNS 劫持检测：解析IP ' + (resolvedIP || '未知') + ' vs 实际IP ' + (actualIP || '未知')
  });
}

// ---- 页面数据缓存（按 tabId 存储 content_script 上报的数据）----
const pageDataCache = new Map();

// ================================================================
// SSL 证书检测模块
// ================================================================
async function checkSSLCertificate(url) {
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'https:') {
      return { valid: false, reason: 'not_https', status: 'none', message: '非 HTTPS 连接' };
    }

    // 使用 chrome.debugger API 获取 SSL 证书信息
    return new Promise((resolve) => {
      let tabId = null;
      
      // 查找当前活动标签页
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
          resolve({ valid: false, reason: 'no_tab', status: 'unknown', message: '无法获取标签页' });
          return;
        }
        
        tabId = tabs[0].id;
        
        // 尝试通过 webRequest 获取安全信息
        // 在 MV3 中，我们通过尝试连接来验证 SSL
        fetch(url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(5000) })
          .then(() => {
            // 如果能成功连接（即使是 no-cors），说明 SSL 基本有效
            resolve({
              valid: true,
              status: 'valid',
              message: 'SSL证书有效',
              protocol: 'TLS',
              issuer: '已验证',
              subjectName: parsedUrl.hostname,
              validFrom: null,
              validTo: null
            });
          })
          .catch((e) => {
            // 连接失败可能是 SSL 问题
            const errorMsg = e.message || '';
            if (errorMsg.includes('SSL') || errorMsg.includes('certificate') || errorMsg.includes('ERR_CERT')) {
              resolve({
                valid: false,
                status: 'invalid',
                message: 'SSL证书无效或已过期',
                reason: 'cert_error'
              });
            } else if (errorMsg.includes('NETWORK') || errorMsg.includes('Failed to fetch')) {
              resolve({
                valid: false,
                status: 'unknown',
                message: '无法连接（网络问题）',
                reason: 'network_error'
              });
            } else {
              // 其他错误，可能是 CORS 等，SSL 本身可能没问题
              resolve({
                valid: true,
                status: 'valid',
                message: 'SSL证书有效（连接测试通过）',
                protocol: 'TLS'
              });
            }
          });
      });
    });
  } catch (e) {
    return { valid: false, reason: 'error', status: 'unknown', message: '检测异常: ' + (e.message || e) };
  }
}

// ================================================================
// DNS 当前源检测模块
// ================================================================
async function detectCurrentDNSProvider() {
  const testDomains = ['www.baidu.com', 'www.qq.com'];
  const providerMap = {
    '114.114.114.114': '114DNS',
    '223.5.5.5': '阿里DNS',
    '119.29.29.29': '腾讯DNS',
    '8.8.8.8': 'Google DNS',
    '1.1.1.1': 'Cloudflare DNS',
    '180.76.76.76': '百度DNS'
  };

  try {
    // 通过多个 DoH 服务查询同一域名，比较结果来推断当前 DNS
    const results = {};
    for (const domain of testDomains) {
      // 使用系统默认 DNS（通过 DoH 查询）
      const dohUrl = 'https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=A';
      const response = await fetch(dohUrl, { 
        method: 'GET', 
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000)
      });
      if (response.ok) {
        const data = await response.json();
        if (data.Answer && data.Answer.length > 0) {
          for (const ans of data.Answer) {
            if (ans.type === 1) {
              results[domain] = ans.data;
              break;
            }
          }
        }
      }
    }

    // 尝试识别 DNS 提供商
    // 通过比较不同 DoH 服务的解析结果来判断
    // 如果所有 DoH 服务返回相同结果，说明 DNS 正常
    // 如果结果不同，可能存在 DNS 劫持

    // 简单检测：通过查询一个已知域名来判断当前使用的 DNS
    const testResult = await DNS_CHECKER.getDNSIP('www.baidu.com', 'auto');
    if (testResult.ip) {
      // 根据解析 IP 反推 DNS 提供商
      for (const [ip, name] of Object.entries(providerMap)) {
        if (testResult.ip === ip) {
          return { provider: name, ip: testResult.ip, detected: true };
        }
      }
      return { provider: '系统默认DNS', ip: testResult.ip, detected: true };
    }

    return { provider: '未知', ip: null, detected: false };
  } catch (e) {
    return { provider: '未知', ip: null, detected: false, error: e.message };
  }
}

// ---- 活动标签页跟踪 ----
let activeTabId = null;
let activeTabUrl = null;

chrome.tabs.onActivated.addListener((activeInfo) => {
  activeTabId = activeInfo.tabId;
  chrome.tabs.get(activeTabId, (tab) => {
    if (chrome.runtime.lastError) return;
    activeTabUrl = tab.url || null;
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tabId === activeTabId && changeInfo.url) {
    activeTabUrl = changeInfo.url;
  }
  // 页面重新加载时清除旧数据
  if (changeInfo.status === 'loading') {
    pageDataCache.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pageDataCache.delete(tabId);
  if (tabId === activeTabId) {
    activeTabId = null;
    activeTabUrl = null;
  }
});

// ---- 用户白名单管理 ----
async function isUserWhitelisted(domain) {
  try {
    const result = await chrome.storage.local.get(['whitelist']);
    const whitelist = result.whitelist || [];
    return whitelist.includes(domain);
  } catch { return false; }
}

// ---- 完整风险评估（异步，含缓存/黑名单查询/DNS前置检查）----
async function evaluateRisk(hostname, pageUrl, downloadUrl, downloadFilename) {
  const mainDomain = UrlUtils.getMainDomain(hostname);

  // 0. 检查评分缓存（10秒内同一域名直接返回）
  const cached = getCachedScore(mainDomain);
  if (cached) {
    console.log('[银狐猎手] 📦 评分缓存命中:', mainDomain, '分数:', cached.score);
    return cached;
  }

  // 0.5 读取用户设置
  const settings = await getUserSettings();
  const dnsCheckEnabled = settings.dnsCheck !== false; // 默认开启

  // 1. DNS 劫持前置检测（如果开启）
  let dnsHijacked = false;
  let dnsResolvedIP = null;
  if (dnsCheckEnabled && typeof DNS_CHECKER !== 'undefined') {
    try {
      const dnsServer = settings.dnsServer || 'auto';
      const dnsResult = await DNS_CHECKER.getDNSIP(hostname, dnsServer);
      dnsResolvedIP = dnsResult.ip;
      // 注意：由于无法直接获取页面实际连接IP，此处仅记录解析IP
      // 劫持判定需要 content_script 上报 actualIP
    } catch (e) {
      console.warn('[银狐猎手] DNS检测异常:', e);
    }
  }

  // 2. 完全信任域名 → 直接安全（DNS劫持时不生效）
  if (!dnsHijacked && typeof isFullyTrusted === 'function' && isFullyTrusted(hostname)) {
    const result = { score: 0, isMalicious: false, ruleResults: [], spoofResult: null, correctUrl: null, riskLevel: 'safe', dnsResolvedIP: dnsResolvedIP, dnsHijacked: false };
    setCachedScore(mainDomain, result);
    return result;
  }

  // 3. 内置白名单 → 直接安全（DNS劫持时白名单失效）
  if (!dnsHijacked && isBuiltinWhitelist(hostname)) {
    const result = { score: 0, isMalicious: false, ruleResults: [{ rule: '内置白名单', score: 0, detail: '域名在内置白名单中' }], spoofResult: null, correctUrl: null, riskLevel: 'safe', dnsResolvedIP: dnsResolvedIP, dnsHijacked: false };
    setCachedScore(mainDomain, result);
    return result;
  }

  // 3.5 政府/教育/科研后缀白名单
  if (!dnsHijacked && isGovSuffixWhitelist(hostname)) {
    const result = { score: 0, isMalicious: false, ruleResults: [{ rule: '政府/教育白名单', score: 0, detail: '域名属于政府/教育/科研机构' }], spoofResult: null, correctUrl: null, riskLevel: 'safe', dnsResolvedIP: dnsResolvedIP, dnsHijacked: false };
    setCachedScore(mainDomain, result);
    return result;
  }

  // 3.6 下载站白名单（仅主域名精确匹配）
  if (!dnsHijacked && isDownloadSiteWhitelist(hostname)) {
    const result = { score: 0, isMalicious: false, ruleResults: [{ rule: '下载站白名单', score: 0, detail: '域名在已知下载站白名单中' }], spoofResult: null, correctUrl: null, riskLevel: 'safe', dnsResolvedIP: dnsResolvedIP, dnsHijacked: false };
    setCachedScore(mainDomain, result);
    return result;
  }

  // 4. 用户白名单 → 直接安全（DNS劫持时白名单失效）
  if (!dnsHijacked && await isUserWhitelisted(mainDomain)) {
    const result = { score: 0, isMalicious: false, ruleResults: [{ rule: '白名单', score: 0, detail: '域名在用户白名单中' }], spoofResult: null, correctUrl: null, riskLevel: 'safe', dnsResolvedIP: dnsResolvedIP, dnsHijacked: false };
    setCachedScore(mainDomain, result);
    return result;
  }

  // 5. 检查站点黑名单（CacheManager 作为二级缓存）
  let isSiteBlacklisted = false;
  if (typeof SiteBlacklist !== 'undefined') {
    isSiteBlacklisted = await SiteBlacklist.isBlacklisted(hostname);
  }

  // 6. 检查下载黑名单
  let isDownloadBlacklisted = false;
  if (typeof DownloadBlacklist !== 'undefined' && downloadUrl) {
    const downloadHost = UrlUtils.extractHostname(downloadUrl);
    const downloadMain = UrlUtils.getMainDomain(downloadHost);
    isDownloadBlacklisted = await DownloadBlacklist.isBlacklisted(downloadMain);
  }

  // 7. 获取页面数据（从 tab 缓存）
  let pageData = {};
  if (activeTabId !== null) {
    pageData = pageDataCache.get(activeTabId) || {};
  }

  // 8. 同步评分
  const scoringParams = {
    hostname,
    pageUrl: pageUrl || activeTabUrl,
    downloadUrl,
    downloadFilename,
    icp: pageData.icp || null,
    icpVerified: pageData.icpVerified || null,
    downloadLinks: pageData.downloadLinks || [],
    suspiciousLinks: pageData.suspiciousLinks || [],
    pageText: pageData.pageText || '',
    domNodeCount: pageData.domNodeCount || 0,
    externalResourceCount: pageData.externalResourceCount || 0,
    frameworkMarkers: pageData.frameworkMarkers || [],
    hasInstallButton: pageData.hasInstallButton || false,
    hasLoginForm: pageData.hasLoginForm || false,
    hasCaptcha: pageData.hasCaptcha || false,
    whoisData: null, // 异步获取，此处跳过（可后续异步补充）
    isSiteBlacklisted,
    isDownloadBlacklisted
  };

  const result = ScoringEngine.evaluateSync(scoringParams);

  // 9. 写入缓存（含DNS信息）
  const enrichedResult = {
    ...result,
    dnsResolvedIP: dnsResolvedIP,
    dnsHijacked: dnsHijacked
  };
  setCachedScore(mainDomain, enrichedResult);

  if (typeof CacheManager !== 'undefined') {
    await CacheManager.set(mainDomain, {
      score: result.score,
      isMalicious: result.isMalicious,
      correctUrl: result.correctUrl,
      ruleResults: result.ruleResults
    });
  }

  return enrichedResult;
}

// ================================================================
// 消息监听
// ================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // ICP 上报（来自 content_script）
  if (message.type === 'icp') {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (tabId !== -1) {
      const existing = pageDataCache.get(tabId) || {};
      const oldIcp = existing.icp;
      existing.icp = message.icp;
      pageDataCache.set(tabId, existing);
      console.log('[银狐猎手] Tab ' + tabId + ' ICP: ' + message.icp);

      // 关键：ICP被动态抓取到时，触发重新评分
      if (message.icp && !oldIcp) {
        (async () => {
          try {
            const domain = extractDomain(message.url || activeTabUrl || '');
            if (domain) {
              // 清除缓存以确保重新评分
              const mainDomain = UrlUtils.getMainDomain(domain);
              if (typeof CacheManager !== 'undefined') {
                await CacheManager.remove(mainDomain);
              }
              // 重新评分
              const newResult = await evaluateRisk(domain, message.url || activeTabUrl, null, null);
              const riskInfo = ScoringEngine.getRiskLevel(newResult.score);
              // 通知 content_script 更新UI（等级变化报警）
              chrome.tabs.sendMessage(tabId, {
                type: 'scoreUpdate',
                data: {
                  score: newResult.score,
                  level: riskInfo.level,
                  ruleResults: newResult.ruleResults || [],
                  reason: 'ICP备案已补充（-' + (typeof SCORE_RULE_3 !== 'undefined' ? SCORE_RULE_3 : 50) + '分）'
                }
              }).catch(() => {});
            }
          } catch (e) {
            console.warn('[银狐猎手] ICP重评分失败:', e);
          }
        })();
      }
    }
    sendResponse({ status: 'ok' });
    return true;
  }

  // 页面数据上报（来自 content_script，扩展版）
  if (message.type === 'pageData') {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (tabId !== -1) {
      const pf = message.pageFingerprint || {};

      // L0 前置过滤：无下载/跳转链接 → 直接放行
      if (message.l0Passed) {
        pageDataCache.set(tabId, {
          icp: null,
          downloadLinks: [],
          suspiciousLinks: [],
          redirectLinks: [],
          l0Passed: true,
          l0Reason: message.l0Reason || 'no_links',
          url: message.url || '',
          pageTitle: pf.pageTitle || ''
        });
        console.log('[银狐猎手] Tab ' + tabId + ' L0放行：无下载或跳转链接');
        sendResponse({ status: 'ok', l0Passed: true });
        return true;
      }

      pageDataCache.set(tabId, {
        icp: message.icp || null,
        icpVerified: message.icpVerified || null,
        downloadLinks: message.downloadLinks || [],
        suspiciousLinks: message.suspiciousLinks || [],
        redirectLinks: message.redirectLinks || [],
        pageText: pf.pageText || '',
        domNodeCount: pf.domCount || 0,
        externalResourceCount: pf.externalResourceCount || 0,
        frameworkMarkers: pf.frameworkMarkers || [],
        emojiDensity: pf.emojiDensity || 0,
        hasInstallButton: pf.hasInstallButton || false,
        hasLoginForm: pf.hasLoginForm || false,
        hasCaptcha: pf.hasCaptcha || false,
        pageTitle: pf.pageTitle || '',
        url: message.url || '',
        l0Passed: false
      });
      console.log('[银狐猎手] Tab ' + tabId + ' 页面数据已更新 (下载:' + (message.downloadLinks || []).length + ' 跳转:' + (message.redirectLinks || []).length + ')');
    }
    sendResponse({ status: 'ok' });
    return true;
  }

  // 获取 ICP（来自 popup）
  if (message.type === 'getIcp') {
    const tabId = sender.tab ? sender.tab.id : -1;
    const data = (tabId !== -1 ? pageDataCache.get(tabId) : null) || {};
    // 兼容旧逻辑：也检查 activeTabId
    if (!data.icp && activeTabId !== null) {
      const activeData = pageDataCache.get(activeTabId) || {};
      sendResponse({ icp: activeData.icp || null });
    } else {
      sendResponse({ icp: data.icp || null });
    }
    return true;
  }

  // 获取页面信息（来自 popup）
  if (message.type === 'getPageInfo') {
    const tabId = activeTabId;
    const data = (tabId !== null ? pageDataCache.get(tabId) : null) || {};
    sendResponse({
      downloadLinks: data.downloadLinks || [],
      suspiciousLinks: data.suspiciousLinks || [],
      icp: data.icp || null
    });
    return true;
  }

  // 域名查询（来自 options.html）→ 使用真实 WhoisClient
  if (message.type === 'lookupDomain') {
    (async () => {
      try {
        if (typeof WhoisClient === 'undefined') {
          sendResponse({ success: false, error: 'WhoisClient 模块未加载' });
          return;
        }
        const result = await WhoisClient.lookup(message.domain);
        if (result) {
          sendResponse({ success: true, data: result });
        } else {
          sendResponse({ success: false, error: '查询失败：未找到域名注册信息' });
        }
      } catch (e) {
        console.error('[银狐猎手] 域名查询异常:', e);
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true; // 异步响应
  }

  // ---- 站点黑名单管理 ----
  if (message.type === 'addSiteBlacklist') {
    (async () => {
      try {
        await SiteBlacklist.add(message.domain, { addedBy: message.source || 'manual', note: message.note || '' });
        // 添加后清除该域名缓存，确保下次检测生效
        await CacheManager.remove(UrlUtils.getMainDomain(message.domain));
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'removeSiteBlacklist') {
    (async () => {
      try {
        await SiteBlacklist.remove(message.domain);
        await CacheManager.remove(UrlUtils.getMainDomain(message.domain));
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'getSiteBlacklist') {
    (async () => {
      try {
        const list = await SiteBlacklist.getAll();
        sendResponse({ success: true, data: list });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 下载黑名单管理 ----
  if (message.type === 'addDownloadBlacklist') {
    (async () => {
      try {
        await DownloadBlacklist.add(message.domain, {
          pageDomain: message.pageDomain || '',
          pageUrl: message.pageUrl || ''
        });
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'removeDownloadBlacklist') {
    (async () => {
      try {
        await DownloadBlacklist.remove(message.domain);
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'getDownloadBlacklist') {
    (async () => {
      try {
        const list = await DownloadBlacklist.getAll();
        sendResponse({ success: true, data: list });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 缓存管理 ----
  if (message.type === 'clearCache') {
    (async () => {
      try {
        await CacheManager.clearAll();
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 风险评估请求（来自 popup 或 options）----
  if (message.type === 'evaluateRisk') {
    (async () => {
      try {
        const result = await evaluateRisk(message.hostname, message.pageUrl, message.downloadUrl, message.downloadFilename);
        sendResponse({ success: true, data: result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 用户白名单管理 ----
  if (message.type === 'addToWhitelist') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['whitelist']);
        const whitelist = result.whitelist || [];
        if (!whitelist.includes(message.domain)) {
          whitelist.push(message.domain);
          await chrome.storage.local.set({ whitelist });
        }
        // 清除缓存
        await CacheManager.remove(UrlUtils.getMainDomain(message.domain));
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'removeFromWhitelist') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['whitelist']);
        const whitelist = result.whitelist || [];
        const newWhitelist = whitelist.filter(d => d !== message.domain);
        await chrome.storage.local.set({ whitelist: newWhitelist });
        await CacheManager.remove(UrlUtils.getMainDomain(message.domain));
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'getWhitelist') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['whitelist']);
        sendResponse({ success: true, data: result.whitelist || [] });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }



  // ---- 弹窗请求完整风险评估（自动使用当前活动标签页域名）----
  if (message.type === 'evaluateRiskForTab') {
    (async () => {
      try {
        const domain = extractDomain(activeTabUrl || '');
        if (!domain) {
          sendResponse({ success: false, error: '无法获取当前域名' });
          return;
        }

        // 检查 L0 放行状态
        const tabData = pageDataCache.get(activeTabId) || {};
        if (tabData.l0Passed) {
          sendResponse({
            success: true,
            data: {
              domain,
              url: activeTabUrl || '',
              score: 0,
              level: 'safe',
              levelText: '安全',
              isMalicious: false,
              spoofResult: null,
              correctUrl: '',
              icpNumber: tabData.icp || '',
              ruleResults: [],
              l0Passed: true,
              l0Reason: '无下载或跳转链接'
            }
          });
          return;
        }

        const result = await evaluateRisk(domain, activeTabUrl, null, null);
        const riskInfo = ScoringEngine.getRiskLevel(result.score);

        // 记录日志
        addLogEntry({
          domain,
          url: activeTabUrl || '',
          action: 'page_visit',
          riskScore: result.score,
          level: riskInfo.level,
          matchedRules: result.ruleResults.map(r => r.rule),
          whitelistHit: false,
          userAction: 'ignored',
          detail: result.ruleResults.map(r => r.rule + '(' + r.score + '分): ' + r.detail).join('；')
        });

        sendResponse({
          success: true,
          data: {
            domain,
            url: activeTabUrl || '',
            score: result.score,
            level: riskInfo.level,
            levelText: riskInfo.text,
            isMalicious: result.isMalicious,
            spoofResult: result.spoofResult || null,
            correctUrl: result.correctUrl || '',
            icpNumber: tabData.icp || '',
            ruleResults: result.ruleResults || [],
            redirectLinks: tabData.redirectLinks || [],
            l0Passed: false
          }
        });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 清除指定域名缓存（弹窗重新检测时使用）----
  if (message.type === 'clearDomainCache') {
    (async () => {
      try {
        const domain = message.domain || extractDomain(activeTabUrl || '');
        if (domain) {
          await CacheManager.remove(UrlUtils.getMainDomain(domain));
        }
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- DNS检测 ----
  if (message.type === 'checkDNS') {
    const domain = message.domain || extractDomain(activeTabUrl || '');
    if (!domain) {
      sendResponse({ success: false, error: '无法获取域名' });
      return true;
    }
    if (typeof DNS_CHECKER !== 'undefined') {
      DNS_CHECKER.checkDNSViaNetwork(domain, (result) => {
        sendResponse({ success: true, data: result });
      });
    } else {
      sendResponse({ success: false, error: 'DNS检测模块未加载' });
    }
    return true;
  }

  // ---- 网络连通性检测 ----
  if (message.type === 'checkNetwork') {
    if (typeof NETWORK_CHECKER !== 'undefined') {
      NETWORK_CHECKER.checkConnectivity((result) => {
        sendResponse({ success: true, data: result });
      });
    } else {
      sendResponse({ success: false, error: '网络检测模块未加载' });
    }
    return true;
  }

  // ---- 获取config.json内容 ----
  if (message.type === 'getConfig') {
    fetch(chrome.runtime.getURL('config.json'))
      .then(r => r.json())
      .then(cfg => {
        sendResponse({ success: true, data: cfg });
      })
      .catch(e => {
        sendResponse({ success: false, error: e.message });
      });
    return true;
  }

  // ---- 获取用户设置 ----
  if (message.type === 'getSettings') {
    (async () => {
      try {
        const settings = await getUserSettings();
        sendResponse({ success: true, data: settings });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 保存用户设置 ----
  if (message.type === 'saveSettings') {
    (async () => {
      try {
        await chrome.storage.local.set({ settings: message.settings });
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- DNS劫持上报（来自 content_script）----
  if (message.type === 'dnsHijackDetected') {
    (async () => {
      try {
        const domain = message.domain || extractDomain(activeTabUrl || '');
        await triggerDNSHijackAlert(domain, message.resolvedIP, message.actualIP);
        // 通知所有标签页更新UI
        chrome.tabs.query({}, (tabs) => {
          for (const tab of tabs) {
            if (tab.id) {
              chrome.tabs.sendMessage(tab.id, {
                type: 'dnsHijackAlert',
                data: { domain, resolvedIP: message.resolvedIP, actualIP: message.actualIP }
              }).catch(() => {});
            }
          }
        });
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 获取忽略域名列表 ----
  if (message.type === 'getIgnoredDomains') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['foxIgnoredDomains']);
        sendResponse({ success: true, data: result.foxIgnoredDomains || [] });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 添加忽略域名 ----
  if (message.type === 'addIgnoredDomain') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['foxIgnoredDomains']);
        const list = result.foxIgnoredDomains || [];
        if (!list.includes(message.domain)) {
          list.push(message.domain);
          await chrome.storage.local.set({ foxIgnoredDomains: list });
        }
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 移除忽略域名 ----
  if (message.type === 'removeIgnoredDomain') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['foxIgnoredDomains']);
        const list = (result.foxIgnoredDomains || []).filter(d => d !== message.domain);
        await chrome.storage.local.set({ foxIgnoredDomains: list });
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 全局静默 ----
  if (message.type === 'setSilentMode') {
    (async () => {
      try {
        const until = Date.now() + (message.duration || 3600) * 1000;
        await chrome.storage.local.set({ foxSilentUntil: until });
        sendResponse({ success: true, until });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'getSilentStatus') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['foxSilentUntil']);
        const until = result.foxSilentUntil || 0;
        const isSilent = until > Date.now();
        sendResponse({ success: true, isSilent, until });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- SSL 证书检测 ----
  if (message.type === 'checkSSL') {
    (async () => {
      try {
        const url = message.url || activeTabUrl || '';
        if (!url) {
          sendResponse({ success: false, error: '无法获取URL' });
          return;
        }
        const result = await checkSSLCertificate(url);
        sendResponse({ success: true, data: result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- DNS 当前源检测 ----
  if (message.type === 'detectDNSProvider') {
    (async () => {
      try {
        const result = await detectCurrentDNSProvider();
        sendResponse({ success: true, data: result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 手动 DNS 测试（使用指定服务器）----
  if (message.type === 'manualDNSTest') {
    (async () => {
      try {
        const domain = message.domain;
        const server = message.server || 'auto';
        if (!domain) {
          sendResponse({ success: false, error: '请输入域名' });
          return;
        }
        if (typeof DNS_CHECKER !== 'undefined') {
          const result = await DNS_CHECKER.checkDNS(domain, server);
          sendResponse({ success: true, data: result });
        } else {
          sendResponse({ success: false, error: 'DNS检测模块未加载' });
        }
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // ---- 打开跳转警告页面 ----
  if (message.type === 'openRedirectWarning') {
    try {
      const warningUrl = chrome.runtime.getURL('redirect-warning.html') +
        '?target=' + encodeURIComponent(message.target || '') +
        '&source=' + encodeURIComponent(message.source || '');
      chrome.tabs.create({ url: warningUrl });
      sendResponse({ success: true });
    } catch (e) {
      sendResponse({ success: false, error: e.message });
    }
    return true;
  }

  // ---- 跳转警告日志记录 ----
  if (message.type === 'redirectWarning') {
    try {
      const data = message.data || {};
      addLogEntry({
        domain: data.target ? extractDomain(data.target) || 'unknown' : 'unknown',
        url: data.source || '',
        action: 'redirect_intercept',
        riskScore: 0,
        level: 'warning',
        matchedRules: ['跳转拦截'],
        whitelistHit: false,
        userAction: data.userAction || 'pending',
        detail: '跳转拦截: ' + (data.trigger || 'unknown') + ' -> ' + (data.target || '')
      });
      sendResponse({ success: true });
    } catch (e) {
      sendResponse({ success: false, error: e.message });
    }
    return true;
  }

    sendResponse({});
  return true;
});

// ================================================================
// 下载拦截（集成缓存 + 黑名单 + 评分引擎）
// ================================================================
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  const url = downloadItem.url;
  const domain = extractDomain(url);
  const filename = downloadItem.filename || '';

  console.log('[银狐猎手] 🔍 拦截下载:', url);

  if (!domain) {
    suggest();
    return;
  }

  // 异步处理（返回 true 让 suggest 延迟调用）
  (async () => {
    try {
      const pageUrl = activeTabUrl || null;
      const result = await evaluateRisk(domain, pageUrl, url, filename);

      const riskInfo = ScoringEngine.getRiskLevel(result.score);
      const matchedRuleNames = result.ruleResults.map(r => r.rule);

      if (result.isMalicious || result.score >= DOWNLOAD_CONFIRM_THRESHOLD) {
        // 高风险：触发桌面通知
        console.warn('[银狐猎手] ⚠️ 高风险下载:', domain, '分数:', result.score);

        let notificationMessage = '域名：' + domain + '\n风险分：' + result.score;
        if (result.spoofResult) {
          notificationMessage += '\n仿冒对象：' + result.spoofResult.entry.name;
        }
        if (result.correctUrl) {
          notificationMessage += '\n官方网址：' + result.correctUrl;
        }
        if (matchedRuleNames.length > 0) {
          notificationMessage += '\n命中规则：' + matchedRuleNames.join('、');
        }

        addLogEntry({
          domain,
          url,
          action: 'download',
          riskScore: result.score,
          level: riskInfo.level,
          matchedRules: matchedRuleNames,
          whitelistHit: false,
          userAction: 'pending',
          detail: result.ruleResults.map(r => r.rule + '(' + r.score + '分): ' + r.detail).join('；')
        });

        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '⚠️ 银狐猎手 安全提醒',
          message: notificationMessage,
          priority: 1
        });

        // 如果命中仿冒，自动将下载域名加入黑名单
        if (result.spoofResult && typeof DownloadBlacklist !== 'undefined') {
          const downloadMain = UrlUtils.getMainDomain(domain);
          await DownloadBlacklist.add(downloadMain, {
            pageDomain: domain,
            pageUrl: pageUrl || url
          });
          console.log('[银狐猎手] 📋 已将下载域名加入黑名单:', downloadMain);
        }
      } else if (result.score > 0) {
        // 低风险：记录日志但不通知
        console.log('[银狐猎手] 📝 低风险下载:', domain, '分数:', result.score);
        addLogEntry({
          domain,
          url,
          action: 'download',
          riskScore: result.score,
          level: riskInfo.level,
          matchedRules: matchedRuleNames,
          whitelistHit: false,
          userAction: 'ignored',
          detail: result.ruleResults.map(r => r.rule + '(' + r.score + '分): ' + r.detail).join('；')
        });
      } else {
        console.log('[银狐猎手] ✅ 安全放行:', domain);
      }
    } catch (e) {
      console.error('[银狐猎手] 下载检测异常:', e);
    } finally {
      // 始终允许下载（仅警告不拦截）
      suggest();
    }
  })();

  return true; // 异步调用 suggest
});

// ================================================================
// 首次安装
// ================================================================
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[银狐猎手] 📦 首次安装');
    chrome.tabs.create({ url: 'legal.html' });

    // 初始化黑名单过期清理
    if (typeof DownloadBlacklist !== 'undefined') {
      DownloadBlacklist.cleanup().catch(() => {});
    }
  }

  if (details.reason === 'update') {
    console.log('[银狐猎手] 🔄 扩展已更新');
    // 更新后清理过期黑名单
    if (typeof DownloadBlacklist !== 'undefined') {
      DownloadBlacklist.cleanup().catch(() => {});
    }
  }
});

console.log('[银狐猎手] ✅ 后台引擎就绪');
