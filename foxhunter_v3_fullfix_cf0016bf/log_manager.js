// ================================================================
// 日志管理器
// ================================================================
const LOG_STORAGE_KEY = 'foxLogs';
const MAX_COUNT = 5000;

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
    if (logs.length > MAX_COUNT) logs = logs.slice(0, MAX_COUNT);
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

// 暴露全局函数
window.addLogEntry = addLogEntry;
window.getAllLogs = getAllLogs;
window.getRecentLogs = getRecentLogs;
window.clearAllLogs = clearAllLogs;
window.deleteLogsByIds = deleteLogsByIds;
window.exportLogsAsJSON = exportLogsAsJSON;
window.exportLogsAsCSV = exportLogsAsCSV;