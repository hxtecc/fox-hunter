// ================================================================
// 银狐猎手 - 设置页面（完整增强版 v3）
// 支持：侧边栏布局 + 7个面板 + 完整功能
// ================================================================

// ---- 全局状态 ----
let currentSettings = {};
let currentConfig = {};
let whitelistDomains = [];
let ignoredDomains = [];
let logs = [];
let logFilter = 'all';
let logPage = 1;
const LOGS_PER_PAGE = 20;

// ---- 默认设置 ----
const DEFAULT_SETTINGS = {
  themeMode: 'dark',
  scanInterval: 3,
  silentDuration: 1,
  enableNotifications: true,
  enableSound: true,
  popupCooldown: 60,
  enableDNSCheck: true,
  dnsCheckInterval: 30,
  enableDNSAlert: true,
  dnsServer: 'auto',
  ball: {
    enabled: true,
    size: 56,
    opacity: 0.8,
    safeColor: '#10b981',
    warningColor: '#f59e0b',
    dangerColor: '#ef5350'
  },
  popup: {
    enabled: true
  },
  redirect: {
    enabled: true
  },
  downloadHook: {
    enabled: true
  },
  ssl: {
    enabled: true
  },
  safeThreshold: 50,
  dangerThreshold: 100
};

// ---- 初始化 ----
document.addEventListener('DOMContentLoaded', async function() {
  await loadAllData();
  initSidebar();
  initGeneralPanel();
  initWhitelistPanel();
  initAppearancePanel();
  initRulesPanel();
  initDNSPanel();
  initLogsPanel();
  initAboutPanel();
  initHeaderButtons();
});

// ---- 加载所有数据 ----
async function loadAllData() {
  // 加载设置
  const result = await chrome.storage.local.get(['settings', 'whitelist', 'foxIgnoredDomains', 'foxLogs']);
  currentSettings = Object.assign({}, DEFAULT_SETTINGS, result.settings || {});
  whitelistDomains = result.whitelist || [];
  ignoredDomains = result.foxIgnoredDomains || [];
  logs = result.foxLogs || [];

  // 加载 config.json
  try {
    const response = await fetch(chrome.runtime.getURL('config.json'));
    currentConfig = await response.json();
  } catch (e) {
    console.error('Failed to load config.json:', e);
  }

  // 加载版本
  try {
    const manifest = await fetch(chrome.runtime.getURL('manifest.json')).then(r => r.json());
    document.getElementById('headerVersion').textContent = 'v' + manifest.version;
    document.getElementById('aboutVersion').textContent = manifest.version;
  } catch (e) {}
}

// ---- 保存设置 ----
async function saveSettings() {
  await chrome.storage.local.set({ settings: currentSettings });
  // 通知所有标签页更新
  chrome.tabs.query({}, function(tabs) {
    for (const tab of tabs) {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'settingsUpdated',
          settings: currentSettings
        }).catch(() => {});
      }
    }
  });
  showToast('设置已保存');
}

// ---- 侧边栏 ----
function initSidebar() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(function(item) {
    item.addEventListener('click', function() {
      const panel = this.dataset.panel;
      switchPanel(panel);
    });
  });
}

function switchPanel(panelId) {
  // 更新导航
  document.querySelectorAll('.nav-item').forEach(function(item) {
    item.classList.toggle('active', item.dataset.panel === panelId);
  });
  // 更新面板
  document.querySelectorAll('.panel').forEach(function(panel) {
    panel.classList.toggle('active', panel.id === 'panel-' + panelId);
  });
}

// ---- 通用设置面板 ----
function initGeneralPanel() {
  const themeMode = document.getElementById('themeMode');
  const scanInterval = document.getElementById('scanInterval');
  const silentDuration = document.getElementById('silentDuration');
  const enableNotifications = document.getElementById('enableNotifications');
  const enableSound = document.getElementById('enableSound');
  const popupCooldown = document.getElementById('popupCooldown');

  // 填充当前值
  themeMode.value = currentSettings.themeMode || 'dark';
  scanInterval.value = currentSettings.scanInterval ?? 3;
  silentDuration.value = currentSettings.silentDuration ?? 1;
  enableNotifications.checked = currentSettings.enableNotifications !== false;
  enableSound.checked = currentSettings.enableSound !== false;
  popupCooldown.value = currentSettings.popupCooldown ?? 60;

  // 绑定事件
  themeMode.addEventListener('change', function() {
    currentSettings.themeMode = this.value;
    applyTheme(this.value);
    saveSettings();
  });

  scanInterval.addEventListener('change', function() {
    currentSettings.scanInterval = parseInt(this.value) || 3;
    saveSettings();
  });

  silentDuration.addEventListener('change', function() {
    currentSettings.silentDuration = parseInt(this.value) || 1;
    saveSettings();
  });

  enableNotifications.addEventListener('change', function() {
    currentSettings.enableNotifications = this.checked;
    saveSettings();
  });

  enableSound.addEventListener('change', function() {
    currentSettings.enableSound = this.checked;
    saveSettings();
  });

  popupCooldown.addEventListener('change', function() {
    currentSettings.popupCooldown = parseInt(this.value) || 60;
    saveSettings();
  });

  // 功能开关
  const ballEnabled = document.getElementById('ballEnabled');
  const popupEnabled = document.getElementById('popupEnabled');
  const downloadHookEnabled = document.getElementById('downloadHookEnabled');

  if (ballEnabled) {
    ballEnabled.checked = currentSettings.ball && currentSettings.ball.enabled !== false;
    ballEnabled.addEventListener('change', function() {
      if (!currentSettings.ball) currentSettings.ball = {};
      currentSettings.ball.enabled = this.checked;
      saveSettings();
    });
  }

  if (popupEnabled) {
    popupEnabled.checked = currentSettings.popup && currentSettings.popup.enabled !== false;
    popupEnabled.addEventListener('change', function() {
      if (!currentSettings.popup) currentSettings.popup = {};
      currentSettings.popup.enabled = this.checked;
      saveSettings();
    });
  }

  if (downloadHookEnabled) {
    downloadHookEnabled.checked = currentSettings.downloadHook && currentSettings.downloadHook.enabled !== false;
    downloadHookEnabled.addEventListener('change', function() {
      if (!currentSettings.downloadHook) currentSettings.downloadHook = {};
      currentSettings.downloadHook.enabled = this.checked;
      saveSettings();
    });
  }

  // 跳转拦截开关
  const redirectEnabled = document.getElementById('redirectEnabled');
  if (redirectEnabled) {
    redirectEnabled.checked = currentSettings.redirect && currentSettings.redirect.enabled !== false;
    redirectEnabled.addEventListener('change', function() {
      if (!currentSettings.redirect) currentSettings.redirect = {};
      currentSettings.redirect.enabled = this.checked;
      saveSettings();
    });
  }

  // SSL 证书检测开关
  const sslEnabled = document.getElementById('sslEnabled');
  if (sslEnabled) {
    sslEnabled.checked = currentSettings.ssl && currentSettings.ssl.enabled !== false;
    sslEnabled.addEventListener('change', function() {
      if (!currentSettings.ssl) currentSettings.ssl = {};
      currentSettings.ssl.enabled = this.checked;
      saveSettings();
    });
  }

  // 应用主题
  applyTheme(currentSettings.themeMode || 'dark');
}

function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
}

// ---- 白名单管理面板 ----
function initWhitelistPanel() {
  renderWhitelist();
  renderIgnoredList();

  const input = document.getElementById('whitelistInput');
  const btnAdd = document.getElementById('btnAddWhitelist');

  btnAdd.addEventListener('click', function() {
    const domain = input.value.trim().toLowerCase();
    if (!domain) return;
    if (whitelistDomains.includes(domain)) {
      showToast('域名已在白名单中', 'warning');
      return;
    }
    whitelistDomains.push(domain);
    chrome.storage.local.set({ whitelist: whitelistDomains });
    input.value = '';
    renderWhitelist();
    showToast('已添加到白名单');
  });

  input.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') btnAdd.click();
  });
}

function renderWhitelist() {
  const container = document.getElementById('whitelistContainer');
  const countEl = document.getElementById('whitelistCount');

  // 内置白名单
  const builtinWhitelist = (currentConfig.whitelist && currentConfig.whitelist.builtin) || [];
  const totalCount = builtinWhitelist.length + whitelistDomains.length;
  countEl.textContent = totalCount;

  let html = '';

  // 内置白名单（只读）
  if (builtinWhitelist.length > 0) {
    html += '<div class="whitelist-section"><h4 class="whitelist-section-title">内置白名单（只读）</h4>';
    html += builtinWhitelist.map(function(domain) {
      return '<div class="whitelist-item whitelist-builtin">' +
        '<span class="whitelist-domain">' + escapeHtml(domain) + '</span>' +
        '<span class="whitelist-badge">内置</span>' +
        '</div>';
    }).join('');
    html += '</div>';
  }

  // 用户白名单（可删除）
  if (whitelistDomains.length > 0) {
    html += '<div class="whitelist-section"><h4 class="whitelist-section-title">用户白名单 (' + whitelistDomains.length + ')</h4>';
    html += whitelistDomains.map(function(domain) {
      return '<div class="whitelist-item">' +
        '<span class="whitelist-domain">' + escapeHtml(domain) + '</span>' +
        '<button class="btn btn-ghost btn-sm" data-remove="' + escapeHtml(domain) + '">移除</button>' +
        '</div>';
    }).join('');
    html += '</div>';
  }

  if (totalCount === 0) {
    html = '<div class="empty-state">暂无白名单域名</div>';
  }

  container.innerHTML = html;

  container.querySelectorAll('[data-remove]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      const domain = this.dataset.remove;
      whitelistDomains = whitelistDomains.filter(function(d) { return d !== domain; });
      chrome.storage.local.set({ whitelist: whitelistDomains });
      renderWhitelist();
      showToast('已从白名单移除');
    });
  });
}

function renderIgnoredList() {
  const container = document.getElementById('ignoredContainer');
  const countEl = document.getElementById('ignoredCount');
  countEl.textContent = ignoredDomains.length;

  if (ignoredDomains.length === 0) {
    container.innerHTML = '<div class="empty-state">暂无忽略域名</div>';
    return;
  }

  container.innerHTML = ignoredDomains.map(function(domain) {
    return '<div class="whitelist-item">' +
      '<span class="whitelist-domain">' + escapeHtml(domain) + '</span>' +
      '<button class="btn btn-ghost btn-sm" data-remove-ignored="' + escapeHtml(domain) + '">移除</button>' +
      '</div>';
  }).join('');

  container.querySelectorAll('[data-remove-ignored]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      const domain = this.dataset.removeIgnored;
      ignoredDomains = ignoredDomains.filter(function(d) { return d !== domain; });
      chrome.storage.local.set({ foxIgnoredDomains: ignoredDomains });
      renderIgnoredList();
      showToast('已从忽略列表移除');
    });
  });
}

// ---- 外观与阈值面板 ----
function initAppearancePanel() {
  const ball = currentSettings.ball || DEFAULT_SETTINGS.ball;

  const ballSize = document.getElementById('ballSize');
  const ballOpacity = document.getElementById('ballOpacity');
  const safeColor = document.getElementById('safeColor');
  const warningColor = document.getElementById('warningColor');
  const dangerColor = document.getElementById('dangerColor');
  const safeThreshold = document.getElementById('safeThreshold');
  const dangerThreshold = document.getElementById('dangerThreshold');

  ballSize.value = ball.size || 56;
  ballOpacity.value = ball.opacity || 0.8;
  safeColor.value = ball.safeColor || '#10b981';
  warningColor.value = ball.warningColor || '#f59e0b';
  dangerColor.value = ball.dangerColor || '#ef5350';
  safeThreshold.value = currentSettings.safeThreshold ?? 50;
  dangerThreshold.value = currentSettings.dangerThreshold ?? 100;

  document.getElementById('ballSizeValue').textContent = ballSize.value + 'px';
  document.getElementById('ballOpacityValue').textContent = ballOpacity.value;

  ballSize.addEventListener('input', function() {
    document.getElementById('ballSizeValue').textContent = this.value + 'px';
    if (!currentSettings.ball) currentSettings.ball = {};
    currentSettings.ball.size = parseInt(this.value);
    saveSettings();
  });

  ballOpacity.addEventListener('input', function() {
    document.getElementById('ballOpacityValue').textContent = this.value;
    if (!currentSettings.ball) currentSettings.ball = {};
    currentSettings.ball.opacity = parseFloat(this.value);
    saveSettings();
  });

  safeColor.addEventListener('change', function() {
    if (!currentSettings.ball) currentSettings.ball = {};
    currentSettings.ball.safeColor = this.value;
    saveSettings();
  });

  warningColor.addEventListener('change', function() {
    if (!currentSettings.ball) currentSettings.ball = {};
    currentSettings.ball.warningColor = this.value;
    saveSettings();
  });

  dangerColor.addEventListener('change', function() {
    if (!currentSettings.ball) currentSettings.ball = {};
    currentSettings.ball.dangerColor = this.value;
    saveSettings();
  });

  safeThreshold.addEventListener('change', function() {
    currentSettings.safeThreshold = parseInt(this.value) || 50;
    saveSettings();
  });

  dangerThreshold.addEventListener('change', function() {
    currentSettings.dangerThreshold = parseInt(this.value) || 100;
    saveSettings();
  });
}

// ---- 检测规则面板 ----
function initRulesPanel() {
  const container = document.getElementById('rulesContainer');
  const rules = currentConfig.rules || [];

  if (rules.length === 0) {
    container.innerHTML = '<div class="empty-state">暂无检测规则</div>';
    return;
  }

  container.innerHTML = rules.map(function(rule, index) {
    return '<div class="rule-item">' +
      '<div class="rule-info">' +
      '<span class="rule-name">' + escapeHtml(rule.name || '规则 ' + (index + 1)) + '</span>' +
      '<span class="rule-desc">' + escapeHtml(rule.description || '') + '</span>' +
      '</div>' +
      '<div class="rule-weight">' +
      '<label>权重:</label>' +
      '<input type="number" class="form-input form-input-sm" value="' + (rule.score || 0) + '" ' +
      'data-rule-index="' + index + '" min="0" max="500">' +
      '</div>' +
      '</div>';
  }).join('');

  container.querySelectorAll('[data-rule-index]').forEach(function(input) {
    input.addEventListener('change', function() {
      const index = parseInt(this.dataset.ruleIndex);
      const newScore = parseInt(this.value) || 0;
      if (currentConfig.rules && currentConfig.rules[index]) {
        currentConfig.rules[index].score = newScore;
        // 保存到 storage
        chrome.storage.local.set({ customRules: currentConfig.rules });
        showToast('规则权重已更新');
      }
    });
  });
}

// ---- DNS检测面板 ----
function initDNSPanel() {
  const enableDNSCheck = document.getElementById('enableDNSCheck');
  const dnsCheckInterval = document.getElementById('dnsCheckInterval');
  const enableDNSAlert = document.getElementById('enableDNSAlert');
  const btnDNSTest = document.getElementById('btnDNSTest');
  const dnsTestDomain = document.getElementById('dnsTestDomain');
  const dnsServer = document.getElementById('dnsServer');
  const btnDetectDns = document.getElementById('btnDetectDns');
  const currentDnsProvider = document.getElementById('currentDnsProvider');

  enableDNSCheck.checked = currentSettings.enableDNSCheck !== false;
  dnsCheckInterval.value = currentSettings.dnsCheckInterval || 30;
  enableDNSAlert.checked = currentSettings.enableDNSAlert !== false;
  dnsServer.value = currentSettings.dnsServer || 'auto';

  // 检测当前 DNS 源
  detectCurrentDnsProvider();

  if (btnDetectDns) {
    btnDetectDns.addEventListener('click', detectCurrentDnsProvider);
  }

  enableDNSCheck.addEventListener('change', function() {
    currentSettings.enableDNSCheck = this.checked;
    saveSettings();
  });

  dnsCheckInterval.addEventListener('change', function() {
    currentSettings.dnsCheckInterval = parseInt(this.value) || 30;
    saveSettings();
  });

  enableDNSAlert.addEventListener('change', function() {
    currentSettings.enableDNSAlert = this.checked;
    saveSettings();
  });

  dnsServer.addEventListener('change', function() {
    currentSettings.dnsServer = this.value;
    saveSettings();
  });

  btnDNSTest.addEventListener('click', async function() {
    const domain = dnsTestDomain.value.trim();
    if (!domain) {
      showToast('请输入域名', 'warning');
      return;
    }

    const resultDiv = document.getElementById('dnsResult');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div class="loading">正在检测...</div>';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'manualDNSTest',
        domain: domain,
        server: dnsServer.value
      });

      if (response && response.success) {
        const data = response.data;
        const serverNames = {
          'auto': '自动',
          '114dns': '114DNS',
          'alidns': '阿里DNS',
          'google': 'Google DNS',
          'cloudflare': 'Cloudflare DNS'
        };
        resultDiv.innerHTML = '<div class="dns-info">' +
          '<div class="dns-row"><span class="dns-label">域名:</span><span class="dns-value">' + escapeHtml(domain) + '</span></div>' +
          '<div class="dns-row"><span class="dns-label">DNS服务器:</span><span class="dns-value">' + escapeHtml(data.dnsProvider || serverNames[dnsServer.value] || dnsServer.value) + '</span></div>' +
          '<div class="dns-row"><span class="dns-label">解析IP:</span><span class="dns-value">' + escapeHtml(data.resolvedIP || 'N/A') + '</span></div>' +
          (data.location ? '<div class="dns-row"><span class="dns-label">归属地:</span><span class="dns-value">' + escapeHtml(data.location) + '</span></div>' : '') +
          '<div class="dns-row"><span class="dns-label">检测时间:</span><span class="dns-value">' + new Date().toLocaleString() + '</span></div>' +
          '</div>';
      } else {
        resultDiv.innerHTML = '<div class="dns-error">检测失败: ' + escapeHtml(response?.error || '未知错误') + '</div>';
      }
    } catch (e) {
      resultDiv.innerHTML = '<div class="dns-error">检测失败: ' + escapeHtml(e.message) + '</div>';
    }
  });
}

// 检测当前 DNS 提供商
async function detectCurrentDnsProvider() {
  const providerEl = document.getElementById('currentDnsProvider');
  if (!providerEl) return;

  providerEl.textContent = '检测中...';
  providerEl.className = 'dns-provider-badge detecting';

  try {
    const response = await chrome.runtime.sendMessage({ type: 'detectDNSProvider' });
    if (response && response.success && response.data) {
      const data = response.data;
      providerEl.textContent = data.provider || '未知';
      if (data.detected) {
        providerEl.className = 'dns-provider-badge detected';
      } else {
        providerEl.className = 'dns-provider-badge unknown';
      }
    } else {
      providerEl.textContent = '未知';
      providerEl.className = 'dns-provider-badge unknown';
    }
  } catch (e) {
    providerEl.textContent = '检测失败';
    providerEl.className = 'dns-provider-badge error';
  }
}

// ---- 日志面板 ----
function initLogsPanel() {
  const filterSelect = document.getElementById('logFilter');
  const btnRefresh = document.getElementById('btnRefreshLogs');

  filterSelect.addEventListener('change', function() {
    logFilter = this.value;
    logPage = 1;
    renderLogs();
  });

  btnRefresh.addEventListener('click', async function() {
    const result = await chrome.storage.local.get(['foxLogs']);
    logs = result.foxLogs || [];
    renderLogs();
  });

  renderLogs();
}

function renderLogs() {
  const container = document.getElementById('logContainer');
  const pagination = document.getElementById('logPagination');

  let filteredLogs = logs;
  if (logFilter !== 'all') {
    filteredLogs = logs.filter(function(log) {
      return log.level === logFilter;
    });
  }

  // 按时间倒序
  filteredLogs = filteredLogs.slice().sort(function(a, b) {
    return (b.timestamp || 0) - (a.timestamp || 0);
  });

  const totalPages = Math.ceil(filteredLogs.length / LOGS_PER_PAGE) || 1;
  const start = (logPage - 1) * LOGS_PER_PAGE;
  const pageLogs = filteredLogs.slice(start, start + LOGS_PER_PAGE);

  if (pageLogs.length === 0) {
    container.innerHTML = '<div class="empty-state">暂无日志记录</div>';
    pagination.innerHTML = '';
    return;
  }

  container.innerHTML = pageLogs.map(function(log) {
    const levelClass = log.level || 'info';
    const time = log.timestamp ? new Date(log.timestamp).toLocaleString() : '';
    return '<div class="log-item log-' + levelClass + '">' +
      '<div class="log-header">' +
      '<span class="log-level">' + levelClass.toUpperCase() + '</span>' +
      '<span class="log-time">' + time + '</span>' +
      '</div>' +
      '<div class="log-message">' + escapeHtml(log.message || '') + '</div>' +
      (log.domain ? '<div class="log-domain">' + escapeHtml(log.domain) + '</div>' : '') +
      '</div>';
  }).join('');

  // 分页
  let paginationHtml = '';
  if (totalPages > 1) {
    paginationHtml += '<button class="btn btn-ghost btn-sm" ' + (logPage <= 1 ? 'disabled' : '') + ' data-page="' + (logPage - 1) + '">上一页</button>';
    paginationHtml += '<span class="page-info">第 ' + logPage + ' / ' + totalPages + ' 页</span>';
    paginationHtml += '<button class="btn btn-ghost btn-sm" ' + (logPage >= totalPages ? 'disabled' : '') + ' data-page="' + (logPage + 1) + '">下一页</button>';
  }
  pagination.innerHTML = paginationHtml;

  pagination.querySelectorAll('[data-page]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      logPage = parseInt(this.dataset.page);
      renderLogs();
    });
  });
}

// ---- 关于面板 ----
function initAboutPanel() {
  // 统计数据
  document.getElementById('statTotalScans').textContent = logs.length;
  document.getElementById('statWarnings').textContent = logs.filter(function(l) { return l.level === 'warning'; }).length;
  document.getElementById('statBlocked').textContent = logs.filter(function(l) { return l.level === 'danger'; }).length;
  document.getElementById('statWhitelist').textContent = whitelistDomains.length;
}

// ---- 顶部按钮 ----
function initHeaderButtons() {
  const btnSaveAll = document.getElementById('btnSaveAll');
  const btnExportLogs = document.getElementById('btnExportLogs');
  const btnImportLogs = document.getElementById('btnImportLogs');
  const btnClearLogs = document.getElementById('btnClearLogs');

  btnSaveAll.addEventListener('click', saveSettings);

  btnExportLogs.addEventListener('click', function() {
    const data = JSON.stringify(logs, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'foxhunter_logs_' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('日志已导出');
  });

  btnImportLogs.addEventListener('click', function() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.addEventListener('change', async function(e) {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const imported = JSON.parse(text);
        if (Array.isArray(imported)) {
          logs = logs.concat(imported);
          await chrome.storage.local.set({ foxLogs: logs });
          renderLogs();
          showToast('日志已导入，共 ' + imported.length + ' 条');
        } else {
          showToast('文件格式错误', 'warning');
        }
      } catch (err) {
        showToast('导入失败: ' + err.message, 'danger');
      }
    });
    input.click();
  });

  btnClearLogs.addEventListener('click', async function() {
    if (confirm('确定要清空所有日志吗？此操作不可恢复。')) {
      logs = [];
      await chrome.storage.local.set({ foxLogs: [] });
      renderLogs();
      showToast('日志已清空');
    }
  });
}

// ---- 工具函数 ----
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type) {
  const toast = document.getElementById('saveToast');
  const textEl = toast.querySelector('.toast-text');
  textEl.textContent = msg;
  toast.style.display = 'flex';
  toast.className = 'toast toast-' + (type || 'success');
  setTimeout(function() {
    toast.style.display = 'none';
  }, 3000);
}
