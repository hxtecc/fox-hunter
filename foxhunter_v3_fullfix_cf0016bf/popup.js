// ================================================================
// 银狐猎手 - popup.js（完整增强版 v2）
// 支持：标签切换 + 风险评分 + 网络检测 + L0放行显示
// ================================================================

// ----- 元素引用 -----
var statusBadge = document.getElementById('statusBadge');
var domainEl = document.getElementById('popupDomain');
var icpEl = document.getElementById('popupIcp');
var scoreValueEl = document.getElementById('scoreValue');
var scoreRingEl = document.getElementById('scoreRing');
var scoreLabelEl = document.getElementById('scoreLabel');
var rulesListEl = document.getElementById('rulesList');
var rescanBtn = document.getElementById('rescanBtn');
var settingsBtn = document.getElementById('settingsBtn');
var scoreArea = document.getElementById('scoreArea');
var l0PassInfo = document.getElementById('l0PassInfo');

// Network tab elements
var dnsDot = document.getElementById('dnsDot');
var dnsStatus = document.getElementById('dnsStatus');
var dnsProvider = document.getElementById('dnsProvider');
var dnsCheckBtn = document.getElementById('dnsCheckBtn');
var dnsResult = document.getElementById('dnsResult');
var netDot = document.getElementById('netDot');
var netStatus = document.getElementById('netStatus');
var netCheckBtn = document.getElementById('netCheckBtn');
var netResult = document.getElementById('netResult');

// ----- 状态 -----
var currentTabId = null;
var currentDomain = '';

// ----- 风险等级配色 -----
var LEVEL_COLORS = {
  safe:    { main: '#10b981', bg: 'rgba(16,185,129,0.12)', text: '安全' },
  warning: { main: '#f59e0b', bg: 'rgba(245,158,11,0.12)', text: '可疑' },
  danger:  { main: '#ef5350', bg: 'rgba(239,83,80,0.12)',  text: '高危' }
};

// ================================================================
// Tab 切换
// ================================================================
var tabBtns = document.querySelectorAll('.tab-btn');
for (var i = 0; i < tabBtns.length; i++) {
  tabBtns[i].addEventListener('click', function() {
    var target = this.getAttribute('data-tab');
    // 更新按钮状态
    for (var j = 0; j < tabBtns.length; j++) {
      tabBtns[j].classList.remove('active');
    }
    this.classList.add('active');
    // 切换内容
    document.getElementById('tabRisk').classList.remove('active');
    document.getElementById('tabNetwork').classList.remove('active');
    if (target === 'risk') {
      document.getElementById('tabRisk').classList.add('active');
    } else if (target === 'network') {
      document.getElementById('tabNetwork').classList.add('active');
    }
  });
}

// ================================================================
// 初始化
// ================================================================
(async function init() {
  try {
    // 读取用户设置（主题、颜色等）
    chrome.storage.local.get(['settings'], function(result) {
      var settings = result.settings || {};
      var ball = settings.ball || {};
      if (ball.safeColor) LEVEL_COLORS.safe = { main: ball.safeColor, text: '安全' };
      if (ball.warningColor) LEVEL_COLORS.warning = { main: ball.warningColor, text: '可疑' };
      if (ball.dangerColor) LEVEL_COLORS.danger = { main: ball.dangerColor, text: '高危' };
      if (settings.themeMode === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
      }
    });

    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    var tab = tabs[0];
    if (!tab) {
      showError('无法获取当前标签页');
      return;
    }
    currentTabId = tab.id;

    var tabUrl = tab.url || '';
    if (tabUrl.startsWith('chrome://') || tabUrl.startsWith('chrome-extension://') || tabUrl.startsWith('edge://')) {
      domainEl.textContent = '浏览器内部页面';
      setStatusBadge('safe');
      scoreValueEl.textContent = '0';
      scoreLabelEl.textContent = '安全';
      return;
    }

    // 域名提取（带降级）
    currentDomain = extractDomainFromUrl(tabUrl);
    if (!currentDomain || currentDomain === '') {
      currentDomain = '未知域名';
    }
    domainEl.textContent = currentDomain;

    // 并行获取：background 完整评分 + content_script 页面信息
    var results = await Promise.all([
      chrome.runtime.sendMessage({ type: 'evaluateRiskForTab' }).catch(function() { return null; }),
      chrome.tabs.sendMessage(tab.id, { type: 'getPageInfo' }).catch(function() { return null; })
    ]);

    var bgResponse = results[0];
    var pageInfo = results[1];

    if (bgResponse && bgResponse.success && bgResponse.data) {
      var data = bgResponse.data;
      currentDomain = data.domain || currentDomain;
      renderFullResult(data, pageInfo);
    } else if (pageInfo) {
      renderFallbackResult(currentDomain, pageInfo);
    } else {
      showError('无法获取页面信息');
    }
  } catch (e) {
    showError('初始化失败: ' + e.message);
  }
})();

// ----- 渲染完整评分结果 -----
function renderFullResult(data, pageInfo) {
  domainEl.textContent = data.domain || '未知';

  var icpNumber = data.icpNumber || (pageInfo && pageInfo.icp) || '';
  icpEl.textContent = icpNumber ? '🛡️ ' + icpNumber : '🛡️ 未检测到 ICP 备案';

  // L0 放行检查
  if (data.l0Passed) {
    scoreArea.style.display = 'none';
    l0PassInfo.style.display = 'block';
    setStatusBadge('safe');
    return;
  }

  scoreArea.style.display = 'block';
  l0PassInfo.style.display = 'none';

  var score = data.score || 0;
  var level = data.level || 'safe';
  renderScoreRing(score, level);
  setStatusBadge(level);
  renderRulesList(data.ruleResults || []);

  // 仿冒提示
  if (data.spoofResult && data.correctUrl) {
    var existing = document.querySelector('.spoof-hint');
    if (existing) existing.remove();
    var spoofHint = document.createElement('div');
    spoofHint.className = 'spoof-hint';
    spoofHint.style.cssText = 'margin-top:10px;padding:8px 12px;background:rgba(239,83,80,0.08);border:1px solid rgba(239,83,80,0.25);border-radius:8px;font-size:12px;color:var(--danger);';
    spoofHint.innerHTML = '⚠️ 疑似仿冒 <b>' + escapeHtml(data.spoofResult.entry ? data.spoofResult.entry.name : '未知品牌') +
      '</b><br>官方网址：<a href="' + escapeHtml(data.correctUrl) + '" target="_blank" style="color:var(--cyan);">' + escapeHtml(data.correctUrl) + '</a>';
    rulesListEl.parentNode.insertBefore(spoofHint, rulesListEl.nextSibling);
  }
}

// ----- 降级渲染 -----
function renderFallbackResult(domain, pageInfo) {
  domainEl.textContent = domain || '未知';

  var icp = pageInfo.icp || '';
  icpEl.textContent = icp ? '🛡️ ' + icp : '🛡️ 未检测到 ICP 备案';

  // L0 放行
  if (pageInfo.l0Passed) {
    scoreArea.style.display = 'none';
    l0PassInfo.style.display = 'block';
    setStatusBadge('safe');
    return;
  }

  scoreArea.style.display = 'block';
  l0PassInfo.style.display = 'none';

  var suspCount = (pageInfo.suspiciousLinks || []).length;
  var noIcp = !icp;
  var score = Math.min(suspCount * 12 + (noIcp ? 10 : 0), 100);
  var level = score >= 100 ? 'danger' : score >= 50 ? 'warning' : 'safe';

  renderScoreRing(score, level);
  setStatusBadge(level);

  var rules = [];
  if (suspCount > 0) {
    rules.push({ rule: '可疑链接', score: suspCount * 12, detail: suspCount + ' 个可疑下载链接', maxScore: 40 });
  }
  if (noIcp) {
    rules.push({ rule: 'ICP 备案缺失', score: 10, detail: '未检测到 ICP 备案号', maxScore: 50 });
  }
  renderRulesList(rules);
}

// ----- 风险评分圆环 -----
function renderScoreRing(score, level) {
  var color = LEVEL_COLORS[level] || LEVEL_COLORS.safe;
  var clampedScore = Math.min(Math.max(score, 0), 200);
  var displayScore = Math.min(clampedScore, 200);

  scoreValueEl.textContent = displayScore;
  scoreValueEl.style.color = color.main;
  scoreLabelEl.textContent = color.text;
  scoreLabelEl.style.color = color.main;

  var radius = 36;
  var circumference = 2 * Math.PI * radius;
  var pct = Math.min(clampedScore / 200, 1);
  var offset = circumference * (1 - pct);

  scoreRingEl.innerHTML =
    '<svg viewBox="0 0 100 100" width="88" height="88">' +
    '  <circle cx="50" cy="50" r="' + radius + '" fill="none" stroke="var(--border)" stroke-width="5" />' +
    '  <circle cx="50" cy="50" r="' + radius + '" fill="none" stroke="' + color.main + '" stroke-width="5"' +
    '    stroke-linecap="round"' +
    '    stroke-dasharray="' + circumference + '"' +
    '    stroke-dashoffset="' + offset + '"' +
    '    transform="rotate(-90 50 50)"' +
    '    style="transition: stroke-dashoffset 0.8s ease, stroke 0.4s ease;" />' +
    '</svg>';
}

// ----- 状态徽章 -----
function setStatusBadge(level) {
  var color = LEVEL_COLORS[level] || LEVEL_COLORS.safe;
  statusBadge.textContent = color.text;
  statusBadge.className = 'status-badge status-' + level;
}

// ----- 命中规则列表 -----
function renderRulesList(ruleResults) {
  rulesListEl.innerHTML = '';

  if (!ruleResults || ruleResults.length === 0) {
    rulesListEl.innerHTML = '<div style="color:var(--success);font-size:13px;padding:8px 0;">✅ 未触发任何风险规则</div>';
    return;
  }

  var sorted = ruleResults
    .filter(function(r) { return r.score !== 0; })
    .sort(function(a, b) { return b.score - a.score; });

  if (sorted.length === 0) {
    rulesListEl.innerHTML = '<div style="color:var(--success);font-size:13px;padding:8px 0;">✅ 未触发任何风险规则</div>';
    return;
  }

  for (var i = 0; i < sorted.length; i++) {
    var r = sorted[i];
    var isPositive = r.score > 0;
    var scoreColor = isPositive ? 'var(--danger)' : 'var(--success)';
    var scoreSign = isPositive ? '+' : '';
    var maxScore = r.maxScore || 100;

    var item = document.createElement('div');
    item.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);';
    item.innerHTML =
      '<span style="font-size:12px;font-weight:700;color:' + scoreColor + ';min-width:42px;text-align:right;">' +
        scoreSign + r.score + '分</span>' +
      '<span style="font-size:13px;font-weight:600;color:var(--text);min-width:90px;">' + escapeHtml(r.rule) + '</span>' +
      '<span style="font-size:11px;color:var(--text-muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(r.detail) + '">' +
        escapeHtml(r.detail) + '</span>';
    rulesListEl.appendChild(item);
  }
}

// ================================================================
// 网络检测功能
// ================================================================

// DNS 检测
dnsCheckBtn.addEventListener('click', function() {
  dnsCheckBtn.disabled = true;
  dnsCheckBtn.textContent = '⏳ 检测中...';
  dnsDot.className = 'net-dot gray';
  dnsStatus.textContent = '检测中...';
  dnsProvider.textContent = '检测中...';
  dnsResult.classList.remove('show');

  chrome.runtime.sendMessage({ type: 'checkDNS' }, function(response) {
    dnsCheckBtn.disabled = false;
    dnsCheckBtn.textContent = '🔍 手动检测DNS';

    if (response && response.success && response.data) {
      var data = response.data;
      if (data.isHijacked) {
        dnsDot.className = 'net-dot red';
        dnsStatus.textContent = '异常 - DNS可能被劫持';
        dnsStatus.style.color = 'var(--danger)';
        dnsProvider.textContent = data.dnsProvider || '未知';
        dnsResult.className = 'net-result show error';
        dnsResult.textContent = '⚠️ ' + (data.error || 'DNS解析异常，可能存在劫持');
      } else {
        dnsDot.className = 'net-dot green';
        dnsStatus.textContent = '正常';
        dnsStatus.style.color = 'var(--success)';
        dnsProvider.textContent = data.dnsProvider || '正常';
        dnsResult.className = 'net-result show success';
        dnsResult.textContent = '✅ DNS解析正常';
      }
    } else {
      dnsDot.className = 'net-dot red';
      dnsStatus.textContent = '检测失败';
      dnsStatus.style.color = 'var(--danger)';
      dnsResult.className = 'net-result show error';
      dnsResult.textContent = '❌ ' + (response ? response.error : '检测失败');
    }
  });
});

// 网络连通性检测
netCheckBtn.addEventListener('click', function() {
  netCheckBtn.disabled = true;
  netCheckBtn.textContent = '⏳ 检测中...';
  netDot.className = 'net-dot gray';
  netStatus.textContent = '检测中...';
  netResult.classList.remove('show');

  chrome.runtime.sendMessage({ type: 'checkNetwork' }, function(response) {
    netCheckBtn.disabled = false;
    netCheckBtn.textContent = '🌐 检测网络连通性';

    if (response && response.success && response.data) {
      var data = response.data;
      if (data.isOnline) {
        netDot.className = 'net-dot green';
        netStatus.textContent = '正常 (通过 ' + (data.successTarget || '测试目标') + ' 验证)';
        netStatus.style.color = 'var(--success)';
        netResult.className = 'net-result show success';
        var details = data.testedTargets.map(function(t) {
          return t.name + ': ' + (t.success ? '✅ ' + t.elapsed + 'ms' : '❌ ' + (t.error || '失败'));
        }).join(' | ');
        netResult.textContent = '✅ 网络正常 - ' + details;
      } else {
        netDot.className = 'net-dot red';
        netStatus.textContent = '异常';
        netStatus.style.color = 'var(--danger)';
        netResult.className = 'net-result show error';
        netResult.textContent = '❌ ' + (data.error || '网络连接异常，请检查网络或VPN设置');
      }
    } else {
      netDot.className = 'net-dot red';
      netStatus.textContent = '检测失败';
      netStatus.style.color = 'var(--danger)';
      netResult.className = 'net-result show error';
      netResult.textContent = '❌ ' + (response ? response.error : '检测失败');
    }
  });
});

// ================================================================
// 重新检测 & 管理设置
// ================================================================
rescanBtn.addEventListener('click', async function() {
  rescanBtn.disabled = true;
  rescanBtn.textContent = '⏳ 重新检测中...';

  try {
    if (currentTabId) {
      await chrome.tabs.sendMessage(currentTabId, { type: 'rescanPage' });
    }
    await chrome.runtime.sendMessage({ type: 'clearDomainCache' });
    await new Promise(function(resolve) { setTimeout(resolve, 1200); });
    // 重新初始化
    location.reload();
  } catch (e) {
    // ignore
  } finally {
    rescanBtn.disabled = false;
    rescanBtn.textContent = '🔄 重新检测';
  }
});

settingsBtn.addEventListener('click', function() {
  chrome.runtime.openOptionsPage();
});

// ================================================================
// 工具函数
// ================================================================
function extractDomainFromUrl(url) {
  try {
    var u = new URL(url);
    var h = u.hostname;
    var parts = h.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return h;
  } catch (e) {
    return '';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showError(msg) {
  domainEl.textContent = msg;
  setStatusBadge('safe');
  scoreValueEl.textContent = '0';
  scoreLabelEl.textContent = '--';
}
