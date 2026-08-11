// redirect-warning.js - 跳转警告页面逻辑

(function() {
  'use strict';

  // 解析 URL 参数
  var params = new URLSearchParams(window.location.search);
  var targetUrl = params.get('target') || '';
  var sourceUrl = params.get('source') || '';
  var targetDomain = '';
  var sourceDomain = '';

  try {
    if (targetUrl) targetDomain = new URL(targetUrl).hostname;
    if (sourceUrl) sourceDomain = new URL(sourceUrl).hostname;
  } catch (e) {
    console.error('URL 解析失败:', e);
  }

  // 显示域名信息
  document.getElementById('targetDomain').textContent = targetDomain || '未知域名';
  document.getElementById('sourceDomain').textContent = sourceDomain || '未知来源';

  // 返回原网站
  document.getElementById('btnBack').addEventListener('click', function() {
    // 记录日志
    logRedirect('return');
    window.history.back();
    // 如果 history.back() 无效，尝试关闭标签页
    setTimeout(function() {
      window.close();
    }, 500);
  });

  // 继续前往
  document.getElementById('btnContinue').addEventListener('click', function() {
    var dontAsk = document.getElementById('dontAskAgain').checked;

    if (dontAsk && targetDomain) {
      // 设置 1 小时内不再提示此域名
      chrome.storage.local.get(['foxIgnoredRedirects'], function(result) {
        var ignored = result.foxIgnoredRedirects || {};
        ignored[targetDomain] = Date.now() + 3600000; // 1小时后过期
        chrome.storage.local.set({ foxIgnoredRedirects: ignored }, function() {
          logRedirect('continue_with_suppress');
          window.location.href = targetUrl;
        });
      });
    } else {
      logRedirect('continue');
      window.location.href = targetUrl;
    }
  });

  // 拦截并加入黑名单
  document.getElementById('btnBlock').addEventListener('click', function() {
    logRedirect('block');
    // 通知 background 添加黑名单
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'addSiteBlacklist',
        domain: targetDomain,
        source: 'redirect_warning'
      }, function() {
        window.history.back();
        setTimeout(function() {
          window.close();
        }, 500);
      });
    } else {
      // 降级处理：直接返回
      window.history.back();
      setTimeout(function() {
        window.close();
      }, 500);
    }
  });

  // 记录跳转日志
  function logRedirect(userAction) {
    if (!chrome || !chrome.storage || !chrome.storage.local) return;

    chrome.storage.local.get(['foxLogs'], function(result) {
      var logs = result.foxLogs || [];
      logs.unshift({
        id: Date.now() + Math.random().toString(36).substr(2, 6),
        timestamp: Date.now(),
        level: 'warning',
        type: 'redirect_intercept',
        message: '跳转拦截: ' + sourceDomain + ' -> ' + targetDomain,
        source: sourceDomain,
        target: targetDomain,
        targetUrl: targetUrl,
        trigger: 'redirect_warning_page',
        userAction: userAction,
        url: sourceUrl
      });
      // 保留最近 500 条
      if (logs.length > 500) logs = logs.slice(0, 500);
      chrome.storage.local.set({ foxLogs: logs });
    });
  }

  // 页面加载时通知 background 记录
  if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'log',
      level: 'warning',
      message: '跳转拦截页面已打开',
      source: targetDomain,
      target: targetDomain
    });
  }
})();
