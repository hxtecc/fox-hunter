// ================================================================
// 银狐猎手 - legal.js（动态加载 config.json + 滚动同意机制）
// ================================================================

(function() {
  var consentArea = document.getElementById('consentArea');
  var btnConsent = document.getElementById('btnConsent');
  var scrollStatus = document.getElementById('scrollStatus');

  // 加载 config.json 动态填充法律条款
  fetch(chrome.runtime.getURL('config.json'))
    .then(function(r) { return r.json(); })
    .then(function(config) {
      if (config.legal) {
        // 动态填充免责声明
        if (config.legal.disclaimer) {
          var disclaimerSection = document.querySelectorAll('.section')[0];
          if (disclaimerSection) {
            disclaimerSection.innerHTML =
              '<h2>1. 免责声明</h2>' +
              '<p>' + config.legal.disclaimer + '</p>';
          }
        }
        // 动态填充隐私承诺
        if (config.legal.privacy) {
          var privacySection = document.querySelectorAll('.section')[1];
          if (privacySection) {
            privacySection.innerHTML =
              '<h2>2. 隐私承诺</h2>' +
              '<p>' + config.legal.privacy + '</p>';
          }
        }
        // 动态填充开源与版权
        if (config.legal.license) {
          var licenseSection = document.querySelectorAll('.section')[2];
          if (licenseSection) {
            licenseSection.innerHTML =
              '<h2>3. 开源与版权</h2>' +
              '<p>' + config.legal.license + '</p>';
          }
        }
        // 动态填充联系方式
        if (config.about && config.about.contactEmail) {
          var contactSection = document.querySelectorAll('.section')[3];
          if (contactSection) {
            contactSection.innerHTML =
              '<h2>4. 联系方式</h2>' +
              '<p>📧 <span class="cyan">' + config.about.contactEmail + '</span></p>';
          }
        }
      }
    })
    .catch(function() {
      // config.json 加载失败，使用默认静态内容
    });

  // 滚动到底部后启用同意按钮
  var hasScrolled = false;

  function checkScroll() {
    var scrollTop = window.scrollY || document.documentElement.scrollTop;
    var windowHeight = window.innerHeight;
    var docHeight = document.documentElement.scrollHeight;

    if (scrollTop + windowHeight >= docHeight - 50) {
      if (!hasScrolled) {
        hasScrolled = true;
        btnConsent.disabled = false;
        btnConsent.classList.add('enabled');
        scrollStatus.innerHTML = '<span class="ready">✅ 已阅读完毕，可以点击同意</span>';
      }
    }
  }

  window.addEventListener('scroll', checkScroll);
  checkScroll(); // 初始检查

  // 同意按钮点击
  btnConsent.addEventListener('click', function() {
    if (btnConsent.disabled) return;
    chrome.storage.local.set({ legalConsent: true }, function() {
      btnConsent.textContent = '✅ 已同意';
      btnConsent.disabled = true;
      setTimeout(function() { window.close(); }, 800);
    });
  });
})();
