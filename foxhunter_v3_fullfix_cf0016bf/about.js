// ================================================================
// 银狐猎手 - about.js（动态加载 config.json）
// ================================================================

(function() {
  // 加载 config.json 动态填充关于页面
  fetch(chrome.runtime.getURL('config.json'))
    .then(function(r) { return r.json(); })
    .then(function(config) {
      if (config.version) {
        var fv = document.getElementById('footerVersion');
        if (fv) fv.textContent = 'v' + config.version;
      }
      if (config.about) {
        var fa = document.getElementById('footerAuthor');
        if (fa && config.about.author) fa.textContent = config.about.author;
      }
    })
    .catch(function() {
      // config.json 加载失败，使用默认值
    });
})();
