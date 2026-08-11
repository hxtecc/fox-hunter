// ================================================================
// 主题管理器 - 全局黑金科幻配色系统
// 所有页面通过 CSS 变量继承配色
// ================================================================

// ----- 配色方案 -----
const COLORS = {
  dark: {
    '--bg': '#0a0a0f',
    '--bg-card': '#14141f',
    '--bg-input': '#1a1a2a',
    '--bg-hover': '#22223a',
    '--text': '#e8e8f0',
    '--text-muted': '#8888aa',
    '--text-dim': '#55556a',
    '--border': '#2a2a4a',
    '--border-light': '#3a3a5a',
    '--gold': '#f0c060',
    '--gold-dim': '#d4a040',
    '--gold-glow': 'rgba(240, 192, 96, 0.15)',
    '--cyan': '#40d4c0',
    '--cyan-dim': '#2b9b8c',
    '--cyan-glow': 'rgba(64, 212, 192, 0.12)',
    '--danger': '#ef5350',
    '--danger-bg': 'rgba(239, 83, 80, 0.12)',
    '--success': '#10b981',
    '--success-bg': 'rgba(16, 185, 129, 0.12)',
    '--warning': '#f59e0b',
    '--warning-bg': 'rgba(245, 158, 11, 0.12)',
    '--radius': '10px',
    '--radius-sm': '6px',
    '--shadow': '0 8px 32px rgba(0,0,0,0.5)',
    '--shadow-gold': '0 4px 24px rgba(240, 192, 96, 0.08)',
  },
  light: {
    '--bg': '#f0f2f5',
    '--bg-card': '#ffffff',
    '--bg-input': '#f5f7fa',
    '--bg-hover': '#eef2f6',
    '--text': '#1a1a2e',
    '--text-muted': '#6b7280',
    '--text-dim': '#9ca3af',
    '--border': '#d1d5db',
    '--border-light': '#e5e7eb',
    '--gold': '#d4a040',
    '--gold-dim': '#b8923a',
    '--gold-glow': 'rgba(212, 160, 64, 0.12)',
    '--cyan': '#2b9b8c',
    '--cyan-dim': '#1f7a6e',
    '--cyan-glow': 'rgba(43, 155, 140, 0.10)',
    '--danger': '#dc2626',
    '--danger-bg': 'rgba(220, 38, 38, 0.08)',
    '--success': '#059669',
    '--success-bg': 'rgba(5, 150, 105, 0.08)',
    '--warning': '#d97706',
    '--warning-bg': 'rgba(217, 119, 6, 0.08)',
    '--radius': '10px',
    '--radius-sm': '6px',
    '--shadow': '0 8px 32px rgba(0,0,0,0.10)',
    '--shadow-gold': '0 4px 24px rgba(212, 160, 64, 0.08)',
  }
};

const STORAGE_KEY = 'foxTheme';

// ----- 获取当前主题 -----
function getTheme(callback) {
  chrome.storage.local.get([STORAGE_KEY], (result) => {
    const saved = result[STORAGE_KEY] || { mode: 'dark' };
    const mode = saved.mode === 'light' ? 'light' : 'dark';
    callback({ mode, ...COLORS[mode] });
  });
}

// ----- 切换主题 -----
function setTheme(mode) {
  if (mode !== 'light' && mode !== 'dark') return;
  chrome.storage.local.set({ [STORAGE_KEY]: { mode } });
  applyThemeToDocument(mode);
}

// ----- 应用主题到当前文档 -----
function applyThemeToDocument(mode) {
  const colors = COLORS[mode] || COLORS.dark;
  const root = document.documentElement;
  for (const [key, value] of Object.entries(colors)) {
    root.style.setProperty(key, value);
  }
}

// ----- 应用主题到所有标签页 -----
function applyThemeToAllTabs(mode) {
  // 当前页面
  applyThemeToDocument(mode);
  // 其他标签页
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id) {
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (m) => {
            const c = m === 'light' ? COLORS.light : COLORS.dark;
            const root = document.documentElement;
            for (const [key, value] of Object.entries(c)) {
              root.style.setProperty(key, value);
            }
          },
          args: [mode]
        }).catch(() => {});
      }
    }
  });
}

// ----- 页面初始化：自动应用已保存主题 -----
(function initTheme() {
  chrome.storage.local.get([STORAGE_KEY], (result) => {
    const saved = result[STORAGE_KEY] || { mode: 'dark' };
    applyThemeToDocument(saved.mode);
  });
})();

// 导出全局函数
window.getTheme = getTheme;
window.setTheme = setTheme;
window.applyThemeToDocument = applyThemeToDocument;
window.applyThemeToAllTabs = applyThemeToAllTabs;