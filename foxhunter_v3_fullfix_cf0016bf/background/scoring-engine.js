/**
 * Virus Detector — 评分引擎 (Scoring Engine)
 *
 * 8 规则评分体系，替代简单的仿冒标志判断。
 * 根据域名仿冒、下载行为、ICP 备案、链接分析、代码工程化、
 * 域名年龄、跨域下载、黑名单命中等多维度综合计算风险分数。
 *
 * @module scoring-engine
 *
 * 评分规则：
 *   规则一：域名仿冒（SCORE_RULE_1 = 60）
 *   规则二：压缩包下载（SCORE_RULE_2_HIGH = 40 / SCORE_RULE_2_LOW = 10）
 *   规则三：ICP 备案缺失/伪造（SCORE_RULE_3 = 50 / SCORE_RULE_3_FAKE = 30）
 *   规则四：链接分析（同页链接/死链/重复链接/下载按钮外链）
 *   规则五：代码工程化检测（SCORE_RULE_5 = 30 / SCORE_RULE_5_PARTIAL = 20）
 *   规则六：域名年龄（S 型衰减，最大 SCORE_DOMAIN_AGE_MAX = 60）
 *   规则七：跨域下载（SCORE_DOWNLOAD_CROSS_DOMAIN = 10）
 *   规则八：黑名单命中（SCORE_SITE_BLACKLIST = 60 / SCORE_DOWNLOAD_BLACKLIST = 20）
 *
 * 域名年龄减分：注册天数 >= 365 天的老域名可减分（最大 SCORE_DOMAIN_AGE_BONUS_MAX = 20）
 *
 * 依赖（通过 importScripts 全局加载）：
 *   - constants.js: 所有评分常量
 *   - url-utils.js: UrlUtils
 *   - trusted-platforms.js: TrustedPlatforms
 *   - trusted-download-hosts.js: TrustedDownloadHosts
 *   - exemptions/fully-trusted.js: isFullyTrusted
 *   - domain-database.js: DomainDatabase
 *   - icp-utils.js: IcpUtils
 *   - site-blacklist.js: SiteBlacklist
 *   - download-blacklist.js: DownloadBlacklist
 */

// ==================== 评分引擎 ====================

class ScoringEngine {

  /**
   * 同步评估域名/页面的风险分数
   *
   * @param {Object} params - 评估参数
   * @param {string} params.hostname - 当前页面主机名
   * @param {string} [params.pageUrl] - 当前页面完整 URL
   * @param {string} [params.downloadUrl] - 下载文件 URL（如有）
   * @param {string} [params.downloadFilename] - 下载文件名
   * @param {string|null} [params.icp] - 页面提取的 ICP 备案号
   * @param {boolean|null} [params.icpVerified] - ICP 是否经 API 核验通过
   * @param {Array} [params.downloadLinks] - 页面下载链接列表
   * @param {Array} [params.suspiciousLinks] - 可疑下载链接列表
   * @param {string} [params.pageText] - 页面文本内容
   * @param {number} [params.domNodeCount] - DOM 节点数
   * @param {number} [params.externalResourceCount] - 外部资源数
   * @param {Object|null} [params.whoisData] - 域名注册信息 { creationDays, validDays, isExpire }
   * @param {boolean} [params.isSiteBlacklisted] - 是否命中站点黑名单
   * @param {boolean} [params.isDownloadBlacklisted] - 是否命中下载黑名单
   * @param {string[]} [params.frameworkMarkers] - 检测到的框架标记
   * @returns {{ score: number, isMalicious: boolean, ruleResults: Array, spoofResult: Object|null, correctUrl: string|null, riskLevel: string }}
   */
  static evaluateSync(params) {
    const {
      hostname,
      pageUrl,
      downloadUrl,
      downloadFilename,
      icp = null,
      icpVerified = null,
      downloadLinks = [],
      suspiciousLinks = [],
      pageText = '',
      domNodeCount = 0,
      externalResourceCount = 0,
      whoisData = null,
      isSiteBlacklisted = false,
      isDownloadBlacklisted = false,
      frameworkMarkers = []
    } = params;

    let totalScore = 0;
    const ruleResults = [];
    let spoofResult = null;
    let correctUrl = null;

    const mainDomain = UrlUtils.getMainDomain(hostname);

    // ---- 前置：完全信任域名跳过全部检测 ----
    if (typeof isFullyTrusted === 'function' && isFullyTrusted(hostname)) {
      return {
        score: 0,
        isMalicious: false,
        ruleResults: [],
        spoofResult: null,
        correctUrl: null,
        riskLevel: RISK_LEVEL.SAFE
      };
    }

    // ==================== 规则八：黑名单命中（最高优先级） ====================
    if (isSiteBlacklisted) {
      totalScore += SCORE_SITE_BLACKLIST;
      ruleResults.push({
        rule: '规则八-站点黑名单',
        score: SCORE_SITE_BLACKLIST,
        detail: '域名命中站点黑名单'
      });
    }

    if (isDownloadBlacklisted) {
      totalScore += SCORE_DOWNLOAD_BLACKLIST;
      ruleResults.push({
        rule: '规则八-下载黑名单',
        score: SCORE_DOWNLOAD_BLACKLIST,
        detail: '下载域名命中黑名单'
      });
    }

    // ==================== 规则一：域名仿冒 ====================
    if (typeof DomainDatabase !== 'undefined' && !TrustedPlatforms.isTrusted(mainDomain)) {
      spoofResult = DomainDatabase.detectSpoof(hostname);
      if (spoofResult) {
        totalScore += SCORE_RULE_1;
        correctUrl = spoofResult.correctUrl || null;
        ruleResults.push({
          rule: '规则一-域名仿冒',
          score: SCORE_RULE_1,
          detail: '仿冒 ' + spoofResult.entry.name + '（' + spoofResult.matchedBy + '）'
        });
      }
    }

    // ==================== 规则二：压缩包/可执行文件下载 ====================
    const downloadTarget = downloadFilename || (downloadUrl ? downloadUrl.split('/').pop() : '');
    const lowerTarget = (downloadTarget || '').toLowerCase();

    let isArchive = false;
    for (const ext of ARCHIVE_EXTENSIONS) {
      if (lowerTarget.endsWith(ext)) { isArchive = true; break; }
    }
    let isExecutable = false;
    for (const ext of EXECUTABLE_EXTENSIONS) {
      if (lowerTarget.endsWith(ext)) { isExecutable = true; break; }
    }

    if (isArchive || isExecutable) {
      // 域名已有嫌疑分 ≥ 阈值 → 高分
      if (totalScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
        totalScore += SCORE_RULE_2_HIGH;
        ruleResults.push({
          rule: '规则二-压缩包下载(高分)',
          score: SCORE_RULE_2_HIGH,
          detail: '域名已有嫌疑(' + totalScore + '分)且下载' + (isArchive ? '压缩包' : '可执行文件')
        });
      } else {
        totalScore += SCORE_RULE_2_LOW;
        ruleResults.push({
          rule: '规则二-压缩包下载(弱信号)',
          score: SCORE_RULE_2_LOW,
          detail: '下载' + (isArchive ? '压缩包' : '可执行文件') + '：' + downloadTarget
        });
      }
    }

    // 主动扫描页面中的压缩包下载链接
    if (downloadLinks.length > 0 && typeof pageUrl === 'string') {
      const pageMainDomain = UrlUtils.getMainDomain(UrlUtils.extractHostname(pageUrl));
      let proactiveScore = 0;
      let highRiskCount = 0;
      let lowRiskCount = 0;

      for (const link of downloadLinks) {
        const linkUrl = typeof link === 'string' ? link : (link.url || '');
        if (!linkUrl) continue;
        const linkLower = linkUrl.toLowerCase();

        // 检查是否是压缩包链接
        let linkIsArchive = false;
        for (const ext of ARCHIVE_EXTENSIONS) {
          if (linkLower.endsWith(ext)) { linkIsArchive = true; break; }
        }
        if (!linkIsArchive) continue;

        const linkHost = UrlUtils.extractHostname(linkUrl);
        const linkMainDomain = UrlUtils.getMainDomain(linkHost);

        // 跨域检测
        if (linkMainDomain !== pageMainDomain) {
          // 检查是否指向可信平台
          if (TrustedDownloadHosts.isTrusted(linkHost)) {
            proactiveScore += SCORE_RULE_2_TRUSTED_PLATFORM;
          } else {
            // 检查是否含下载关键词
            const hasDownloadKw = DOWNLOAD_LINK_KEYWORDS.some(kw => linkLower.includes(kw));
            if (hasDownloadKw) {
              highRiskCount++;
              proactiveScore += SCORE_RULE_2_PER_HIGH_RISK;
            } else {
              lowRiskCount++;
              proactiveScore += SCORE_RULE_2_PER_LOW_RISK;
            }
          }
        }
      }

      // 批量分发加权
      const totalArchiveLinks = highRiskCount + lowRiskCount;
      if (totalArchiveLinks >= SCORE_RULE_2_BATCH_THRESHOLD) {
        proactiveScore = Math.min(proactiveScore * SCORE_RULE_2_BATCH_MULTIPLIER, SCORE_RULE_2_PROACTIVE_MAX);
      } else {
        proactiveScore = Math.min(proactiveScore, SCORE_RULE_2_PROACTIVE_MAX);
      }

      // 官网劫持检测：仿冒站上的下载链接指向非官方域名
      if (spoofResult && spoofResult.entry) {
        const officialDomains = spoofResult.entry.officialDomains || [];
        let hijackCount = 0;
        for (const link of downloadLinks) {
          const linkUrl = typeof link === 'string' ? link : (link.url || '');
          if (!linkUrl) continue;
          const linkHost = UrlUtils.extractHostname(linkUrl);
          const linkMain = UrlUtils.getMainDomain(linkHost);
          const isOfficial = officialDomains.some(d => {
            const dNorm = d.replace(/^www\./i, '').toLowerCase();
            return linkMain === dNorm || linkMain.endsWith('.' + dNorm);
          });
          if (!isOfficial && linkMain !== mainDomain) {
            hijackCount++;
          }
        }
        if (hijackCount > 0) {
          const hijackScore = Math.min(hijackCount * SCORE_RULE_2_HIJACK, HIJACK_SCORE_CAP);
          proactiveScore += hijackScore;
          ruleResults.push({
            rule: '规则二-官网下载劫持',
            score: hijackScore,
            detail: '仿冒站上 ' + hijackCount + ' 个下载链接指向非官方域名'
          });
        }
      }

      if (proactiveScore > 0) {
        // 域名嫌疑加权
        if (totalScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
          proactiveScore = Math.round(proactiveScore * SCORE_RULE_2_SUSPICION_MULTIPLIER);
        }
        totalScore += proactiveScore;
        ruleResults.push({
          rule: '规则二-主动扫描',
          score: proactiveScore,
          detail: '页面扫描到 ' + totalArchiveLinks + ' 个跨域压缩包链接（高危' + highRiskCount + '，低危' + lowRiskCount + '）'
        });
      }
    }

    // ==================== 规则三：ICP 备案检测 ====================
    if (typeof IcpUtils !== 'undefined') {
      const isExempt = IcpUtils.isIcpExempt(hostname);

      if (!isExempt) {
        if (!icp) {
          // 无 ICP 备案号
          totalScore += SCORE_RULE_3;
          ruleResults.push({
            rule: '规则三-ICP缺失',
            score: SCORE_RULE_3,
            detail: '页面未检测到 ICP 备案号'
          });
        } else if (icpVerified === false || IcpUtils.isBlacklistedIcp(icp)) {
          // ICP 存在但无法核验或为已知伪造号码
          totalScore += SCORE_RULE_3_FAKE;
          ruleResults.push({
            rule: '规则三-ICP可疑',
            score: SCORE_RULE_3_FAKE,
            detail: 'ICP 备案号 "' + icp + '" 无法核验或为已知伪造号码'
          });
        }
        // icpVerified === true → 通过，不加分
      }
    }

    // ==================== 规则四：链接分析 ====================
    if (downloadLinks.length > 0 && pageUrl) {
      const pageHost = UrlUtils.extractHostname(pageUrl);
      let rule4Score = 0;
      const rule4Details = [];

      // 规则四B：外链绑在下载按钮上 / 外链指向文件
      for (const link of downloadLinks) {
        const linkUrl = typeof link === 'string' ? link : (link.url || '');
        const linkText = typeof link === 'object' ? (link.text || '') : '';
        if (!linkUrl) continue;

        const linkHost = UrlUtils.extractHostname(linkUrl);
        const linkMain = UrlUtils.getMainDomain(linkHost);
        const linkLower = linkUrl.toLowerCase();
        const textLower = (linkText || '').toLowerCase();

        // 跨域外链
        if (linkMain !== mainDomain) {
          // 规则四B-a：外链绑在下载按钮上
          const isDownloadBtn = DOWNLOAD_BUTTON_KEYWORDS.some(kw => textLower.includes(kw.toLowerCase()));
          if (isDownloadBtn) {
            rule4Score += SCORE_RULE_4B_DOWNLOAD_BTN;
            rule4Details.push('下载按钮外链: ' + linkUrl);
          }

          // 规则四B-b：外链指向文件
          let isFileLink = false;
          for (const ext of FILE_EXTENSIONS) {
            if (linkLower.endsWith(ext)) { isFileLink = true; break; }
          }
          if (isFileLink) {
            rule4Score += SCORE_RULE_4B_FILE_LINK;
            // 附加：文件是压缩包
            let isArchiveFile = false;
            for (const ext of ARCHIVE_EXTENSIONS) {
              if (linkLower.endsWith(ext)) { isArchiveFile = true; break; }
            }
            if (isArchiveFile) {
              rule4Score += SCORE_RULE_4B_ARCHIVE_LINK;
            }
          }
        }
      }

      // 规则四A-③：重复链接检测
      const linkCounts = new Map();
      for (const link of downloadLinks) {
        const linkUrl = typeof link === 'string' ? link : (link.url || '');
        if (!linkUrl) continue;
        linkCounts.set(linkUrl, (linkCounts.get(linkUrl) || 0) + 1);
      }
      let maxDuplication = 0;
      let duplicateUrl = '';
      for (const [url, count] of linkCounts) {
        if (count > maxDuplication) {
          maxDuplication = count;
          duplicateUrl = url;
        }
      }
      if (maxDuplication >= DUPLICATE_LINK_THRESHOLD) {
        const dupScore = Math.min(
          Math.floor(4 * Math.log2(maxDuplication)),
          SCORE_RULE_4A_DUPLICATE_LINK
        );
        // 检查是否是下载链接
        const isDownloadLink = DOWNLOAD_LINK_KEYWORDS.some(kw => duplicateUrl.toLowerCase().includes(kw));
        const finalDupScore = isDownloadLink ? dupScore + SCORE_RULE_4A_DOWNLOAD_LINK_BONUS : dupScore;
        rule4Score += finalDupScore;
        rule4Details.push('重复链接: "' + duplicateUrl + '" 出现 ' + maxDuplication + ' 次');
      }

      if (rule4Score > 0) {
        totalScore += rule4Score;
        ruleResults.push({
          rule: '规则四-链接分析',
          score: rule4Score,
          detail: rule4Details.join('；')
        });
      }
    }

    // ==================== 规则五：代码工程化检测 ====================
    if (domNodeCount > 0 || externalResourceCount > 0) {
      let strongSignals = 0;
      let totalSignals = 0;
      const rule5Details = [];

      // 信号1：DOM 节点数过少
      if (domNodeCount > 0 && domNodeCount < AI_PAGE_THRESHOLDS.MIN_DOM_NODES) {
        strongSignals++;
        totalSignals++;
        rule5Details.push('DOM节点数过少(' + domNodeCount + ')');
      }

      // 信号2：外部资源数过少
      if (externalResourceCount > 0 && externalResourceCount < AI_PAGE_THRESHOLDS.MIN_EXTERNAL_RESOURCES) {
        strongSignals++;
        totalSignals++;
        rule5Details.push('外部资源数过少(' + externalResourceCount + ')');
      }

      // 信号3：未检测到主流框架
      if (frameworkMarkers.length === 0 && pageText.length > AI_PAGE_THRESHOLDS.MIN_TEXT_LENGTH) {
        totalSignals++;
        rule5Details.push('未检测到主流框架');
      }

      // 信号4：Emoji 密度检测
      if (pageText.length >= EMOJI_MIN_TEXT_LENGTH) {
        const promoMatchCount = PROMO_KEYWORDS.filter(kw =>
          pageText.toLowerCase().includes(kw.toLowerCase())
        ).length;

        if (promoMatchCount >= EMOJI_KEYWORD_MATCH_THRESHOLD) {
          let emojiCount = 0;
          try {
            const emojiRegex = new RegExp(EMOJI_REGEX_SOURCE, 'gu');
            const matches = pageText.match(emojiRegex);
            emojiCount = matches ? matches.length : 0;
          } catch (e) { /* regex not supported, skip */ }

          if (emojiCount > 0) {
            const textLength = pageText.length;
            const density = (emojiCount / textLength) * 1000; // per 1000 chars
            if (density >= EMOJI_DENSITY_THRESHOLD_LOW) {
              let emojiScore;
              if (density >= EMOJI_DENSITY_THRESHOLD_HIGH) {
                emojiScore = EMOJI_DENSITY_MAX_SCORE;
              } else {
                const ratio = (density - EMOJI_DENSITY_THRESHOLD_LOW) / (EMOJI_DENSITY_THRESHOLD_HIGH - EMOJI_DENSITY_THRESHOLD_LOW);
                emojiScore = Math.floor(EMOJI_DENSITY_MAX_SCORE * ratio);
              }
              totalScore += emojiScore;
              ruleResults.push({
                rule: '规则五-Emoji密度',
                score: emojiScore,
                detail: '推广关键词命中' + promoMatchCount + '个，Emoji密度' + density.toFixed(1) + '/千字符'
              });
            }
          }
        }
      }

      // 代码工程化评分
      if (strongSignals >= 2) {
        totalScore += SCORE_RULE_5;
        ruleResults.push({
          rule: '规则五-代码工程化(高度可疑)',
          score: SCORE_RULE_5,
          detail: rule5Details.join('；')
        });
      } else if (strongSignals >= 1 && totalSignals >= 2) {
        totalScore += SCORE_RULE_5_PARTIAL;
        ruleResults.push({
          rule: '规则五-代码工程化(中度可疑)',
          score: SCORE_RULE_5_PARTIAL,
          detail: rule5Details.join('；')
        });
      }
    }

    // ==================== 规则六：域名年龄（可疑加分） ====================
    if (whoisData && whoisData.creationDays >= 0) {
      const creationDays = whoisData.creationDays;
      // S 型衰减公式: floor(MAX / (1 + (x / (60 * b))^a))
      const ageScore = Math.floor(
        SCORE_DOMAIN_AGE_MAX / (1 + Math.pow(creationDays / (60 * DOMAIN_AGE_DECAY_B), DOMAIN_AGE_DECAY_A))
      );

      if (ageScore > 0) {
        totalScore += ageScore;
        ruleResults.push({
          rule: '规则六-域名年龄',
          score: ageScore,
          detail: '域名注册 ' + creationDays + ' 天，可疑加分 ' + ageScore
        });
      }

      // 域名年龄减分（老域名信任加分）
      if (totalScore >= DOMAIN_AGE_BONUS_SCORE_THRESHOLD && creationDays >= DOMAIN_AGE_BONUS_MIN_DAYS) {
        let bonus = 0;
        if (creationDays >= DOMAIN_AGE_BONUS_MAX_DAYS) {
          bonus = SCORE_DOMAIN_AGE_BONUS_MAX;
        } else {
          bonus = Math.floor(
            SCORE_DOMAIN_AGE_BONUS_MAX * (creationDays - DOMAIN_AGE_BONUS_MIN_DAYS) /
            (DOMAIN_AGE_BONUS_MAX_DAYS - DOMAIN_AGE_BONUS_MIN_DAYS)
          );
        }
        if (bonus > 0) {
          totalScore -= bonus;
          ruleResults.push({
            rule: '域名年龄减分',
            score: -bonus,
            detail: '域名注册 ' + creationDays + ' 天，老域名信任减分 ' + bonus
          });
        }
      }
    }

    // ==================== 规则七：跨域下载 ====================
    if (downloadUrl && pageUrl) {
      const downloadHost = UrlUtils.extractHostname(downloadUrl);
      const downloadMain = UrlUtils.getMainDomain(downloadHost);
      const pageMain = UrlUtils.getMainDomain(UrlUtils.extractHostname(pageUrl));

      if (downloadMain !== pageMain) {
        totalScore += SCORE_DOWNLOAD_CROSS_DOMAIN;
        ruleResults.push({
          rule: '规则七-跨域下载',
          score: SCORE_DOWNLOAD_CROSS_DOMAIN,
          detail: '下载域名(' + downloadMain + ')与页面域名(' + pageMain + ')不一致'
        });

        // 下载域名过新附加加分
        if (whoisData && whoisData.creationDays >= 0 &&
            whoisData.creationDays < DOWNLOAD_CREATION_DAYS_THRESHOLD) {
          totalScore += SCORE_DOWNLOAD_NEW_DOMAIN;
          ruleResults.push({
            rule: '规则七-新域名下载',
            score: SCORE_DOWNLOAD_NEW_DOMAIN,
            detail: '下载域名注册仅 ' + whoisData.creationDays + ' 天（< ' + DOWNLOAD_CREATION_DAYS_THRESHOLD + '天）'
          });
        }
      }
    }

    // ==================== 最终判定 ====================
    const isMalicious = totalScore >= SCORE_THRESHOLD;
    const riskLevel = totalScore >= SCORE_THRESHOLD ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;

    return {
      score: totalScore,
      isMalicious,
      ruleResults,
      spoofResult,
      correctUrl,
      riskLevel
    };
  }

  /**
   * 快速评估：仅检查域名仿冒 + 黑名单（用于导航拦截等低延迟场景）
   * @param {string} hostname
   * @param {Object} [options] - { isSiteBlacklisted, isDownloadBlacklisted }
   * @returns {{ score: number, isMalicious: boolean, spoofResult: Object|null, correctUrl: string|null }}
   */
  static quickEvaluate(hostname, options = {}) {
    const {
      isSiteBlacklisted = false,
      isDownloadBlacklisted = false
    } = options;

    let score = 0;
    let spoofResult = null;
    let correctUrl = null;

    if (typeof isFullyTrusted === 'function' && isFullyTrusted(hostname)) {
      return { score: 0, isMalicious: false, spoofResult: null, correctUrl: null };
    }

    if (isSiteBlacklisted) score += SCORE_SITE_BLACKLIST;
    if (isDownloadBlacklisted) score += SCORE_DOWNLOAD_BLACKLIST;

    const mainDomain = UrlUtils.getMainDomain(hostname);
    if (typeof DomainDatabase !== 'undefined' && !TrustedPlatforms.isTrusted(mainDomain)) {
      spoofResult = DomainDatabase.detectSpoof(hostname);
      if (spoofResult) {
        score += SCORE_RULE_1;
        correctUrl = spoofResult.correctUrl || null;
      }
    }

    return {
      score,
      isMalicious: score >= SCORE_THRESHOLD,
      spoofResult,
      correctUrl
    };
  }

  /**
   * 将评分结果转为风险等级描述
   * @param {number} score
   * @returns {{ level: string, label: string, color: string }}
   */
  static getRiskLevel(score) {
    if (score >= SCORE_THRESHOLD) {
      return { level: 'danger', label: '高危', color: '#ef5350' };
    } else if (score >= DOWNLOAD_CONFIRM_THRESHOLD) {
      return { level: 'warning', label: '可疑', color: '#f59e0b' };
    } else if (score >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
      return { level: 'caution', label: '注意', color: '#fbbf24' };
    } else {
      return { level: 'safe', label: '安全', color: '#10b981' };
    }
  }
}

// 暴露到全局作用域（importScripts 模式）
self.ScoringEngine = ScoringEngine;
