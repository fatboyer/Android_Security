<div align="center">

# Android 应用安全 · Android App Security

**Android / APP 应用漏洞挖掘综合指南**

**A Practical Guide to Android / App Vulnerability Discovery**

从测试方法论与工具链，到各类攻击面的检测、利用验证与修复加固

[![Platform](https://img.shields.io/badge/Platform-Android-3DDC84?logo=android&logoColor=white)](#)
[![Version](https://img.shields.io/badge/Version-V2.0-orange)](#)
[![Docs](https://img.shields.io/badge/Docs-Markdown%20%7C%20PDF%20%7C%20DOCX-blue)](#)
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)](#)

[中文](#中文) · [English](#english)

</div>

---

## 中文

> 这是一份可以按图索骥的 Android 应用安全测试手册：从环境搭建、信息收集到漏洞验证与修复，每一步都尽量给出命令、代码和检查清单。

### 项目简介

本仓库是一份面向 Android 应用安全测试与漏洞挖掘的实践型指南。与零散的学习笔记不同，文档以**攻击面**为主线，把每个测试项拆成可执行的流程：

**漏洞概述 → 危害与影响 → 原理分析 → 静态/动态检测 → 完整利用验证 → 修复与加固 → 检查要点**

最新 **V2.0** 版本包含 **18 个章节、175 项测试项、5 个附录**，既可作为渗透测试人员的现场手册，也可作为企业安全自查基线和研发修复参考。

### 内容特色

- **全流程覆盖**：从测试环境搭建、APK 获取与拆分合并、静态分析、动态分析、抓包与 Hook，到漏洞定级与报告编写。
- **可落地、可复现**：检测命令、Python/Frida 脚本、Payload、利用步骤与验证方法均尽量给出完整示例。
- **关注版本差异**：对已废弃 API、平台行为变更和历史漏洞加注时效标记，避免在新版本 Android 上误判。
- **清单化输出**：附录提供常用命令速查表、整体测试检查表、章节索引与测试项总览。
- **多格式交付**：Markdown 便于检索与版本管理，PDF 便于分发打印，DOCX 便于批注和二次编辑。

### 章节导航

| 章节 | 主题 |
| :-- | :-- |
| 第 1 章 | Android 安全测试方法论与工具链 |
| 第 2 章 | 安全配置类漏洞 |
| 第 3 章 | 信息泄露与本地数据存储安全 |
| 第 4 章 | Intent 安全（注入 / 重定向 / Intent Scheme） |
| 第 5 章 | Activity 组件漏洞 |
| 第 6 章 | Service 组件漏洞 |
| 第 7 章 | ContentProvider 组件漏洞 |
| 第 8 章 | Broadcast Receiver 组件漏洞 |
| 第 9 章 | WebView 漏洞 |
| 第 10 章 | 网络通信安全 |
| 第 11 章 | 密码学与密钥管理 |
| 第 12 章 | 权限与访问控制 |
| 第 13 章 | 应用经典漏洞 |
| 第 14 章 | 运行时安全与对抗技术 |
| 第 15 章 | 供应链、第三方 SDK 与依赖安全 |
| 第 16 章 | 其他常见与非常见测试项 |
| 第 17 章 | 二维码 / 扫一扫 / Deep Link 攻击面 |
| 第 18 章 | 静态审计补充清单（Checklist 类测试项） |

**附录**：A 常用命令与工具速查 · B 整体测试检查表 · C 参考链接与资料 · D 章节索引与测试项总览表 · E 参考链接（来源与延伸阅读）

### 仓库结构

```text
Android_Security/
├── Android应用安全/
│   ├── APP应用漏洞挖掘指南V2.0.md      # 最新版，推荐阅读
│   ├── APP应用漏洞挖掘指南V2.0.pdf     # 适合分发、打印
│   ├── APP应用漏洞挖掘指南V2.0.docx    # 适合批注、二次编辑
│   └── Android应用漏洞挖掘指南V1.0.md  # 早期版本，存档
├── Frida/                              # 预留目录（Frida 脚本与笔记，待补充）
└── README.md                           # 中英文双语说明（中文 / English）
```

### 文档入口

| 版本 | Markdown | PDF | Word |
| :-- | :-- | :-- | :-- |
| **V2.0（最新）** | [在线阅读](./Android应用安全/APP应用漏洞挖掘指南V2.0.md) | [下载 PDF](./Android应用安全/APP应用漏洞挖掘指南V2.0.pdf) | [下载 DOCX](./Android应用安全/APP应用漏洞挖掘指南V2.0.docx) |
| V1.0（存档） | [在线阅读](./Android应用安全/Android应用漏洞挖掘指南V1.0.md) | — | — |

### 快速开始

```bash
git clone https://github.com/fatboyer/Android_Security.git
cd Android_Security
```

推荐使用支持 Markdown 的编辑器阅读，例如 VS Code、Typora、Obsidian，也可以直接在 GitHub 上打开对应文件。需要分发或打印时使用 PDF；需要批注或二次编辑时使用 DOCX。

### 阅读建议

| 读者角色 | 建议阅读路径 |
| :-- | :-- |
| **新手入门** | 从第 1 章开始，按方法论完整走一遍靶场应用，再逐个章节深入 |
| **有经验的测试人员** | 通过[附录 D：测试项总览表](./Android应用安全/APP应用漏洞挖掘指南V2.0.md#附录-d-章节索引与测试项总览表)快速定位，直接查看目标测试项的「原理分析」与「完整利用步骤」 |
| **企业安全自查** | 使用每章末尾的「检查要点」和附录 B 的《整体测试检查表》逐项对照排查 |
| **研发 / 修复人员** | 重点关注各章节的「修复与加固」小节，其中给出了可落地的代码与配置 |

### 时效性标记

Android 平台迭代较快，文档中保留了部分历史测试项。请结合目标应用的 `minSdkVersion` / `targetSdkVersion` 和运行设备版本判断某项是否仍然适用：

| 标记 | 含义 | 处理方式 |
| :-- | :-- | :-- |
| ⚠️ **已废弃 API** | 相关 API 已被官方标记为 `@Deprecated`，高版本可能抛异常或行为变化 | 仅对老应用/老设备排查；新项目不作为修复项 |
| ⏳ **行为已变更** | 平台默认值或系统行为已改变 | 检测逻辑必须按 Android 版本区分 |
| 🧓 **历史漏洞（已修复）** | 仅在旧 Android 版本存在，官方已修复 | 仅作历史参考，重点关注低版本设备 |
| ✅ **仍有效** | 结论至今仍成立 | 正常测试，但仍需注意版本差异 |

> 提示：可使用 `aapt dump badging app.apk | grep sdkVersion` 获取目标版本信息，使用 `adb shell getprop ro.build.version.release` 获取设备系统版本。

### 版本说明

| 版本 | 状态 | 内容概述 |
| :-- | :-- | :-- |
| **V2.0** | 最新版本 | 18 章 + 5 个附录，覆盖 18 类攻击面与 175 项测试项；新增时效性标记、完整利用步骤和检查清单 |
| V1.0 | 存档版本 | 早期 9 章版本，保留供历史参考 |

### 免责声明

> **本指南仅供安全学习、授权渗透测试与企业安全自查使用。**
>
> 请勿将文档中的技术用于未经授权的目标。测试前务必取得目标所有者的书面授权，并遵守《中华人民共和国网络安全法》等相关法律法规及目标所在地区的法律规定。因滥用相关技术或工具造成的任何后果，由使用者自行承担，本仓库作者不承担任何责任。

### 参与贡献

欢迎通过 [Issue](https://github.com/fatboyer/Android_Security/issues) 或 Pull Request 参与共建：

- 发现内容错误、链接失效或测试项已过时，请提交 Issue。
- 新增漏洞案例、测试方法或工具脚本，欢迎提交 PR。
- 提交问题时请尽量附上 Android 版本、设备型号、目标应用版本和复现步骤，便于核对。

如果这个项目对你有帮助，欢迎点一个 **Star ⭐**。

### 许可说明

本仓库暂未声明开源许可证（No license declared）。文档内容仅供安全学习、授权测试与企业自查使用；未经作者许可，请勿用于商业转载或二次分发。如需授权，请通过 Issue 联系。

<div align="right"><a href="#english">English →</a></div>

---

## English

> A step-by-step field manual for Android application security testing: from lab setup and information gathering to vulnerability validation and remediation, with commands, code, and checklists wherever possible.
>
> **Note:** The guide itself is written in Simplified Chinese. This section provides an English overview of the repository.

### Overview

This repository contains a hands-on guide to Android application security testing and vulnerability discovery. Instead of scattered notes, the guide is organized around **attack surfaces** and turns each test item into an actionable workflow:

**Overview → Impact → Root Cause → Static / Dynamic Detection → Exploitation Validation → Remediation → Review Checklist**

The latest **V2.0** release includes **18 chapters, 175 test items, and 5 appendices**. It can be used as a field manual for penetration testers, a self-assessment baseline for enterprise security teams, and a remediation reference for developers.

### Highlights

- **End-to-end coverage**: lab setup, APK acquisition and split-APK merging, static analysis, dynamic analysis, traffic interception, hooking, vulnerability rating, and reporting.
- **Practical and reproducible**: detection commands, Python/Frida scripts, payloads, exploitation steps, and validation methods with complete examples.
- **Version-aware**: deprecated APIs, platform behavior changes, and historical vulnerabilities are explicitly marked, helping avoid false positives on modern Android versions.
- **Checklist-driven**: appendices include a command cheat sheet, a complete testing checklist, a chapter index, and a test-item overview.
- **Multiple formats**: Markdown for searching and version control, PDF for sharing and printing, DOCX for review comments and editing.

### Chapters

| Chapter | Topic |
| :-- | :-- |
| 1 | Android Security Testing Methodology and Toolchain |
| 2 | Security Configuration Vulnerabilities |
| 3 | Information Leakage and Local Data Storage |
| 4 | Intent Security (Injection / Redirection / Intent Scheme) |
| 5 | Activity Vulnerabilities |
| 6 | Service Vulnerabilities |
| 7 | ContentProvider Vulnerabilities |
| 8 | Broadcast Receiver Vulnerabilities |
| 9 | WebView Vulnerabilities |
| 10 | Network Communication Security |
| 11 | Cryptography and Key Management |
| 12 | Permissions and Access Control |
| 13 | Classic Application Vulnerabilities |
| 14 | Runtime Security and Anti-Analysis Techniques |
| 15 | Supply Chain, Third-Party SDKs, and Dependencies |
| 16 | Other Common and Uncommon Test Cases |
| 17 | QR Code / Scanner / Deep Link Attack Surface |
| 18 | Static Audit Checklist Items |

**Appendices**: A Command and Tool Cheat Sheet · B Complete Testing Checklist · C References · D Chapter Index and Test-Item Overview · E References (Sources and Further Reading)

### Repository Layout

```text
Android_Security/
├── Android应用安全/
│   ├── APP应用漏洞挖掘指南V2.0.md      # Latest version (recommended)
│   ├── APP应用漏洞挖掘指南V2.0.pdf     # For sharing and printing
│   ├── APP应用漏洞挖掘指南V2.0.docx    # For review comments and editing
│   └── Android应用漏洞挖掘指南V1.0.md  # Legacy version (archived)
├── Frida/                              # Reserved for Frida scripts and notes (to be added)
└── README.md                           # Bilingual README (Chinese / English)
```

### Documentation

| Version | Markdown | PDF | Word |
| :-- | :-- | :-- | :-- |
| **V2.0 (latest)** | [Read online](./Android应用安全/APP应用漏洞挖掘指南V2.0.md) | [Download PDF](./Android应用安全/APP应用漏洞挖掘指南V2.0.pdf) | [Download DOCX](./Android应用安全/APP应用漏洞挖掘指南V2.0.docx) |
| V1.0 (archived) | [Read online](./Android应用安全/Android应用漏洞挖掘指南V1.0.md) | — | — |

### Getting Started

```bash
git clone https://github.com/fatboyer/Android_Security.git
cd Android_Security
```

Open the Markdown files in any Markdown-capable editor such as VS Code, Typora, or Obsidian, or read them directly on GitHub. Use the PDF for distribution and printing, and the DOCX for review comments or further editing.

### Suggested Reading Paths

| Reader | Recommended path |
| :-- | :-- |
| **Beginners** | Start with Chapter 1, walk through a practice app following the methodology, then study individual chapters |
| **Experienced testers** | Use [Appendix D: Test-Item Overview](./Android应用安全/APP应用漏洞挖掘指南V2.0.md#附录-d-章节索引与测试项总览表) to locate a topic, then read its "Root Cause Analysis" and "Full Exploitation Steps" |
| **Enterprise self-assessment** | Use the "Review Checklist" at the end of each chapter and the Complete Testing Checklist in Appendix B |
| **Developers / remediators** | Focus on each chapter's "Remediation and Hardening" sections for implementable code and configuration |

### Version Markers

Android evolves quickly, and the guide intentionally retains some historical test items. Use the target app's `minSdkVersion` / `targetSdkVersion` and the device OS version to decide whether an item still applies:

| Marker | Meaning | How to handle |
| :-- | :-- | :-- |
| ⚠️ **Deprecated API** | The API is officially marked `@Deprecated`; behavior may change or throw on newer versions | Check legacy apps/devices only; not a remediation item for new projects |
| ⏳ **Behavior changed** | Platform defaults or system behavior have changed | Detection logic must be version-specific |
| 🧓 **Historical vulnerability (fixed)** | Exists only on older Android versions and has been fixed upstream | Historical reference only; focus on older devices |
| ✅ **Still valid** | The finding still holds | Test normally, while accounting for version differences |

> Tip: get the target SDK with `aapt dump badging app.apk | grep sdkVersion`, and the device OS version with `adb shell getprop ro.build.version.release`.

### Version History

| Version | Status | Summary |
| :-- | :-- | :-- |
| **V2.0** | Latest | 18 chapters + 5 appendices, covering 18 attack-surface categories and 175 test items; adds version markers, full exploitation steps, and review checklists |
| V1.0 | Archived | Early 9-chapter edition, kept for historical reference |

### Disclaimer

> **This guide is intended for security education, authorized penetration testing, and enterprise security self-assessment only.**
>
> Do not use the techniques in this repository against targets without authorization. Always obtain written permission from the target owner before testing, and comply with applicable laws and regulations, including the Cybersecurity Law of the People's Republic of China and the laws of the target's jurisdiction. Any consequences arising from misuse of the techniques or tools are the sole responsibility of the user; the author of this repository assumes no liability.

### Contributing

Contributions are welcome via [Issues](https://github.com/fatboyer/Android_Security/issues) or Pull Requests:

- Found an error, a broken link, or an outdated test item? Please open an Issue.
- Have a new vulnerability case, testing method, or tool script? Pull Requests are welcome.
- When reporting a problem, please include the Android version, device model, target app version, and reproduction steps where possible.

If this project helps you, please consider giving it a **Star ⭐**.

### License

No open-source license has been declared for this repository. The documentation is provided for security education, authorized testing, and enterprise self-assessment. Please do not use it for commercial reproduction or redistribution without the author's permission. For licensing requests, please open an Issue.

<div align="right"><a href="#中文">← 中文</a></div>
