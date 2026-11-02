<div align="center">

# Android App Security

**A Practical Guide to Android / App Vulnerability Discovery**

From methodology and toolchain to attack-surface testing, exploitation validation, and remediation

[![Platform](https://img.shields.io/badge/Platform-Android-3DDC84?logo=android&logoColor=white)](#)
[![Version](https://img.shields.io/badge/Version-V2.0-orange)](#)
[![Docs](https://img.shields.io/badge/Docs-Markdown%20%7C%20PDF%20%7C%20DOCX-blue)](#)
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)](#)

[简体中文](README.md) · **English**

</div>

---

> A step-by-step field manual for Android application security testing: from lab setup and information gathering to vulnerability validation and remediation, with commands, code, and checklists wherever possible.
>
> **Note:** The guide itself is written in Simplified Chinese. This README provides an English overview of the repository.

## Overview

This repository contains a hands-on guide to Android application security testing and vulnerability discovery. Instead of scattered notes, the guide is organized around **attack surfaces** and turns each test item into an actionable workflow:

**Overview → Impact → Root Cause → Static / Dynamic Detection → Exploitation Validation → Remediation → Review Checklist**

The latest **V2.0** release includes **18 chapters, 175 test items, and 5 appendices**. It can be used as a field manual for penetration testers, a self-assessment baseline for enterprise security teams, and a remediation reference for developers.

## Highlights

- **End-to-end coverage**: lab setup, APK acquisition and split-APK merging, static analysis, dynamic analysis, traffic interception, hooking, vulnerability rating, and reporting.
- **Practical and reproducible**: detection commands, Python/Frida scripts, payloads, exploitation steps, and validation methods with complete examples.
- **Version-aware**: deprecated APIs, platform behavior changes, and historical vulnerabilities are explicitly marked, helping avoid false positives on modern Android versions.
- **Checklist-driven**: appendices include a command cheat sheet, a complete testing checklist, a chapter index, and a test-item overview.
- **Multiple formats**: Markdown for searching and version control, PDF for sharing and printing, DOCX for review comments and editing.

## Chapters

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

## Repository Layout

```text
Android_Security/
├── Android应用安全/
│   ├── APP应用漏洞挖掘指南V2.0.md      # Latest version (recommended)
│   ├── APP应用漏洞挖掘指南V2.0.pdf     # For sharing and printing
│   ├── APP应用漏洞挖掘指南V2.0.docx    # For review comments and editing
│   └── Android应用漏洞挖掘指南V1.0.md  # Legacy version (archived)
├── Frida/                              # Reserved for Frida scripts and notes (to be added)
├── README.md                           # Chinese README
└── README_EN.md                        # English README (this file)
```

## Documentation

| Version | Markdown | PDF | Word |
| :-- | :-- | :-- | :-- |
| **V2.0 (latest)** | [Read online](./Android应用安全/APP应用漏洞挖掘指南V2.0.md) | [Download PDF](./Android应用安全/APP应用漏洞挖掘指南V2.0.pdf) | [Download DOCX](./Android应用安全/APP应用漏洞挖掘指南V2.0.docx) |
| V1.0 (archived) | [Read online](./Android应用安全/Android应用漏洞挖掘指南V1.0.md) | — | — |

## Getting Started

```bash
git clone https://github.com/fatboyer/Android_Security.git
cd Android_Security
```

Open the Markdown files in any Markdown-capable editor such as VS Code, Typora, or Obsidian, or read them directly on GitHub. Use the PDF for distribution and printing, and the DOCX for review comments or further editing.

## Suggested Reading Paths

| Reader | Recommended path |
| :-- | :-- |
| **Beginners** | Start with Chapter 1, walk through a practice app following the methodology, then study individual chapters |
| **Experienced testers** | Use [Appendix D: Test-Item Overview](./Android应用安全/APP应用漏洞挖掘指南V2.0.md#附录-d-章节索引与测试项总览表) to locate a topic, then read its "Root Cause Analysis" and "Full Exploitation Steps" |
| **Enterprise self-assessment** | Use the "Review Checklist" at the end of each chapter and the Complete Testing Checklist in Appendix B |
| **Developers / remediators** | Focus on each chapter's "Remediation and Hardening" sections for implementable code and configuration |

## Version Markers

Android evolves quickly, and the guide intentionally retains some historical test items. Use the target app's `minSdkVersion` / `targetSdkVersion` and the device OS version to decide whether an item still applies:

| Marker | Meaning | How to handle |
| :-- | :-- | :-- |
| ⚠️ **Deprecated API** | The API is officially marked `@Deprecated`; behavior may change or throw on newer versions | Check legacy apps/devices only; not a remediation item for new projects |
| ⏳ **Behavior changed** | Platform defaults or system behavior have changed | Detection logic must be version-specific |
| 🧓 **Historical vulnerability (fixed)** | Exists only on older Android versions and has been fixed upstream | Historical reference only; focus on older devices |
| ✅ **Still valid** | The finding still holds | Test normally, while accounting for version differences |

> Tip: get the target SDK with `aapt dump badging app.apk | grep sdkVersion`, and the device OS version with `adb shell getprop ro.build.version.release`.

## Version History

| Version | Status | Summary |
| :-- | :-- | :-- |
| **V2.0** | Latest | 18 chapters + 5 appendices, covering 18 attack-surface categories and 175 test items; adds version markers, full exploitation steps, and review checklists |
| V1.0 | Archived | Early 9-chapter edition, kept for historical reference |

## Disclaimer

> **This guide is intended for security education, authorized penetration testing, and enterprise security self-assessment only.**
>
> Do not use the techniques in this repository against targets without authorization. Always obtain written permission from the target owner before testing, and comply with applicable laws and regulations, including the Cybersecurity Law of the People's Republic of China and the laws of the target's jurisdiction. Any consequences arising from misuse of the techniques or tools are the sole responsibility of the user; the author of this repository assumes no liability.

## Contributing

Contributions are welcome via [Issues](https://github.com/fatboyer/Android_Security/issues) or Pull Requests:

- Found an error, a broken link, or an outdated test item? Please open an Issue.
- Have a new vulnerability case, testing method, or tool script? Pull Requests are welcome.
- When reporting a problem, please include the Android version, device model, target app version, and reproduction steps where possible.

If this project helps you, please consider giving it a **Star ⭐**.

## License

No open-source license has been declared for this repository. The documentation is provided for security education, authorized testing, and enterprise self-assessment. Please do not use it for commercial reproduction or redistribution without the author's permission. For licensing requests, please open an Issue.
