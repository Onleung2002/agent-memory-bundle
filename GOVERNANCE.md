# GOVERNANCE.md — MBCP（v0.1 草案）

## 原則

1. **中立性係結構唔係口號**：pass criteria 公開；suite 雙向可重跑；唔接受任何 vendor 資助去改 requirement；收到 vendor 錢 = 護城河自毀（hard rule）。
2. **唔自稱 v1.0／certified**：未 accreditation 前所有產出叫 **Conformance Report / Evidence Pack**，唔用「certificate / certified」字眼（EU/UK ISO/IEC 17021 體系含義；非法律意見，正式文件由律師確認）。
3. **版本紀律**：semver；spec 變更走 RFC 流程（issue → proposal → ≥1 co-maintainer approve → suite 同步更新 → release）。

## 維護者結構

- 現狀：單人 maintainer（Isaac Leung）— **已知的弱點**，會被當 vaporware 處理。
- G0 目標（2026-11-30）：≥2 位 external co-maintainer 口頭承諾。
- 提交 AAIF / CSA STAR Agentic 前提：有齊 co-maintainers（避免單人提交）。
- 無 vendor 保留席位；所有人（包括 maintainer）同一梯隊規則。

## 貢獻者梯隊

Contributor（issue/PR）→ Committer（≥5 merged PR）→ Co-maintainer（Isaac 邀請 + 現任 co-maintainer ≥1 同意）。

## 利益申報

任何 maintainer 若受聘/收費於 memory vendor / GRC platform，必須申報同迴避相關 requirement 表決。

## 版本與凍結

- spec v0.1 凍結條件：≥2 個獨立（非 project 自家）實作通過全部 suite scenarios。
- 凍結後 spec 變更需 major version bump + RFC + co-maintainer 多數同意。
