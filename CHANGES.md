# CHANGES

## 2026-11-19 — v0.2 API amendment 1: dropped-ids channel

**版本邊界（migration 語意）**：`mbcp.load(bundles)` 回傳形態由 plain `list[record dict]`（v0.1）改為 `LoadResult(records, dropped_ids)` dataclass（v0.2 API amendment 1，2026-11）。Bundle schema 零改動；SPEC 整體版本仍為 v0.1，正式 v0.2 等 spec consolidation（G1 前）。

**遷移**：`load()` 嘅 list 迭代用法改為 `load(...).records`；digest-failed / non-string body 而被 drop 嘅 record id 而家列入 `.dropped_ids`（sorted + dedup + NFC-normalized）——dropped-ids are reported, not silently discarded。政策過濾（tombstone / lifecycle 刪除 / budget skip / truncate_last 冇剩餘）唔入 dropped_ids。

**來源**：2026-11-16 外部 conformance 審查（James He，W3C CG active，UC-8 fixtures 作者）捉到 v0.1 digest-drop 靜默同對外陳述不符；Isaac 裁決 2026-11-16 提早落地、2026-11-19 批准 RFC（docs/RFC_a21_dropped_ids.md，Q1–Q5）。v0.1 呢個行為釐定為 conformance defect。
