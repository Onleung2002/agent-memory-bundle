# RFC: A-21 dropped-ids 提早落地（v0.2 實作第一項）

Status: DRAFT — 待 Isaac 裁決（Q1–Q5）
Date: 2026-11-19
Origin: 2026-11-16 James He（W3C CG active，UC-8 fixtures 作者）外部 conformance 審查捉到本 repo 對外信嘅不實陳述：信寫「digest-failed load reports dropped-ids rather than a clean pass」，但 MBCP v0.1 嘅 digest drop 係靜默（SPEC §1.6 + A-21 明文排程 v0.2）。Isaac 裁決 2026-11-16：A-21 提早，做 v0.2 實作第一項，MBRK030 核心 code round。

## 1. 現狀基線（對 source 核實，唔係憑記憶）

- `mbcp/bundle.py:539` `def load(bundles):` 回傳 plain `list[record dict]`。digest-failed record 喺 `if not _digest_ok(record): continue` 處靜默消失。
- 其他 drop 位（同一函數）：non-string body（A-07 load-path drop）、`on_budget_exceed:"skip"` 超預算、`truncate_last` 冇剩餘預算。
- Tombstoned / `lifecycle:"deleted"` id 係預期過濾（SPEC §1.2），唔係 integrity failure。
- 調用點（全 repo grep 實核）：
  - `tools/run_scenarios.py` `_check_load`（兩處）— 直接 `load(...)` 當 list 迭代。
  - `mbcp/bundle.py:667` `load_bytes()` — `canonical_bytes(load(bundles))`，依賴 list 可 canonical 化。
  - `deploy/hermes_dispatcher.py` — **冇調用 `load()`**（只用 `normalize_id` / `build_bundle` / `L1DeletionService` / `make_record`）。
  - `importers/_common.py` — 用 `import_bundle` / `build_bundle`，唔用 `load()`。
- 對外 artifact 現況：對外信已寫 dropped-ids 行為但 code 冇——呢個係 James He 提出嘅實質 gap，唔係措辭問題。

## 2. 設計問題逐項

### Q1 回傳形態（breaking change 必然發生，揀形態）

改 signature 係 breaking change（A-04 verbatim `load(bundles) -> list[record dict]`）。三個選項：

| 選項 | 形態 | Backward-compat | 跨實作契約清晰度 |
|---|---|---|---|
| (a) | `list` 子類 + `.dropped_ids` 屬性 | 現有 list 迭代代碼零改動 | 差——外部 impl 會被誘導抄 list-subclass hack；`type(res)` 判斷產生隱蔽行為差 |
| (b) | `dataclass LoadResult(records: list, dropped_ids: list)` | 所有 list 用法 break，要改 scenario runner + load_bytes | 清晰——兩個 named field，conformance vector 可逐字寫 |
| (c) | plain dict `{"records": [...], "dropped_ids": [...]}` | 同上 break | 同 (b) 清晰，但同 `import_bundle` 回傳 dict 風格一致 |

**建議：(b) dataclass**。理由：呢個係跨實作契約（A-04），外部 impl 第一日就要照抄清晰形態；list-subclass 向下兼容係假兼容——契約函數嘅兼容性靠 version boundary 明文管理，唔靠 type hack。實際要改嘅調用點只有 3 處（scenario runner ×2、`load_bytes` 一行），成本極低。

Migration 語意：SPEC §3a 改寫 `load(bundles) -> LoadResult(records, dropped_ids)`；`CHANGES.md` 明文記版本邊界「v0.1: plain list → v0.2: LoadResult」。

### Q2 dropped-ids 嘅範圍（邊啲 drop 算）

Brief 已釘死兩端：digest-failed 必須入；tombstoned / lifecycle-filtered 必須唔入。中間有三個灰色 drop 位要裁決：

| Drop 位 | 建議分類 | 理由 |
|---|---|---|
| digest-failed record（含 digest-failed 嘅 `lifecycle:"deleted"` copy——佢唔產生訊號兼被 drop） | **入 dropped-ids** | UC-8 要捉嘅正正係呢類 |
| non-string body drop（A-07 load-path） | **入 dropped-ids**（reason 区分） | 同樣係「record 無法被信任地載入」嘅 integrity/validity 失敗，唔係政策過濾 |
| budget skip / truncate_last 冇剩餘 | **唔入**（見 Q3） | 政策性預期行為，同 tombstone 同類——load_policy 係 record 自己宣告嘅 |

### Q3 通道粒度（政期過濾要不要第二條通道）

選項：(i) 淨係一條 `dropped_ids`（integrity/validity 失敗），政策過濾（tombstone/lifecycle/budget）唔報告；(ii) 加第二條 `filtered_ids` 全報。

**建議 (i)**。理由：UC-8 關心嘅係「integrity 失敗被靜默吞」——呢條窿在於 digest-failed 同 pass 無法區分；政策過濾由 load_policy / tombstone journal 已有可觀測語意，加第二條通道會令 `dropped_ids` 語意模糊化，而 conformance vector 要為每條通道寫 mutation。確有需要的話 v0.3 加，唔好今次埋。

### Q4 dropped-ids 內容形態

- **建議：`sorted()` + dedup + NFC-normalized id（`normalize_id`）嘅 plain `list[str]`**。
- 重複 id 嘅多份 digest-failed copy → 一個 id 出現一次（dedup）。同 id 既有 winner（merge 勝出）又有 digest-failed copy → id 兩邊都出現（records 有佢、dropped_ids 都有佢）——呢個唔係矛盾，係「呢個 id 有一份 copy 被拒」，scenario 要有 case 釘死。
- richer 形態（`[{id, bundle_id, reason}]`）唔入契約——v0.2 先釘死 id list，richer 係 impl 自由擴展（同 A-04 build-path 函數唔入契約同一哲學）。
- Determinism：跟 `load()` 主輸出同一標準——同一輸入 byte-identical `dropped_ids`，排序 key = normalized id（併字序）。

### Q5 SPEC 版本邊界

`dropped-ids` 通道落咗，SPEC 對外係咪即刻叫 v0.2？兩個層面：

- **Bundle schema `mbcp_version` 唔受影響**：bundle 格式零改動（A-23 tolerant reader 本來就唔 check 版本字串），無 schema bump。
- **問題淨係 API 契約版本**。建議：SPEC 頭部 version 保持 0.1、加一行 amendment marker「v0.2 API amendment 1: dropped-ids channel (2026-11)」，`CHANGES.md` 記錄——避免 registry / G1 conformance 材料全部要 re-baseline（bundle 格式冇變，將 spec 版本推上 0.2 會令外部 impl 對住一條其實冇變嘅 bundle contract 諗「v0.2」）。正式 v0.2（真 spec 版本）等 G1 前嘅 spec consolidation 一齊定。
- James He 回信語意：寫「v0.1 silently discarded digest-failed records; this was a v0.1 conformance defect, fixed by the v0.2 dropped-ids amendment」——誠實承認 v0.1 有呢個缺陷，唔好話「一直都有」。

## 3. 誠實條款（brief 逐字落）

- SPEC / docstring 所有描述呢個行為嘅句子用「**dropped-ids are reported, not silently discarded**」語意，唔准 overclaim（禁 `certificate/certification/guarantee`，pin 照 M4 詞形獨立 needle）。
- 能力邊界照寫：dropped-ids 係**報告**通道，唔係攔截——record 仍然係 drop 唔係 load，通道令 drop 可觀測；佢唔提供「重建 / quarantine / retry」語意（嗰啲係 H3-H5 / A-3 availability 項）。

## 4. Scope

1. `mbcp/`：`LoadResult` dataclass + `load()` 填 `dropped_ids`（digest-failed + non-string body 兩類）；`load_bytes()` 適應。
2. SPEC.md：§1.6 靜默句改寫、§3a A-04 契約句改寫、amendment marker；`docs/SPEC_AMBIGUITIES_V0P1.md` A-21 條目改「已落地（v0.2 提早，2026-11-16，來源：外部 conformance 審查 James He）」。
3. `tools/run_scenarios.py`：`_check_load` 解包 `LoadResult`；新 scenario「digest-failed record → dropped-ids 有 id、pass 冇靜默吞」＋「同 id winner+digest-failed copy 並存」＋「tombstoned 唔入 dropped_ids」case。現有 331u + 24sc 全重跑綠，guard 對 origin/main 計 delta。
4. `CHANGES.md` 版本邊界記錄。
5. `deploy/hermes_dispatcher.py`：worker 實核冇 `load()` 調用（controller 已 grep 證實），確認 no-op 即可，唔准順手 refactor。

## 5. 流程

照鐵律：本 RFC → Isaac 批 → controller 落 SPEC/docs 前置 commit（如 Isaac 裁決需要）→ worker = Kimi core branch round → controller 核實自報 → verifier = GLM（唔同族）。Verifier adversarial 硬要求（Isaac 已列）：

- (a) 真跑含 digest-failed record 嘅 bundle：`dropped_ids` 有該 id、pass 冇靜默吞；
- (b) mutation：攞走 dropped-ids 通道 → suite 必 fail；
- (c) tombstoned record 不出現喺 `dropped_ids`；
- (d) mutation：`dropped_ids` 排序 key 拆走 → determinism test fail（order-dependent）。

## 6. 時間

唔阻塞 G0（11-30），但 James He 回信等緊——RFC 即批即派，目標 worker+verify 一週內收口。
