# RFC: L2 Propagation · Receipt Re-issuance · L4 正式化

狀態：**DRAFT — 待 Isaac 批准，批准前零新 code**
作者：controller（memory_bundle profile）；依據：SPEC §1.2、docs/BACKLOG.md（M1 carried ×2 + M2 round 2/3 advisories）、docs/MILESTONE_M2.md §6
設計簇理由：L2（跨 bundle propagation）、re-issuance（刪除「醫返好」路徑）、L4（回執正式化）共用同一套 tombstone journal / evidence / receipt 基建；分開做會做兩次（M2 收尾時 Isaac 已點名）。M1 carried 兩條同 load path 連住，一併處理。

---

## 0. 現狀基線（M2 終態）

- L1 完成：tombstone-first journal（fsync）、truthful receipts（`evidence/` + `recovery.jsonl` 雙綁定）、crash recovery、idempotent delete、`verify_receipt`
- 已知限制（SPEC §1.2.1）：L1 receipt immutable；recover 後無 re-issuance path；無跨 bundle propagation
- 收據只對「無 service root 寫入權」嘅第三方 tamper-evident（無簽名）

## 1. L2 — 跨 bundle propagation

**目標語意**：刪除一個 id 時，所有「引用」該 id 嘅 bundle 都收到 tombstone，並且 load path 證明冇任何 bundle 可以復活。

### 1.1 核心設計問題（需要 Isaac 拍板）

- **Q1「引用」嘅定義**：M2 採用 id-wide 語意（service root 內同 id 全部剷）。L2 嘅範圍係 (a) 同一 service root 內多 bundle（而家已做咗大半，M2 fix round 1 起），定 (b) 跨 service root / 跨副本 propagation（真正嘅 L2）？建議：M3 做 (b) 嘅最小形式——export 一份「propagation pack」（tombstone 集合），俾另一個 service root `import`；實現方式重用 `import_bundle` 既有 tombstone-first 語意，唔引入新 protocol。
- **Q2 receipt 嘅 propagation 欄位**：`propagation.propagated_to` 而家係空 array。L2 receipt 應該列實際收到 tombstone 嘅 bundle/root 清單。定 receipt 仍 immutable、propagation 證明另開 artifact？建議：L2 證明 = 獨立 `propagation-<target>.json` artifact（列每個受影響 root/bundle + 對方 journal 嘅 tombstone digest），唔改 L1 receipt schema（向後兼容）。
- **Q3 失敗語意**：某個 bundle 收唔到 propagation（offline / 異體）時——block 定 best-effort + 記 pending？建議：best-effort + `propagation.jsonl` journal 記 pending 項，同 tombstone journal 同構（fail-closed 哲學延續：未確認嘅 propagation 唔算已傳播）。

### 1.2 可測 invariant（全部 machine-checkable）

1. propagate 之後，任一 bundle 嘅 stale copy 經 `load()` 都唔可以復活該 id
2. propagation pack import 係冪等：重複 import 無新 journal 行
3. propagation pack 係 deterministic bytes（canonical form）
4. 未確認嘅 propagation 唔會令 `verify_receipt` 變 ok

## 2. Receipt Re-issuance / Supersession

**現狀（semantics (i)）**：receipt immutable；recover() 移除未報告 digest 後，該 target 永遠無 receipt 可以 ok:True，`delete()` retry 永遠 `DeletionIncompleteError`。Fail-closed 但無「醫返好」路徑。

### 2.1 建議語意：supersession chain（唔改舊 receipt）

- 新 receipt `supersedes: <old_receipt_id>`；新 receipt 嘅 `removed_records` = delete-time evidence ∪ recovery removals（per target）
- `verify_receipt` 精化：一條 chain 入面**最新** receipt 對「evidence ∪ recovery」做 equality check；舊 receipt 保持 immutable 且繼續 fail（佢確實 under-report，歷史唔改寫）
- `ok:True` 語意升級為：「呢條 chain 嘅最新 receipt accounting 埋呢個 target 已知嘅全部 removal」——第三方驗證時只需要最新 receipt + 佢 supersedes 嘅 id 清單
- schema 影響：`deletion-receipt.v0.json` 加 optional `supersedes`（minLength 1）；v0 → 需要考慮係咪 bump v1（見 §5 RFC 紀律）

### 2.2 要拍板

- **Q4**：supersession 係咪接受「新 receipt 取代舊 receipt 做驗證入口」？替代方案係完全唔做 re-issuance、靠 `recovery.jsonl` 對帳（現狀 fail-closed 但第三方難用）。建議：做 supersession，因為 L4 嘅目標係「可交俾第三者驗證」，而而家嘅 fail-closed 狀態令 recovery 後嘅 target 無任何可出示 artifact。
- **Q5**：`delete()` retry 喺 under-report 狀態下而家 raise `DeletionIncompleteError`——supersession 落地後應該自動 re-issue 而唔係 raise？建議：係（fail-closed 只留俾真異常）。

## 3. L4 — 回執正式化

L4 = 「可交俾第三者驗證刪除已發生」。而家 L1 receipt 已經有 90% 形狀，缺嘅係**完整性承諾**同**信任模型**。

### 3.1 缺口

1. **簽名/錨定**：service root 入面檔案可被 root 權限改寫（M2 advisory #4）。L4 最小方案：receipt + journal snapshot 嘅 detached signature（純 stdlib 無 crypto——需要決定依賴策略，見 Q6）
2. **時鐘信任**：`deleted_at`/`issued_at` 係本地時鐘；第三方驗證只能信 monotonic journal 順序，唔能信絕對時間。建議 receipt 加 `journal_pos`（行號+digest chain），令驗證者可以重放 journal 對帳
3. **無 L3 證明**：`derived_artifacts_verified: false` 永遠係 false 直至 L3 實現——L4 v1 明文 scope 排除 L3，唔冒認

### 3.2 要拍板

- **Q6 crypto 依賴**：SPEC 而家係純 stdlib（suite 可雙向重跑係賣點）。簽名需要 hashlib 之外嘅嘢（ed25519 等）。選項：(a) 純 stdlib `hmac` + 共享密鑰（弱，但零依賴）；(b) 引入最小依賴（如 `cryptography`），SPEC §0 註明 optional dependency；(c) L4 暫緩，先做 L2 + supersession，L4 留 M4。**建議 (c)**：L2/supersession 唔使 crypto，先把第三方可驗證性做到「無簽名但 digest-chain 完整」，簽名係 M4 獨立決定。
- **Q7 L4 receipt 係咪新 schema**：若 M3 唔做 L4，呢條留空。

## 4. M1 carried 兩條（同 load path 連住，M3 一併收）

1. **lifecycle=deleted 冇 id-wide 語意**（BACKLOG M1 #1）：建議收緊為——load path 將 `lifecycle:"deleted"` 記錄視為**該 id 嘅 id-wide 刪除訊號**（同 tombstone 同等對待），理由：而家「同 id 另一 bundle active 就復活」係復活路徑；代價係 archived→active 修復流程要用唔同 id 或明文 lifecycle 權重。需要 SPEC 修訂（RFC 流程）。
2. **manifest 缺 records/tombstones 容忍成 []**（BACKLOG M1 #2）：建議分兩層——build path（`build_bundle`/`validate_*`）要求兩個欄位必須存在（`additionalProperties`/`required` 收緊）；load path 保持 tolerant reader（SPEC §1.5 明文）。注意 M2 deletion service 內部有多處 `manifest.get("records", [])`，收緊 schema 後要同步改寫，係 round 內最大嘅回歸風險點。

## 5. 版本紀律（GOVERNANCE §3）

以上任何語意變更（lifecycle id-wide、supersession、L2 artifact）都係 SPEC 修訂：走 issue → proposal → ≥1 co-maintainer approve → suite 同步 → release。v0.1 尚未凍結，无 major bump 壓力，但 suite scenarios 必須同步加 case（DEL-05+ / INT-03+），唔准只改 code 唔改 suite。

## 6. 第二獨立實作評估（策略主線）

GOVERNANCE 凍結條件：≥2 個獨立（非 project 自家）實作通過全部 suite scenarios。這係 badge 路線 critical path，比 L2/L4 功能更早做越好。

| 候選 | 契合度評估 |
|---|---|
| **UMP / agent memory 標準實作（開源）** | 最高：MBCP record shape 繼承 UMP；若 UMP 生態有 reference impl，加 MBCP profile 層即可跑我哋 suite（runner 只用 public API：`mbcp.load` / `import_bundle` / `canonical_bytes`——已係雙向重跑設計）。風險：UMP 0.1+ 未必有現成 Python impl |
| **自寫第二實作（唔同語言，e.g. Rust/Go）** | 可控但工時大；好處係同時 stress-test suite 嘅語意明確性（雙模型 fail-set 重疊度指標，SPEC §3） |
| **吸引外部 contributor（GitHub public 後）** | 長線；前提係 repo public + co-maintainer 到位（GOVERNANCE G0 目標 2026-11-30） |

**建議**：M3 design doc 批准後、L2 實作前，先花 2-3 日做「第二實作 spike」：用純 stdlib 喺另一語言/另一 codebase 寫 P0 層（canonical + load_policy + tombstone-first），對住 suite scenarios 跑。呢個 spike 嘅價值係**捉 SPEC 嘅歧義**——歧義喺第二實作時爆，好過喺 L2 複雜度疊上去之後先爆。

## 7. 建議 M3 排序（若 RFC 獲批）

1. 第二實作 P0 spike（捉 SPEC 歧義，先決一切）
2. M1 carried #2（schema 收緊 build path）＋ #1（lifecycle id-wide）——細，但動 load path，早做
3. L2 minimal（propagation pack + propagation.jsonl + receipt propagation artifact）
4. Supersession（Q4/Q5 拍板後）
5. L4（Q6 拍板後，可能 M4）

## 8. Open questions 匯總（等 Isaac 批時逐條裁決）

| # | 問題 | 建議 |
|---|---|---|
| Q1 | L2 範圍：root 內定跨 root | 跨 root minimal（propagation pack） |
| Q2 | propagation 證明載體 | 獨立 artifact，唔改 L1 receipt schema |
| Q3 | propagation 失敗語意 | best-effort + pending journal |
| Q4 | supersession 做唔做 | 做 |
| Q5 | delete() retry 喺 under-report 下自動 re-issue | 係 |
| Q6 | L4 crypto 依賴 | M3 唔做 L4；簽名留 M4 |
| Q7 | L4 schema | 留空 |
| — | lifecycle id-wide 語意方向 | id-wide 刪除訊號（需 SPEC 修訂） |
| — | 第二實作 spike 優先序 | 排 L2 之前 |
