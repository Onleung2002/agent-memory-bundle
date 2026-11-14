# SPEC v0.1 歧義清單（P0 spike 產出，2026-11-06 收編）

來源：獨立第二實作 spike（GLM，物理隔離、零 source 盲寫，9/9 scenarios pass）。原報告：`/tmp/spike_glm/SPIKE_REPORT.md`。用途：M3 SPEC 精確化 pass 嘅 requirement 輸入。
狀態標記：**[PIN]** = 寫低現行行為（主 impl 與 spike 讀法一致，SPEC 修訂直接採納）｜**[裁決]** = Isaac 已裁決（2026-11-06）｜**[M3]** = 落 M3 實作項｜**[分歧]** = spike 與主 impl 讀法唔同，需 Isaac 裁決。

## 收編狀態（2026-11-14 更新，對照 docs/BACKLOG.md）

- **A-01 至 A-15：已收編**（M3 精確化 round 0 起：A-01/A-02 parse + compare mode 補句、A-05 suite 同步、A-07 分層處理，其餘 PIN 項全部 SPEC 補句落實）
- **A-16：已收編**——M4 Round C Batch 1（commit 88e515e）裁決 + 修復：duplicate tiebreak = canonical SHA-256（主 impl 改動 + 測試），order-independent
- **A-17 至 A-27：已收編**（PIN 全部落 SPEC / suite；A-21 dropped-ids = M4 輪內已落）
- **仍然 OPEN（唔係本清單 A-xx 編號，記喺 BACKLOG）**：
  1. H3/H4/H5 spec-lag wording（supersession 兩觸發位、write-boundary id-level 措辭、receipt exact compare）——下次 SPEC touch 一齊修，清單見 `docs/HONESTY_OPEN_ITEMS.md`
  2. ADV-C1-1 / ADV-C3-2：legacy 非 ASCII id / 折疊 id quarantine + migration scan（A-3 availability 面）
  3. Registry v0.2：external record 驗證設計（fetchable repo_url + 拒 cite 本 repo commit）
  4. Blind-rewrite spike v2：major spec 修訂（Round A/B/C）後未重跑——G1 前應重複一次（M3 實證：一次捉 31 條歧義）

## Blocking（7）

- **A-01** [PIN] 非 ASCII 輸出：canonical JSON 用 raw UTF-8（`ensure_ascii=False`），唔用 `\uXXXX` escape。SPEC §1.4 補句。
- **A-02** [PIN] 同 class 預算消耗順序：priority class（critical>standard>opportunistic）→ manifest sort key `(bundle.id, canonical SHA-256)` → bundle 內位置。SPEC §1.1 補句。（INT-02 隱性釘死）
- **A-03** [裁決] truncated record 消耗 **truncated length**（即用晒剩餘預算；截斷後同 class 冇 record 可以再載入）。fail-closed：預算計「收貨幾多」唔計「原本有幾多」。SPEC §1.6 補句。
- **A-04** [PIN＋M3] **Public API contract**（§3 加「公開 API 契約」節，全套最重要）：`load(bundles) -> list[record dict]`（verbatim、含 unknown fields、截斷已套用、deterministic）；`import_bundle(store, bundle) -> {"records":[...], "tombstones":[...]}`（回傳新狀態，**唔 mutate 輸入**）；`canonical_bytes(x) -> bytes`、`canonical_sha256(x) -> hex str`。跨實作契約 = 呢三個函數 + scenario runner 語意；build-path 函數（make_record 等）唔係跨實作契約。[M3] `dropped-ids` 通道（A-21）做 v0.2 契約一部分。
- **A-05** [裁決] scenario `expect` 比對語意要明文：`record_ids` 精確有序；`bodies` 按 id；`digests_valid` = 所有輸出 record digest 驗證通過；`tombstones` = **只比對 scenario 檔明文 `compare:` 欄位清單入面嘅 keys**——唔接受隱性 subset match；DEL-04 要補 `deleted_at` 或明文 declare 比較欄位。suite 同步改。
- **A-06** [裁決] `max_chars` 單位 = **Unicode code points (Unicode scalar values)**，唔係 UTF-8 bytes / UTF-16 units。SPEC §1.1 明文寫出三個唔係。
- **A-07** [裁決] 非 string `body` 分層化解 §1.5/§1.6 矛盾：**build path reject**（§1.5）；**load path drop**（§1.6）＋ dropped-ids 通道（A-21 → M3）。

## Mild（12）

- **A-08** [PIN] class budget 最小值計法：計所有通過 tombstone/lifecycle/digest 過濾並完成 id-merge 嘅 candidate records（digest-dropped 唔計）。
- **A-09** [PIN] merge 嘅 first/last 參照 global 序列（manifest sort key → bundle 內 index），唔係 input order。LOAD-02/MERGE-01 證實。
- **A-10** [PIN] 同 id 跨 priority 嘅 duplicate：merged record 用 winner 嘅 `load_policy` 全套（priority/max_chars/on_budget_exceed）。
- **A-11** [PIN] merge 先於 budget：一個 id 只計一次預算。
- **A-12** [PIN] digest = SHA-256(canonical **body**)，唔係成個 record（fixture 14/15 驗證；第 15 個係 INT-01 故意 mismatch）。
- **A-13** [PIN] manifest tiebreak digest 計「as-loaded」成個 manifest（含 P3 unknown fields + records + tombstones）。
- **A-14** [PIN] load path 順序：結構驗證 → tombstone filter → lifecycle filter → digest 驗證（tombstoned + 壞 digest = 靜默過濾唔報錯）。
- **A-15** [PIN] tombstone dedupe 嘅 `deleted_at` 比較 = RFC3339 instant（aware datetime）；`+08:00` > 同刻 `Z`；unparseable → `LoadValidationError`。SPEC §1.2 補句。
- **A-16** [分歧→需裁決] `deleted_at` 相同（tie）時 dedupe 勝者：spike 揀 canonical SHA-256 最大者（完全 order-independent）；主 impl `_merge_tombstones` 係 input order 先到先得（`max()` 平手取先現者）。**建議：align 做 canonical-SHA-256 tiebreak**（§1.1 determinism 原則一致、L2/supersession 需要 order-independence；代價 = `_merge_tombstones` 一行改動 + 測試）。待 Isaac 裁。
- **A-17** [PIN] 輸出 tombstone 按 `target_id` 排序。
- **A-18** [PIN] `lifecycle:"deleted"` 喺 import path 保留唔剷（load 先 filter）。
- **A-19** [PIN] **import 會剷走 store 入被 tombstone（store＋incoming）針對嘅既有 records**——「先刪後加」涵蓋兩邊。L2 propagation pack 就建喺呢個語意上。SPEC §1.2 補句。
- **A-20** [PIN] store 與 incoming 同 id：store copy 勝（first wins），incoming duplicate 忽略。
- **A-21** [M3] digest-drop 靜默無通道：load result 加 dropped-ids（併入 A-04 API pin，v0.2）。
- **A-22** [PIN] `on_budget_exceed:"error"`：`BudgetExceeded` 即刻 raise、load 中止。
- **A-23** [PIN] load path 結構驗證涵蓋 manifest 層（bundle.id/mbcp_version/arrays）同 tombstone 層；`mbcp_version` load 時唔對 `^0\.1$` 檢查（tolerant reader）。
- **A-24** [PIN] unknown-field retention 係全嵌套層級（`scope` 入面加 key 都保留）。

## Cosmetic（5）

- **A-25** [PIN] `max_chars: 0`：class 預算 0 → 全 class skip；truncate_last 冇剩餘 → drop。
- **A-26** [PIN] 空輸入（`load([])`、空 arrays）→ 空結果、唔報錯。
- **A-27** [PIN] exact fit（`len(body) == remaining`）正常載入、唔截斷、唔 mark。
- **A-28** [PIN] `truncate_last` = 保留 prefix（INT-02 證實；名字係暗示唔係定義）。
- **A-29** [PIN] scenario YAML = JSON-syntax 子集；非 JSON YAML 未定義（runner parse fail 可接受）。
- **A-30** [PIN] 例外契約只 pin `LoadValidationError`、`MergeConflict`（概念）、budget error 名（A-22 `BudgetExceeded`）；其餘訊息字串自由。
- **A-31** [PIN] `sensitivity=secret ⊼ exportable=true` build-path invariant：來源係 schema description + §1.3；build-path 強制（M2/M3 已實現於 `mbcp.validate_record` 層）。

## Fixture-resolved（寫返入 SPEC 免流失）

digest=canonical body（A-12）｜merge first/last 用 tiebreak 序（A-09）｜truncate 保留 prefix（A-28）｜load-path tombstone 跨 bundle（DEL-02）。

## Suite 同步（SPEC 修訂 commit 時一併，照 RFC §5 紀律）

新增 scenario：非 ASCII canonical（A-01）｜truncate 後有後續 record（A-03）｜import 剷 store 既有被針對 records（A-19）｜dedupe tie（A-16，裁決後）｜DEL-04 compare 欄位明文化（A-05）｜非 string body load drop（A-07/A-21）。
