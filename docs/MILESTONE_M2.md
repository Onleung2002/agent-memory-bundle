# M2 Milestone Report — Importers + L1 Deletion Service

狀態：**正式收尾（2026-11-06，Isaac 驗收通過）**
終判：M2 全 range `d081177..e8678b5` — **PASS-WITH-ADVISORIES**（advisories 非阻塞）
Protocol：worker = Kimi（GLM Coding Plan 對手方 API），verifier = GLM；寫+審唔同族；verifier 做 adversarial repro + mutation testing（M1 起嘅標準手段）。

## 1. Scope（SPEC §4 + §1.2 L1）

- `importers/chatgpt.py` / `importers/hermes.py`：ChatGPT export 同 Hermes profile 解析、sensitivity 標記、`consent.exportable=false` default、tombstone-aware import
- `mbcp/deletion.py`：L1 deletion service — tombstone-first journal（fsync 先於 manifest rewrite）、truthful receipts（`schemas/deletion-receipt.v0.json`）、crash recovery、idempotent delete、`verify_receipt()`
- 之後 fix round 加：tombstones required kwarg、sensitivity 詞彙入 schema、build-path invariant、recover() 收據問責

## 2. Commit 時間線（全部喺 branch，最終 merge 入 main）

| Commit | 內容 | 作者 |
|---|---|---|
| `d081177` | M2 base：importers + L1 deletion + 61 新測試 | worker (deepseek, M2 原始輪) |
| `9a74d87` | Fix round 1：truthful delete receipts + journal-bound verification（F1/F2） | worker (deepseek, deleg_b9af5f88) |
| `7ccbf8b` | docs：BACKLOG commit（M1 round-2 + M2 advisories） | controller |
| `7961be3` | docs：BACKLOG #6 對齊 Isaac 裁決（sensitivity 詞彙 {public, internal, sensitive, secret}） | controller |
| `85aff37` | Fix round 2：tombstones required kwarg（F4）+ sensitivity 詞彙入 schema + 6 個 false-green 測試 gap + `tools/test_inventory.py` | worker (Kimi) |
| `b92dfba` | docs：M2 verify round 2 advisories（7 條）+ spec-worthy 清單 | controller |
| `c33d806` | **Merge M2 入 main**（初判 FAIL 之後兩輪 fix，verify PASS-WITH-ADVISORIES 後 merge） | controller |
| `19c67d1` | Fix round 3：invariant 搬入 `mbcp.make_record`/`validate_record`/`build_bundle` + recover() 洗白閂環（`recovery.jsonl`，semantics (i)） | worker (Kimi) |
| `b941e2d` | docs：M2 verify round 3 advisories（4 條） | controller |
| `e8678b5` | **Merge M2 fix round 3 入 main** | controller |

## 3. 驗證輪次同判決

| 輪 | Verifier | 對象 | 判決 | 關鍵發現 |
|---|---|---|---|---|
| V1（M2 base） | GLM | `d081177` | **FAIL** | F1 MAJOR：`delete()` known 分支喺 crash-retry / 跨 bundle 同 id 情況下出假 receipt；F2 MAJOR：`verify_receipt` 接受重算 self-digest 嘅偽造證據；F3 測試數報錯；F4 tombstone-first 係 caller contract 唔係 importer 行為；26 mutations 中 5 個 false-green |
| V2（fix round 1+2） | GLM | `d081177..85aff37` | **PASS-WITH-ADVISORIES** | F1/F2 確認修好（5 個 adversarial case 重現）；6 個 false-green mutations 全數被新測試捉住；新發現：invariant 只喺 importer build path（MEDIUM-HIGH）、recover() 洗白收窄未閂（MEDIUM）、LOW×4 |
| V3（fix round 3） | GLM | `19c67d1` / 全 range | **PASS** / **PASS-WITH-ADVISORIES** | invariant 三入口都拒、load path tolerant 有 test 文檔化；recover 洗白閂環（`ok:True` = accounting 埋所有已知 removal）；mutation M1–M5 全捉住；新 advisories 4 條（round 3 #1 re-issuance 設計項最重） |

Controller 每輪獨立抽查 verifier 關鍵 claim（adversarial repro 親手重現），無依賴 verifier 自報。

## 4. Mutation testing 總計

- V1：26 mutations，21 caught，5 false-green（fsync、verify journal/schema check、all_tombstones merge、rfc3339 verbatim）+ controller 独立 sweep 加捉 hermes inline `§`
- V2：8 mutations（6 前 False-green + 2 regression），8/8 caught
- V3：7 mutations（invariant×2、recover×3、standing×2），7/7 caught
- 終態：**零已知 false-green**

## 5. Isaac 裁決紀錄（M2 期間）

1. Fix round worker = Kimi core / GLM bulk；deepseek 只做研究類 delegation
2. F4 tombstones required kwarg 同 F1/F2 同輪修
3. BACKLOG.md 由 controller commit，唔入 worker fix commit；連帶 `git worktree prune`
4. Sensitivity 詞彙 = {public, internal, sensitive, secret}；invariant：`secret` + `exportable=true` → build-path reject（machine-checkable）
5. Sensitivity mapping：兩個 importer 都 `sensitive`（保護性 default）
6. M2 驗收通過；LOW×4 留 M3；spec-worthy 三項只記 BACKLOG 唔入 SPEC
7. Round 3 完成 + verify PASS 先算 M2 收尾；M3 開工前先做 retrospective

## 6. 遺留項（→ M3 / 待裁決）

- **[設計，待 Isaac]** Receipt re-issuance under semantics (i)：recover() 後該 target 永遠無可驗 receipt（fail-closed）；re-issuance 要同 L2 跨 bundle 語意 + L4 receipt 正式化一齊設計
- **[待 Isaac]** SPEC limitations 聲明（見 MILESTONE_M2.md §7）
- **[M3]** LOW×4：`tombstones=()` 靜默通過（importer 面）；L1 service state 無簽名；re-delete 回傳舊 bundle receipt；guard/inventory 數文字唔數執行
- **[M3]** Round 3 #2（schema-enum test 應讀 schema 檔）、#3（recover() error hygiene）、#4（raw mbcp `build_bundle(tombstones=())` asymmetry）
- **[M1 carried]** lifecycle=deleted 冇 id-wide 語意；manifest 缺 records/tombstones 容忍成 []
- **[spec-worthy，只記 BACKLOG]** `evidence/` artifact、`DeletionIncompleteError`、L1 receipt 概念（對外交換前要 RFC）

## 7. 已知限制（待 Isaac 決定是否寫入 SPEC §1.2）

L1 receipt 係 immutable artifact（semantics (i)）：`recover()` 移除咗 receipt 未報告嘅 digest 之後，該 target 嘅在冇 receipt 永遠無法通過 `verify_receipt`——系統 fail-closed（唔會出假 ok），但冇 re-issuance/healing API path。re-issuance 語意（supersession chain / claimed⊇evidence）將同 L2 跨 bundle propagation 一齊設計。**現狀：SPEC.md 無此聲明。**

## 8. 環境註記

- 測試一律 plain `python3`（pytest 冇裝）：`tools/run_tests.py`、`tools/run_scenarios.py`、`tools/test_count_guard.sh`、`tools/test_inventory.py`
- GitHub push 由 Isaac 做（controller container 無 credentials）；local main `e8678b5` 待 push + CI 確認
- 終態測試數：147 unit + 9 scenarios = 156；guard baseline origin/main→HEAD = 54→156

## 9. 事件紀錄（retrospective audit 修正後）

- **Working-tree 撞車（root cause = controller 排程）**：V1 mutation verify session（proc_e855cec1e655）仲行緊（差約 30 秒完成）時，controller 已 dispatch fix round 1 worker（deleg_b9af5f88）。兩個 agent 撞同一 working tree；controller 其後 restore 自己嘅 mutations，worker 被迫改用 scratch clone 落地 `9a74d87`。歸屬更正：改 branch 嘅係 controller 自己派嘅 worker，唔係第三方 rogue session。教訓已寫入 protocol（見 HANDOVER.md）：fix worker 只准 verdict 整合後 dispatch；同一 working tree 一次只准一個 agent；事件調查第一步查自己 dispatch 記錄。
- **歸屬更正**：`9a74d87` 原記「worker (Kimi)」，實際 deleg_b9af5f88 = deepseek（controller 當時親口報「Fix round 已派 worker（deepseek）」）。記錄必須跟事實。
