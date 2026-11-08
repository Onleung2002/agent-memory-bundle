# MBCP Backlog（verifier advisories + 後續收緊）

## M1 verifier round 2 advisories（2026-11-05，未計入 fail）
1. **lifecycle=deleted 冇 id-wide 語意**：同 id 喺另一 bundle 仍 active 時，load 會返 active 版本（lifecycle 表達刪除有復活路徑）。收緊方案：lifecycle=deleted 視為 id-wide 刪除訊號，或 SPEC 明文限定用 tombstone 表達刪除。
2. **manifest 缺 records/tombstones 被容忍成 []**：SPEC 1.5 話缺 required fields 一律 reject——實作只 require bundle.id。收緊 schema validation。
3. **guard baseline 未生效**：origin/main 首個有效 baseline 係 merge 後（54 tests）——由 merge 開始 guard 先真正有約束力（self-test 已補救失效風險）。
4. **worktree 殘留**：guard --self-test 被中斷會留低 .git/worktrees 註冊（現 4 個殘留）。加 `git worktree prune`。

## M2 verifier advisories（2026-11-06，verifier=GLM via claude CLI；F1/F2 判 fail）
1. **L1 delete() 喺 known 分支要 crash-aware**：journal 有 tombstone 但 target record 仍在 bundle 時，要先完成 manifest rewrite（或調 recover()）先返 receipt；永遠唔可以返一個自己 verify_receipt=ok:False 嘅 receipt。crash 後 retry delete() 唔 recover() 會寫出 removed_records=[] 嘅假成功 receipt（mbcp/deletion.py known 分支）。
2. **journal tombstone 要分 bundle scope 或明文 id-wide 語意**：bundle A 刪咗 id X，service.delete("bundle-b", X, …) 而家會靜靜哋 skip manifest rewrite、掉咗 caller 嘅 derived_artifacts、照寫 receipt。要決定：per-bundle tombstone，或 SPEC 寫明 tombstone 係 id-wide 並喺 receipt 反映跨 bundle 狀態。
3. **receipt 證據要綁返 journal**：verify_receipt 只比對 deleted_at 字串；tombstone_digest（deletion.py 設咗從未讀）、tombstone.reason、derived_artifacts、removed_records[].digest 全部無綁定 → 偽造 receipt 重算 self-digest 就過。至少要驗 tombstone_digest/reason 對 journal；removed_records[].digest 要刪除時 hash 入 tombstone 或文檔寫明刪後不可驗。
4. **recovery 會洗白舊 receipt**：crash 後 recover() 一行，先前 verify_receipt=False 嘅 receipt 會變 True，無任何 recovery 痕跡。收緊方案：recovered receipt 加標記，或 journal 之外留 recovery log。
5. **durability 無測試**：journal os.fsync 冇任何測試 cover（mutation 移除 fsync 無 test 失敗）。加 fsync contract test（monkeypatch os.fsync，斷言 journal fd 喺 manifest write 之前有 fsync）。
6. **sensitivity 詞彙無喺 schema 落戶**：provenance.sensitivity（personal/private）係 importer 自創詞彙，schema 無 enum 約束。→ 本輪 fix 直接入 schema（見 M2 fix brief ②）。Isaac 裁決（2026-11-06）：詞彙 = {public, internal, sensitive, secret}；machine-checkable invariant：`sensitivity=secret` 而 `consent.exportable=true` → build-path reject（加測試）。 importer 現有 default（chatgpt=personal、hermes=private）要 remap 入新詞彙。
7. **per-file test inventory 無機器可查數**：worker 報稱 test count 同實際 def test_ 數有出入（chatgpt 16/實 17、hermes 17/實 16、deletion 20/實 21）。建議 tools/test_inventory.py 輸出 per-file 數，guard 一齊檢查。

## M2 verify round 2（2026-11-06，verifier=GLM；範圍 d081177..85aff37，verdict PASS-WITH-ADVISORIES；Isaac 裁決：非阻塞，LOW×4 留 M3）
1. **[MEDIUM-HIGH] sensitivity invariant 只喺 importer build path**：`check_sensitivity_invariant` 只由 `importers/_common.build_record` 呼叫；`mbcp.build_bundle → mbcp.load` 端到端接受 `sensitivity="secret"` + `consent.exportable=true`（verifier+controller 各自重現）。BACKLOG M2 #6「build-path reject」無限定 importer、SPEC §1.3 consent 違反=conformance fail → invariant 要搬入 `mbcp.validate_record`/`make_record`，加 load-path conformance test。→ round 3 scope。
2. **[MEDIUM] recover() 洗白未閂**：recover() 刪走 novel-digest stale copy 唔入 `evidence/`、唔出 receipt；舊 receipt recover 後變 ok:True 但 under-report（verifier+controller 重現）。BACKLOG 上版 #4 要求 recovery marker/recovery log 未實現。→ round 3 scope。
3. **[LOW] `require_tombstones` 只拒 None**：`tombstones=()` 靜默通過四個 entry point（重現）。要拒空容器+override flag，或文檔寫明 explicit-empty contract。
4. **[LOW] L1 service state 無簽名**：journal+evidence 係 root 內普通檔案，有寫入權限者可改到同偽造 receipt 一致——L1 receipt 只對無 root 寫入權嘅第三方 tamper-evident。保持 limitations 字眼，唔好跨 trust boundary 出示 L1 receipt。
5. **[LOW] re-delete 回傳舊 bundle 嘅 receipt**：target 已全部不存在時 `delete("bundle-b",…)` 回傳當初 bundle A 簽發嘅 receipt（bundle_id=A）。真話但語意易誤會；re-scope 或文檔說明。
6. **[LOW] guard/inventory 數文字唔數執行**：兩者都數 `def test_` 行；測試體被閹割（early return）計數照過。建議 inventory 總數同 runner 執行 pass 數交叉核對。
7. **[NIT] schema-gate test 涵蓋窄**：`test_verify_receipt_rejects_schema_invalid_…` 只試 `level`/`limitations`；加 `derived_artifacts_verified=true` 鎖死「L1 永不宣稱 L3」。

### spec-worthy（Isaac 裁決：只記 BACKLOG，唔入 SPEC）
- `evidence/<sha256(id)>.json` per-target removal evidence artifact（service-root layout 若對外要 RFC）
- `DeletionIncompleteError`（L1 contract 一部分，spec-worthy）
- L1 receipt 概念（SPEC 1.2 只定義 L4 receipt；L1 receipt + limitations + derived_artifacts_verified:false 係中間概念；若成為交換 artifact 要 RFC）

## M2 verify round 3（2026-11-06，verifier=GLM；commit 19c67d1 PASS；M2 全 range d081177..19c67d1 PASS-WITH-ADVISORIES）
1. **receipt re-issuance under semantics (i)**（design，fail-closed 非 defect）：recover() 刪走 receipt 未報嘅 digest 後，該 target 永遠無 receipt 可以 ok:True、`delete()` retry 永遠 DeletionIncompleteError——ok:True = 「accounting 埋所有已知 removal」成立，但無 API path 拿到新嘅可驗 attestation。re-issuance 需要 verify_receipt semantics 精化（supersession chain / claimed⊇evidence），係設計決定唔係 bugfix。→ 待 Isaac 裁決。
2. **schema-enum test 應該讀 schema 檔**：`test_vocabulary_values_match_schema_enum`（tests/test_sensitivity_invariant.py:190-197）拎 in-code tuple 比 hardcoded literal，從未讀 `schemas/bundle-record.v0.json`——enum 增項偵測唔到。改成 load schema JSON 斷言相等（`test_sensitivity_schema.py:32-33` 同病）。
3. **recover() error hygiene**：`mbcp/deletion.py:626-628` manifest `json.loads` 無 try/except，corrupt manifest 會炸 raw `JSONDecodeError` 而唔係 `DeletionError`（同 `_bundle_manifests` :241-249 唔一致；c33d806 已存在，非 round 3 引入）。
4. **[carried from round 2] raw mbcp `build_bundle(tombstones=())`**：importer 面已 required，mbcp 核心層未——決定 mbcp 層係咪都要 required，定文檔寫明 asymmetry 係 importer-scope。

## M3 precision verify（2026-11-07，verifier=GLM；040a0f2 + 3a17f53 PASS-WITH-ADVISORIES）
1. **A-15 未實現**（controller brief 漏，非 worker 錯）：SPEC §1.2 已寫「unparseable `deleted_at` → LoadValidationError」但 `check_tombstone_on_load` 只查非空字串、`_parse_ts` 靜默 fallback 字串比較——load 接受垃圾 timestamp（controller 重現）。要裁決：實現 parse 驗證，或修訂 SPEC 句子；`_parse_ts` fallback 同步處理。→ M3 主體 round 0。
2. **SPEC §3 補 `digests` compare mode**（controller 草案漏）：runner 已實現 per-id `digests: {id: hex}`（load-03 用緊），SPEC §3 compare-mode 清單冇佢——第三方實作讀 SPEC 唔會知 LOAD-03 比對語意。一行修訂。→ M3 主體 round 0。
3. **A-01 unit-level pin**：raw-UTF8 只有 scenario pin（unit 全 ASCII 盲區，ensure_ascii=True 時 149 unit 全綠）。加一條 unit test（斷言 CJK canonical bytes 無 `\u` escape）。
4. **Runner 硬化**：`_project` 對 missing compare key 會 KeyError 㷬成個 runner——應報 scenario fail 而唔係 crash。
5. **compare list 可加 `deleted_at`**：三個 import scenarios 冇驗 merged `deleted_at`（tied copies 字串形態可能唔同，屬判斷位）；del-06 同字串形態個案可以加。

## M3 round 0 verify（2026-11-08，verifier=GLM；8348817 + fdd5312 PASS）
1. **[LOW] load/build `deleted_at` grammar 不對稱**：load path 用裸 `fromisoformat`（接受 space-separator/basic-format，拒 RFC3339-legal 小寫 t/z），build path 用 schema regex（較嚴）。統一兩邊 grammar 或修 SPEC §1.2 句子。
2. **[INFO] `validate_tombstone` 內 `_check_deleted_at_rfc3339` 係 dead layer**（schema `format: date-time` 更嚴、先 fired）——加 layering 註解免日後 dead-code drift。

## M3 round 1 verify（2026-11-08，verifier=GLM；8de7e06 PASS-WITH-ADVISORIES，8 mutations 零 false-green）
1. **[advisory] digest-failed `lifecycle:"deleted"` 嘅 id-wide signal 無 test pin**：verifier 手工驗證語意正確（signal 喺 digest 驗證之前收集，digest 壞都排除該 id 全部 copies，fail-closed）；但未來「先驗 digest 先信 lifecycle」重構會靜默翻轉——建議加 unit test。
2. **[需 Isaac wording pin] SPEC §1.2「active copies…archived 唔受影響」有歧義**：strict-literal 讀法下被 deleted id 嘅 archived copies 仍會載入，但同句「處理同 tombstone 同等」+ 實證（tombstone 會排除 archived copies）支持 worker 實現嘅讀法（archived-of-deleted 都排除，已有 test pin）。建議 SPEC 加句：「archived 唔係刪除訊號；被 deleted id 嘅 archived copies 一樣被排除，同 tombstone」。
3. **[nit] `load()` docstring 步驟編號失實**：lifecycle scan 實際喺 digest 驗證之前（bundle.py:471-475 before :477），docstring 編號倒轉——reword。
4. **[勘誤] M1 advisory #2 前提部分錯**：manifest schema 自 M1（`a086cd0`）已 required 四 keys；真正缺口係「build/load 不對稱無明文」——今輪已用測試 pin 返（build 拒缺 key、load 容忍）。

## M3 round 2 verify（2026-11-08，verifier=GLM；5bacd97 PASS-WITH-ADVISORIES，6 mutations 零 false-green）
1. **[LOW] propagation.jsonl 每 re-import +1 acked line**：import 冇 pending-first、acked line 無條件 append（propagation.py:266）——同一 pack N 次 import 出 N 條 line。同 docstring「every intake attempt」一致，但 test 名 `no_new_journal_lines` 只量 L1 journal，易誤讀。→ 文檔 pin「attempts audit」或去重。
2. **[LOW] propagation.jsonl invalid-UTF-8 → bare UnicodeDecodeError**：`read_propagation_journal` 只包 JSONDecodeError（propagation.py:313）；L1 `journal_tombstones` 同款。→ bytes decode + typed error。
3. **[LOW] ack 檔案 read-back 無 integrity re-check**：no-op re-import 直接 `json.loads` on-disk ack（propagation.py:244），corrupt → JSONDecodeError leak；tampered → 原樣返回。writer-root 內信任模型（同 BACKLOG M2 #4）。→ read 時驗 integrity 或文檔寫明。
4. **[INFO] RFC UC2 ack 回傳腿未做**：ack 只喺 importing root，source root 無 pending→acked 路徑——minimal scope 內正確，記低免得日後當做咗。
5. **[INFO] manifest tombstones array 保留 import order**（content-equal、order 不同）；`load()`/records/acks 完全 order-independent——繼承 L1 journal-order 行為。
6. **[INFO] 誠實天花板**：digest-chain integrity only、零簽名（M4/L4）；自洽偽造會 import——已被 mutation-enforced 誠實條款 pin 住，任何對外文案必須維持呢個框架。
7. **[INFO] UC1 handover pack**（scope-filtered handover + intake attestation gate 完整流）未做——本輪只做 pack intake gate。

## M3 round 3 verify（2026-11-08，verifier=GLM；ce2d709 PASS-WITH-ADVISORIES，11 mutations 零 false-green）
1. **[LOW·inherited] fresh-path 同 id receipt overwrite**：deleted → resuscitated → deleted again 嘅 fresh path 產生同 receipt id（id preimage = {bundle_id, target_id, merged deleted_at}）→ `_atomic_write` 覆寫原 receipt file。M2 起已存在（verifier 於 ff8d6de 重現、controller 親手重現確認），round 3 冇引入；無 laundering（新 receipt accounting 更全、chain link 被覆寫會 fail-closed）。風險：caller 持有嘅第一個 receipt digest 靜默 dangling、audit trail 失去首份 bytes。→ M4 候選：fresh-path id preimage 加 tombstone_digest/nonce，或已存在 receipt 時行 supersession。**commit message「append-only」對呢條 path 唔準確——記錄跟事實。**
2. **[INFO] `_latest_receipt` 跨 target supersedes 汙染**：X 嘅 receipt 聲稱 supersedes Y 嘅 receipt → Y 嘅 tail 被 hide → Y retry 出 DeletionIncompleteError（availability 而唔係 integrity，fail-closed）。
3. **[誠實確認] receipt writer 偽造喺 L1/L2 不可偵測**（constructive 攻擊 ok:true）——artifacts 全程如實 disclaim（L4/M4 scope），零 overclaim。
4. **[語意裁定] chain walk 係向 origin 方向行**：tail 嘅 supersedes 指向 ancestor，ancestor file 冇咗 → broken chain ok:false（fail-closed 方向正確；恢復 = re-issue 新 chain）。

## 工序教訓（worker 品質 pattern）
- Kimi 兩次都喺 YAML plain scalar 撞 `: `（step 名含 colon）→ CI 加 actionlint step 可即時捉（屬 SC-CI 類，下輪加）。
- Worker 自寫測試全部 white-box 假綠（18/18 過但核心 invariant 冇 enforce）→ 證明「寫+審唔同族」係必要唔係奢侈；mutation testing 應成為 verifier 標準手段（round 2 已用，效果好）。
