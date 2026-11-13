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

## Audit hotfix 輪（2026-11-08，獨立 audit=deepseek；d0dfa48+360f1e1+dbc8413，GLM verify）
1. **[已修] HIGH×2 + §4 + §11**：receipt accounting 綁 target 唔綁世代、delete() 全 return path self-verify、surrogate/NaN typed + wedge 消除、bundle.id grammar + collision refuse。詳見 docs/AUDIT_2026-11-08.md 逐項表。
2. **[已修] A-1 fresh-path id collision**：同 bundle resuscitate overwrite 路由 `_reissue_receipt`（supersession）；ATK1-3 pinned（含 ATK3 兩 mode + 恰好一個 tail）。
3. **[已 pin] A-5 parse gate**：8 條 NaN-literal pins；M4c mutation 紅×5。
4. **[已收编 C2，前提勘誤] A-2**：brief/舊 pin 嗰句「recover() broad except 靜默 skip」premise 係 stale——d0dfa48 起 recover 對 malformed 已 typed raise；舊 pin 係 **vacuous**（delete 先 raise → journal 空 → recover 冇讀毒檔；instrumented parent 核實）。真正 delta（151997d）= OSError/KeyError skip+count（`last_recovery_skipped_unreadable`）、TypeError typed wrap、delete-scan OSError typed、NaN pin 改 non-empty journal 語意。唔寫「C2 消滅 silent skip」。
5. **[backlog] A-3**：毒 manifest 塞住全 root deletes（fail-closed 正確）——SECURITY.md 補 availability 句。**[backlog] A-4**：`_safe_id` 尾底線摺疊 non-injective。
6. **[M4 Round C 待裁決]**：§3 lock/CAS、§5 L2 authorization+receipt、§7/§15 ack identity+pending、§13 bundle inventory、§14 numeric serialization——每條帶 audit 建議修法，見 AUDIT_2026-11-08.md。（§6/§8/§9/§10/§12 已 Batch 1 修復收編；§7 pack_digest 部分同輪修、ack identity 完整修法留 Round C Batch 2。）
7. **[已修] Round C Batch 1（88e515e）**：§6 寫入邊界拒收、§7 pack_digest 計 source_root、§8 max_chars≥1 兩邊堵、§9 duplicate tiebreak = canonical SHA-256、§10 lifecycle:deleted integrity 前提（語意反轉，Isaac 裁決）、§12 id grammar + NFC。**ADV-C1-1（backlog）**：legacy 非 ASCII id manifest 由可載入變 load-fail + recover-poison（A-3 面擴大）——要 quarantine/migrate 工具 + SPEC 句講明 rejection-closure ≠ NFC-comparison（raw layer NFC 仍 mutation-pinned）。**ADV-C1-2（backlog）**：hostile export metadata（session 檔名、conversation id 帶 `/`）而家 typed fail——fail-closed 正確，併入 id follow-up。**[`:` 裁定]**：SPEC grammar 修訂合法化 `:`（namespace prefix 正確形狀），唔做 importer id migration（會斷已持久化 tombstone 對應）。
8. **[程序] Audit 揭 M3 round-3 BACKLOG #1「無 laundering」判斷錯**（controller 當時 repro digest 相同 mask 咗問題）——該條已由今輪 HIGH#1 修復取代；記錄跟事實。

## M4 Round A verify（2026-11-08，registry；49a44fb+8c522a0 PASS-WITH-ADVISORIES）
1. **[registry v0.2 / Round C 分流] ADV-2 外部 record 驗證設計**：unresolvable spec_commit → schema-only（偽造數字過 pin）；更惡——偽造者可 cite 本 repo 真 commit 頂替。修法：`producer: external` 必須帶 fetchable `repo_url` + commit resolution 檢查（或明示 `count-verified: false`），並拒絕 cite 本 repo commit 嘅 external record。v0.1 可接受（registry 得一條 home record，PR review 層把關）。
2. **[已 pin] ADV-1**：`record_generated_at` 對 spec_commit git committer date（reg_06）；**[已 pin] ADV-3**：術語法 grep pin（reg_07——dual needle：`certificat-` 同 `certified`，後者唔包前者 root，M3 mutation 首跑揭 pin 自身漏「certified」）；**[已 pin] ADV-4**：所有 schemas `additionalProperties:false` meta-pin（reg_08）。三 mutation 重跑全紅。
3. **[已修] ADV-5**：REGISTRY.md「quoted verbatim」→「authorized English rendering」。
4. **[裁定記錄]**：worker reject controller 嘅 HEAD-coupling anti-drift 設計，GLM verifier ENDORSED（HEAD-coupled check 係 self-reference 死代碼；commit-coupled 令歷史記錄永遠可驗）——brief 設計錯、worker 修正對。

## M4 Round C Batch 2 verify（2026-11-10，151997d PASS-WITH-ADVISORIES，7/7 mutations 零 false-green）
1. **[已修] ADV-C2-1**：lock comment/commit message 嗰句「flock 同 process 兩個 fd 互斥唔生效」係錯（kernel probe：separate open() fd 會互斥；dup'd fd 共享）——設計必要性係 re-entrancy（同 thread nested 鎖會 self-block）唔係互斥失效。comment 已改正（kernel 語意寫啱）。
2. **[C2 決策] A-2 收法**：雙管（收窄 except + skip 計數可見），verifier instrumented parent 核實 vacuous-pin 勘誤屬實。
3. **[backlog] ADV-C2-3**：`put_bundle`/`export_propagation_pack` 繞過 root lock——non-target bundle mid-delete → receipt 出世就 inventory-divergent（自己 check_inventory=True fail）；target-copy mid-delete fail-closed。無 corruption/假 receipt，LOW-MEDIUM liveness/semantic wart。**Batch 3 收**（鎖 put_bundle 或 inventory 改 final re-read）。
4. **[backlog] ADV-C2-4**：`.mbcp.lock` 被 unlink while held → 之後嘅新 process 鎖新 inode，跨 process 互斥 void（inherent advisory-lock 屬性）；in-process gating 唔受影響。SPEC §1.2.3 已一句講明。
5. **[裁定]**：bare `build_receipt(inventory=None)` 記空 set severity = LOW（唔新增洗白路徑，unsigned-receipt 限制先前已有；inventory 嚴格只加證據）；pre-C2 receipts schema-invalid breaking by design，無 committed artifact 受影響。

## M4 Round C Batch 3 verify（2026-11-10，4a71609 PASS-WITH-ADVISORIES，mutation 全紅零 false-green）
1. **[已修] ADV-C2-3 正式標 closed**：put_bundle/export_propagation_pack 入 root lock；import_bundle 證實真 write-free（grep 零 file I/O）、record_pending_propagation 留鎖外（O_APPEND 一行，best-effort，verify_receipt 唔會查）——SPEC 1.2.3 修訂句已落。
2. **[已修] ADV-C3-1**：`_safe_id` docstring「distinct ids never collide」係 overclaim（second-preimage live 重現：`abc_` ↔ `abc--639ce2d59e09` 同檔名）——措辭改「collisions are typed-guarded, injectivity not claimed」，code 唔郁（safety = deterministic mapping + typed collision guard）。
3. **[backlog] ADV-C3-2**：legacy 折疊 id 舊檔名與 post-C3 put 並存無 collision（`bundle_inventory` set 塌縮重複 id；無資料損失）——要 coherence check 或 one-shot migration scan。
4. **[backlog] ADV-C3-3**（pre-existing）：crash-torn `propagation.jsonl` 永久毒（typed fail-closed 無 heal）；O_APPEND atomicity 係 Linux 保證唔係 strict POSIX——portability 措辭注意。
5. **[已 pin] ADV-C3-4**：跨 process flock 證據 pin（controller 親手寫 `tests/test_flock_cross_process.py`：兩真 OS process、barrier/Event 無 sleep、phase1 typed timeout + phase2 釋鎖後成功 + phase1 零寫入 residue；mutation（neutralize flock）乾淨捉到）。「SPEC 已聲稱嘅嘢 suite 必須有證據」。
6. **[裁定] delete-handle verbatim residual = LOW**：`get_bundle`/delete bundle_id 檔案定址保持 verbatim（case-variant = 唔同檔案），fail-closed；SPEC 1.5 comparison scope 本來就唔涵蓋 file addressing——spec-consistent，已在 §1.2.3 補句講明。

## M4 Round B audit2 hotfix verify（2026-11-13，a18f7d0 PASS-WITH-ADVISORIES，6/6 mutations load-bearing）
1. **[已修] W1 keypoint validation**：三層（authorize_source / load_keypair / attestation_problems embedded-pubkey gate）——L3 係 load-bearing（verifier 親手手寫 accept-list bypass L1 證明 config-time 驗證擋唔住手列入嘅 identity key）；identity-pubkey 零私鑰 chain attack 紅轉綠（victim record 倖存、journal 唔存在）；`checkvalid` byte-identical（minimal-diff 裁決）+ pin 斷言 raw 偽造 equation 層仍 True——誠實 scope 有測試背書。
2. **[已修] W2 key-loss fail-closed**：`KeyMaterialLostError`（receipts/journal 歷史存在即拒）；`rotate_keypair` 顯式 hatch（docstring「silently loses the tail」誠實）；**verifier 裁定 per-instance cache 可接受**（cached valid material 繼續簽 = availability-preserving 同 trust domain；key-loss 發現路徑 = restart 後新 instance）——BACKLOG LOW：per-signing-op stat 或 SECURITY.md 記 cache 語意。
3. **[已修] W5-W8**：DeletionError 入 except（契約「failure→line appended」全 typed 覆蓋）、acked line `.get("retry_count",0)`、schema 驗證入 signed-only gate（sig-first 保持）、dead-lettered 拒 re-enqueue——audit probe7 P4-P7 全紅轉綠。
4. **[裁定] H6 docstring-only 可接受**：SPEC 1.2.8 無 mandate eligibility gate；enforce 會爆 dead-letter pin（fixed injected now MAX+1 retries）；已 pin advisory 語意（`test_next_attempt_at_is_advisory_not_enforced`）——未來 enforce = visible deliberate change。
5. **[backlog] W3/W4/W9/H1**（audit 原判 LOW）：authorize_source untyped ValueError、record_pending 無鎖 append（唔係洗白通道）、build-path untyped crash、load_keypair wrong-length hex——全部 fail-closed 下游（verifier 再確認）。
6. **[backlog] H3/H4/H5 spec-lag**：supersession 兩觸發位（SPEC 1.2.2 話一個）、write-boundary id-level 措辭（SPEC 話 (id,digest) pairs）、receipt 層兩處 exact compare（conservative direction）——下次 SPEC touch 修。
7. **[backlog] verifier 新發現 ×2**：keypair cache 語意記 SECURITY.md 候選；L2 keypoint gate 對 self-consistent key 檔係 redundancy（無 seed 映射 small-order point）——保留作 cheap defense-in-depth，零動作。
8. **[記錄] I5**：mut3 下 alone-copy pin 唔 discriminating——強化建議（同 bundle 加第二條 active copy）收 BACKLOG；I6 = ADV-C2-4 重申（non-new）。

## 工序教訓（worker 品質 pattern）
- Kimi 兩次都喺 YAML plain scalar 撞 `: `（step 名含 colon）→ CI 加 actionlint step 可即時捉（屬 SC-CI 類，下輪加）。
- Worker 自寫測試全部 white-box 假綠（18/18 過但核心 invariant 冇 enforce）→ 證明「寫+審唔同族」係必要唔係奢侈；mutation testing 應成為 verifier 標準手段（round 2 已用，效果好）。
