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

## 工序教訓（worker 品質 pattern）
- Kimi 兩次都喺 YAML plain scalar 撞 `: `（step 名含 colon）→ CI 加 actionlint step 可即時捉（屬 SC-CI 類，下輪加）。
- Worker 自寫測試全部 white-box 假綠（18/18 過但核心 invariant 冇 enforce）→ 證明「寫+審唔同族」係必要唔係奢侈；mutation testing 應成為 verifier 標準手段（round 2 已用，效果好）。
