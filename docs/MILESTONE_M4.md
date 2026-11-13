# MILESTONE M4 — L4 簽名 + Conformance Registry + Round C 收緊

> 封存日期：2026-11-13。M4 全收（Round A → C → B + mini-round + audit2 hotfix）。
> SSOT：SPEC.md / GOVERNANCE.md / docs/BACKLOG.md。本檔係 milestone 敘事，唔係 requirement 來源。

## 1. Round A — Conformance Registry（第一個對外正式 artifact）

- `schemas/conformance-record.v0.json` + `tools/make_registry_record.py`（git metadata 自動生成 `spec_commit`/`record_generated_at`，零手填——「手填係漂移嘅入口」）+ `docs/REGISTRY.md` + 首條記錄（home impl、spec 0.1、attestation = verifier-attested 引 audit hotfix 輪記錄）。
- **術語法（Isaac 必改位）**：GOVERNANCE 原則 2 落地——全 artifact 禁 certificate/certified/certification，升級路徑 = self-declaration → verifier-attested；grep pin（licensed blockquote 唯一豁免）；dual-needle（`certificat-` 同 `certified` 唔同 root——controller pin 首版漏 certified，mutation 跑揭出嚟）。
- **Worker pushback #1（GLM verifier ENDORSED）**：worker reject controller 嘅 HEAD-coupling anti-drift 設計（self-reference 死代碼），改做 spec_commit git 歷史核對——歷史記錄永遠可驗。
- ADV-1/3/4 pins + ADV-2（external record 驗證設計）歸 registry v0.2 / Round C 分流。

## 2. Round C — audit 待裁 10 條分流（三 batch）

- **Batch 1（88e515e + SPEC 60afd52）**：§6 寫入邊界拒收（put/import 對 tombstoned id typed reject——「cannot resurrect」升級 ingest 契約）、§7 pack_digest 計 source_root、§8 max_chars≥1 兩邊堵、§9 duplicate tiebreak = canonical SHA-256（order-independent 哲學統一）、§10 lifecycle:deleted integrity 前提（**語意反轉**：刪除訊號必須 authentic，明文取代 M3 round-1「signal survives digest-drop」讀法）、§12 id grammar + NFC。`:` deviation 由 Isaac 裁決合法化（namespace prefix 正確形狀；importer migration 會斷已持久化 tombstone 對應——唔做）。
- **Batch 2（151997d + SPEC e99a00d）**：§3 root advisory lock（flock + owner/Condition re-entrant、bounded timeout、serialization/liveness 保證唔係 security boundary——誠實框架寫死）、§13 receipt store inventory（bundle_set + inventory_digest；`check_inventory` opt-in point-in-time 對帳）、A-2 error split（OSError skip+count、malformed typed、delete-scan fail-closed）。**Worker pushback #2**：A-2「broad except 靜默 skip」premise 係 stale——d0dfa48 起已 typed raise，舊 pin vacuous（journal 空冇讀毒檔）；verifier instrumented parent 核實。
- **Batch 3（4a71609 + SPEC d57a850 + pin c17c1b3）**：put_bundle/export 入 root lock（ADV-C2-3 閉——born-inventory-divergent receipt 窿封死）、`_safe_id` injective 化（ADV-C3-1 誠實修正：typed-guarded, injectivity not claimed——second-preimage live 重現）、id comparison NFC + ASCII case-insensitive、**ADV-C3-4 controller pin**：兩真 OS process flock 證據（barrier-based 無 sleep；mutation neutralize-flock 乾淨捉到——「SPEC 已聲稱嘅嘢 suite 必須有證據」）。
- Worker flag 誠實記錄：delete-handle verbatim residual（file addressing 唔喺 SPEC 1.5 comparison scope——spec-consistent，LOW）。

## 3. Round B — L4 ed25519 attestation（badge 級保證落地）

- **主體（0fbe0e2 + SPEC ed15b6f）**：receipt envelope + propagation pack ed25519 簽名（per-root keypair，`.mbcp.key` 0600，key_id = sha256(pubkey)[:16]）；vendored RFC 8032 reference（provenance header；KAT vectors 入 suite）；intake authorization **fail-closed** accept-list（Isaac 裁決：§10「刪除訊號必須 authentic」喺 L2 嘅直接延伸——unverified pack 可以觸發刪除 = 未認證刪除通道由 L2 重返；verified/unverified 分級只准 intake 記錄層觀測）；pending retry/dead-letter lifecycle。
- **誠實威脅模型**：簽名防局部篡改唔防全 root compromise（key 同 store 同 root）；第三方驗證要 out-of-band pubkey anchor；簽名唔提供 trust root；GOVERNANCE 原則 2 適用——cryptographically-signed attestation 唔係 certificate。
- **Worker timeout 事故**：pure-Python ed25519 令 suite 慢 ~8 分鐘，worker 撞 3300s wall-clock 被殺——在途工作其實功能完整（controller 親驗 311/24 全綠），continuation worker（同 branch）收尾 commit。事故定性：時間預算問題，唔係品質問題。
- **Mini-round（6df658d）**：verify 揭 ADV-B1（MEDIUM）——`checkvalid` 唔拒 S≥L，malleable sig 全收（controller 親手重現）。修：S<L canonical-scalar check + malleability pin + gate-order pin（ADV-B3）+ provenance 誠實修正。
- **Worker pushback #3（verifier 白紙黑字自我勘誤）**：vendored code 歸屬——verifier 初判 RFC Appendix A，worker 修正係 cr.yp.to affine reference（`_xrecover` 等 16 函數 shape）；S<L 係 §5.1.7 step 1 非 step 3；hostile-pubkey 誠實框架 upheld。**三次 worker pushback（A-2 premise、HEAD-coupling、citation）全部啱**——記錄跟事實嘅工序證據。

## 4. Second independent audit（deleg_2435d630 → docs/AUDIT2_2026-11-11.md）

- 0 EXPLOITABLE / 10 WEAKNESS / 7 HONESTY-GAP；9 probes + 5 mutations；七個表面信心度 85-95%。
- 即刻修：W10 .gitignore、H2 SPEC garbled 句、H7 SECURITY.md post-L4 改寫（controller）。
- Hotfix（a18f7d0 + SPEC f69c709 hotfix rulings）：W1 三層 keypoint validation（identity-pubkey 零私鑰 chain attack 紅轉綠——victim record 倖存）、W2 key-loss fail-closed（KeyMaterialLostError + rotate_keypair 顯式 hatch）、W5-W8 pending typed contract、H6 裁定 docstring-only（SPEC 無 mandate eligibility gate；enforce = visible deliberate change）。
- BACKLOG 攜入：W3/W4/W9/H1（LOW、fail-closed 下游）、H3/H4/H5 spec-lag wording、I5 pin 強化。

## 5. 測試演進與 commit 鏈

- Suite：298（Round C 收）→ 311/24（Round B 主體）→ 313/24（mini-round）→ **331 unit + 24 scenarios = 355**（audit2 hotfix 收）；guard origin/main 177→355。
- 主鏈：`7297422`(M3 §5a) → Round A `49a44fb`+`8c522a0`+`48e53c4` → SPEC `60afd52`/C1 `88e515e`/merge `c4aaf7e` → SPEC `e99a00d`/C2 `151997d`/merge `f56a986` → SPEC `d57a850`/C3 `4a71609`+pin `c17c1b3`/merge `c5c7551` → SPEC `ed15b6f`/B `0fbe0e2`/mini `6df658d` → audit2 `f69c709`/hotfix `a18f7d0`/merge（本 milestone 封存 commit）。
- 每輪標準：SPEC controller 先行 → Kimi worker → GLM verify（mutation 零 false-green + probe 紅轉綠）→ controller 親手抽查 → CI 綠 → Isaac 批 → merge。

## 6. 攜入 M5+/BACKLOG

- Registry v0.2（ADV-2 external record 驗證設計：fetchable repo_url + count-verified + 拒絕 cite 本 repo commit）
- ADV-C3-2 legacy 折疊 id migration scan；ADV-C1-1 legacy 非 ASCII id quarantine 工具（A-3 availability 面）
- W3/W4/W9/H1（audit2 LOW sweep）；H3/H4/H5 spec-lag wording；keypair cache 語意入 SECURITY.md 候選
- G1（2027-01-31）：兩個非自家實作跑 suite（候選 Blanchard/Wright）；G2（2027-03-31）：L2+supersession+registry 首條（已達）+L4 移 G3 前（已達——M4 Round B 完成）
- Key rotation 語意（key_id 已預留；G2 前定）
