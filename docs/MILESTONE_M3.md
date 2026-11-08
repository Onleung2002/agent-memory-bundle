# M3 Milestone Report — SPEC 精確化 + M1 carried + L2 propagation + Receipt supersession

完成日期：2026-11-08。分支主體 merge 入 main（`e724c9e`），CI 綠，origin/main 同步。

## 1. 範圍與裁決來源

- **P0 spike**（GLM，物理隔離盲寫：只俾 SPEC + scenarios + schemas，零 source）：9/9 pass、SPEC 歧義清單 31 條（7 blocking）。收編 `docs/SPEC_AMBIGUITIES_V0P1.md`。
- **Isaac 裁決**：A-03 = truncated length；A-06 = Unicode code points；A-16 = canonical SHA-256 tie-break（(b)，由 controller 如實標「分歧」觸發）；SPEC 精確化 pass 七項整體批準；archived-wording pin（A-2）；A-15 = 實現（spec 與 code 唔可以兩個世界）。
- **RFC** `docs/RFC_L2_REISSUANCE_L4.md` Q1-Q7 + use case UC1-UC4。

## 2. 輪次記錄（全部 worker=Kimi、verifier=GLM、mutation 零 false-green 為收貨線）

| Round | Commits | 內容 | Verdict |
|---|---|---|---|
| Precision | `3a17f53`(SPEC) + `040a0f2` | SPEC 七項修訂 + A-16 tiebreak + suite 14 scenarios | PASS-W-ADV |
| Round 0 | `8348817`(SPEC) + `fdd5312` | A-15 實現 + A-01 raw-UTF8 unit pin + runner 硬化 | PASS-W-ADV |
| Round 1 | `a02108c`(SPEC) + `8de7e06` | M1 carried：lifecycle-deleted id-wide + manifest required-keys 不對稱 pin | PASS-W-ADV |
| Round 2 | `4ffb9c0`(SPEC) + `5bacd97` | L2 minimal：propagation pack export/import + ack + propagation.jsonl fail-closed | PASS-W-ADV |
| Round 3 | `b77a206`(SPEC §1.2.2) + `ce2d709` | Receipt supersession chain + round-2 LOW cleanup ×3 | PASS-W-ADV |

Controller commits：`35c99a8`(ambiguity inventory)、各 BACKLOG advisory commits、M1/M2 advisory refs。Merge 提交：`e228ab6`、`11e9ce1`、`ff8d6de`、`e724c9e`。

## 3. 測試規模演進

54 (M1) → 156 (M2 收) → 195 (round 2) → **212（194 unit + 18 scenarios）**。Guard non-decreasing；inventory cross-check；CI 加 actionlint + cross-check step。

## 4. 誠實框架（transversal，對外必須維持）

- **Digest-chain integrity only、零簽名**：自洽偽造（pack 或 receipt）不可偵測——兩個 verifier session 都 constructive 證實並確認 artifacts 零 overclaim；誠實 wording 由 mutation-enforced test pin 住（M5×2）。簽名 = M4/L4（ed25519，Q6 裁決方向）。
- G2 gate 已正式修訂（2027-03-31：L2 + supersession + registry 首條記錄；L4 移 G3 前），記於 knowledge_base business case。

## 5. 攜入 M4 的事項（BACKLOG 有詳細條目）

1. **[LOW] fresh-path 同 id receipt overwrite**（inherited，M2 起）：deleted→resuscitated→deleted 重用同 receipt id 覆寫檔案——id preimage 加 tombstone_digest/nonce 或行 supersession。
2. UC2 ack 回傳腿（source root pending→acked）。
3. UC1 handover pack 完整流（bundle handover + intake attestation gate 完整版）。
4. L4 簽名（ed25519，Q6）：三層 digest 信任模型升級為可對外驗證。
5. 精確化驗證殘餘：round-1 archived-wording test 已 pin；M3 精確化 round 的 LOW advisories 已收編。

## 6. 程序備忘

- Protocol 內化：每輪「verdict 整合先 merge」全程零 working-tree 撞車；controller SPEC/BACKLOG commits 同 worker code commits 永遠分離；worker 自報 guard baseline 與 pushed origin/main 有差異時由 verifier 釐清（round 1 case）。
- 學到教訓：M1 advisory #2 前提部分錯（schema 自 M1 已 required）——勘誤記 BACKLOG，記錄跟事實。
- Mutation 驗收標準全程無鬆動：四輪 30+ mutations，test-suite false-green 為零（一宗 mutation-design artifact 由 verifier 文檔化排除）。
