# Security Policy

## 支援版本

- `main`（head）： actively maintained。
- 舊 milestone tag：best-effort。

## 報告漏洞

**唔好開 public issue。** email project maintainer（見 GOVERNANCE.md / repo owner），72 小時內確認、修復 timeline 視乎嚴重度。

## 誠實嘅威脅模型（請先讀，多數「發現」其實係已披露嘅設計邊界）

MBCP 嘅 artifact（deletion receipt、propagation pack、ack）目前提供 **digest-chain integrity only**：

1. **無簽名（直到 L4 ed25519 落地）**：任何可以寫入一個 root 嘅人（root writer / 有 filesystem 權限者）可以偽造自洽嘅 receipt / pack / ack，`verify_receipt` / import 驗證會通過。呢個係已披露嘅 L1/L2 信任模型——tamper-evidence 建基於 writer 唔偽造，唔係防偽保證。代碼、schema、ack artifacts 全部如實聲明（見 `mbcp/deletion.py` `L1_LIMITATIONS`、`mbcp/propagation.py` `ACK_LIMITATIONS`）。
2. **Receipt「刪除證明」唔係第三方可驗證 erasure certificate**：第三方驗證（L4）係 roadmap；在冇 L4 前，receipt 驗證假設你信任產生 receipt 嗰個 root 嘅內部狀態。
3. **跨 root propagation 嘅 attestation gate**：拒絕無效 attestation 係 digest-chain 層面；同樣唔係防偽。
4. **Machine unlearning 邊界**：tombstone/receipt 證明「bundle 層已刪」；runtime 記憶體、衍生快取、模型權重內容嘅實際抹除唔喺本 spec 範圍（SPEC §5 non-goals + RFC UC4）。

以上唔係漏洞，係 spec 明文嘅邊界。真正嘅漏洞（例如：無效 pack 被 import、journal 損壞被靜默吞、crash 後出假 ok receipt、budget 繞過）——請報告，我哋 fail-closed 哲學下呢啲全部係 bug。
