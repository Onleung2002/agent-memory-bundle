# Security Policy

## 支援版本

- `main`（head）： actively maintained。
- 舊 milestone tag：best-effort。

## 報告漏洞

**唔好開 public issue。** email project maintainer（見 GOVERNANCE.md / repo owner），72 小時內確認、修復 timeline 視乎嚴重度。

## 誠實嘅威脅模型（請先讀，多數「發現」其實係已披露嘅設計邊界）

MBCP 嘅 artifact（deletion receipt、propagation pack、ack）而家有 **L4 ed25519 簽名**（receipt envelope + pack level，per-root keypair，private key `.mbcp.key` 0600）：簽名驗證 fail-closed，偽造 / 篡改 / 錯 key 全 typed reject。以下係簽名**仍然唔提供**嘅嘢（一字唔美化）：

1. **簽名防局部篡改，唔防全 root compromise**：private key 同 store 同 root——任何可以讀寫整個 root 嘅人（root writer / filesystem 權限者）可以攞到 key 並簽出自洽嘅 receipt / pack / ack。簽名嘅保證係「喺 key 唔被攻破嘅前提下，artifact 內容唔可以被局部改寫或偽造」；key_id fingerprint binding 令偷換 key 會被偵測，但 key 本身被偷 = 邊界內。呢個係已披露嘅 L1-L4 信任模型，唔係防偽承諾。
2. **Receipt「刪除證明」唔係第三方可驗證 erasure certificate**：第三方驗證需要 out-of-band pubkey anchor（conformance registry record / export 內 pubkey 欄）——簽名本身唔提供 trust root。GOVERNANCE 原則 2 適用：呢個唔係 certificate，係 cryptographically-signed attestation。
3. **跨 root propagation intake 係 fail-closed authorization**：無 authorized-source accept-list = typed reject 所有 pack（無 unverified tier）；但 accept-list 嘅配置係 operator 責任——錯配（例如誤列錯誤嘅 key）唔會被系統偵測。
4. **Machine unlearning 邊界**：tombstone/receipt 證明「bundle 層已刪」；runtime 記憶體、衍生快取、模型權重內容嘅實際抹除唔喺本 spec 範圍（SPEC §5 non-goals + RFC UC4）。
5. **歷史版本**：L4 落地（Round B）之前嘅 receipt/pack 係 digest-chain only、無簽名；舊 artifact 對新版 schema/驗證 fail-closed 拒收。

以上唔係漏洞，係 spec 明文嘅邊界。真正嘅漏洞（例如：無效 pack 被 import、journal 損壞被靜默吞、crash 後出假 ok receipt、budget 繞過、malleable signature 被 accept）——請報告，我哋 fail-closed 哲學下呢啲全部係 bug。
