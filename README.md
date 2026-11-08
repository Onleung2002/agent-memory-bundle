# agent-memory-bundle — MBCP

> **MBCP = Memory Bundle Conformance Profile** — 一個 UMP-compatible 嘅中立 conformance profile + 可執行測試套件 + 刪除可證（GDPR Art.17）evidence tooling + importers。
> 我哋唔造記憶格式，唔造 agent runtime——我哋做**考官**。

## 權威性聲明（"not a vendor format"）

- 本 spec 唔重複定義 UMP（Universal Memory Protocol）；本 spec 係 **UMP 之上嘅 conformance profile**，補足 UMP 未定義嘅三個窿：①跨 bundle deterministic load budget／合併語意 ②刪除可證（proof-of-reach，唔只係 tombstone flag）③可重跑嘅中立測試套件。
- 與 Agent Skills（progressive disclosure）嘅關係：skills 管 per-repo 漸進載入；MBCP 管**跨 bundle** 嘅載入裁決。兩者互補唔重疊。
- 本 project 無 vendor 席位；governance 見 [GOVERNANCE.md](GOVERNANCE.md)。

## Quickstart

純 Python 3.11+ stdlib，零第三方依賴：

```bash
git clone https://github.com/Onleung2002/agent-memory-bundle.git
cd agent-memory-bundle
python3 tools/run_tests.py         # 194 unit tests
python3 tools/run_scenarios.py     # 18 conformance scenarios
```

- 讀 [SPEC.md](SPEC.md)——尤其 §1（語意裁決）、§3a（公開 API 契約：`load` / `import_bundle` / `canonical_bytes`）。
- 對住 `tests/scenarios/*.yaml` 寫你自己嘅實作（**唔參考 `mbcp/` 源碼**——conformance 嘅意義在於獨立實作）。
- 提交 implementation report 入 conformance registry；流程見 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 現狀（v0.1，未凍結）

- ✅ M1：bundle schema + canonical + deterministic load/merge
- ✅ M2：ChatGPT/Hermes importers + L1 刪除服務（tombstone-first、crash recovery、truthful receipts）
- ✅ M3：SPEC 精確化（31 條歧義閂）+ L2 跨 root propagation（pack/ack/journal）+ receipt supersession chain
- ⏳ M4：L4 簽名（ed25519）、conformance registry、handover 完整流
- Milestone 詳情：[docs/MILESTONE_M2.md](docs/MILESTONE_M2.md)、[docs/MILESTONE_M3.md](docs/MILESTONE_M3.md)

## 誠實嘅限制（讀完先用）

- 本 project 嘅 artifact（receipt、pack、ack）目前提供 **digest-chain integrity only**——無簽名前，tamper-evidence 建基於 root writer 自己唔偽造，**唔係防偽保證**（L4 ed25519 進行中，見 [SECURITY.md](SECURITY.md)）。
- 「刪除可證」係 machine-checkable 收據語意，唔係法律意見；GDPR Art.17 適用性由你嘅 DPO/律師判斷。
- Machine unlearning（runtime 記憶體、衍生快取、模型權重）唔喺本 spec 範圍（SPEC §5）。

## Kill Criteria（寫死；CI 依此判 GO/NO-GO）

1. 12 個月內 **<2 個非自家 producer** 通過 L0 round-trip → 格式前提不成立，轉純 importer/刪除取證工具（退路本身有價）。
2. 任何主流 runtime 開放原生 state export 或 MCP 加 memory primitive → 放棄格式所有權，轉 migration/evidence 層。
3. CSA 出 memory supplement / Vanta 出 MEM test pack → 轉做其 verifier 網絡或「刪除取證」深水 niche。
4. 2028 年 <15 付費 logo 且 ACV <$40k → 商業模型不成立。

## 開發紀律

- Test-first：未過測試唔算完成；**test-count guard**——任何 commit 令測試數目下跌而無對應 spec 修訂 = CI fail。
- 每季用「故意失敗 candidate」驗證個 gate 真會 fail（防 skipped/neutral check 假綠）。
- Fixtures 只用 synthetic/公開 corpus——本 project 講 consent，唔可以自己漏 PII。
- Spec 保持 v0.1 直至 **≥2 個獨立實作**通過同一 suite 先凍結。
