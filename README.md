# agent-memory-bundle — MBCP

> **MBCP = Memory Bundle Conformance Profile** — 一個 UMP-compatible 嘅中立 conformance profile + 可執行測試套件 + 刪除可證（GDPR Art.17）evidence tooling + importers。
> 我哋唔造記憶格式，唔造 agent runtime——我哋做**考官**。

## 權威性聲明（"not a vendor format"）

- 本 spec 唔重複定義 UMP（Universal Memory Protocol）；本 spec 係 **UMP 之上嘅 conformance profile**，補足 UMP 未定義嘅三個窿：①跨 bundle deterministic load budget／合併語意 ②刪除可證（proof-of-reach，唔只係 tombstone flag）③可重跑嘅中立測試套件。
- 與 Agent Skills（progressive disclosure）嘅關係：skills 管 per-repo 漸進載入；MBCP 管**跨 bundle** 嘅載入裁決。兩者互補唔重疊。
- 本 project 無 vendor 席位；governance 見 [GOVERNANCE.md](GOVERNANCE.md)。

## 角色分工（execution architecture v2）

| 角色 | 誰 | 權限 |
|---|---|---|
| SSOT | 本 repo（CI = gatekeeper） | 唯一真話來源 |
| Worker | OpenCode/Claude Code（Kimi K3 核心 + GLM Pro bulk） | 寫碼喺 per-task worktree；**唔准 push main** |
| Independent Verifier | GLM（另一模型家族，fresh context） | read-only：verdict + failing test + 拒收理由 |
| Controller | Hermes `memory_bundle` profile | triage/watch/匯報；**冇 requirement 權、唔寫碼** |

## Kill Criteria（寫死；CI 依此判 GO/NO-GO）

1. 12 個月內 **<2 個非自家 producer** 通過 L0 round-trip → 格式前提不成立，轉純 importer/刪除取證工具（退路本身有價）。
2. 任何主流 runtime 開放原生 state export 或 MCP 加 memory primitive → 放棄格式所有權，轉 migration/evidence 層。
3. CSA 出 memory supplement / Vanta 出 MEM test pack → 轉做其 verifier 網絡或「刪除取證」深水 niche。
4. 2028 年 <15 付費 logo 且 ACV <$40k → 商業模型不成立。

## Drift 警報（俾任何 agent/人望住嘅紅線）

> **任何時候發現自己喺度寫 agent loop / skill runner / cron scheduler / chatbot plumbing——即刻停。你已經 drift 咗入 agent runtime 地盤。** 正確位置：bundle schema、importer/exporter、conformance suite、合規證據、registry。

## 開發紀律

- Test-first：未過測試唔算完成；**test-count guard**——任何 commit 令測試數目下跌而無對應 spec 修訂 = CI fail。
- 每季用「故意失敗 candidate」驗證個 gate 真會 fail（防 skipped/neutral check 假綠）。
- Fixtures 只用 synthetic/公開 corpus——本 project 講 consent，唔可以自己漏 PII。
- Spec 保持 v0.1 直至 **≥2 個獨立實作**通過同一 suite 先凍結。

## 相關研究（父庫 knowledge_base profile）

- `research_notes/business_case_mbcp_2026-11-05.md` — 7 thesis（Monitor 已審）
- `research_notes/execution_architecture_v2_2026-11-05.md` — 四角色架構
- `research_notes/agent_runtime_memory_portability_2026-11-05.md` — 格式 teardown
