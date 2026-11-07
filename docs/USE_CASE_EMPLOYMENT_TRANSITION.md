# Use Case：就業過場（入職/離職）— Canonical Scenario for L2/L3/L4

**來源**：Isaac 2026-11-06 口述場景（產品第一個 real-world anchoring）。

## 場景

每人有多個 personal AI agent profiles（如：financial controller / private / research…）。

**入職**：求職者只選擇性交付一個 bundle（例如 FC profile）加入公司 AI agent——其他 profile 嘅資料唔應該進入公司 agent。交付範圍由個人決定（scope 選擇），公司 agent 受 consent 綁定（俾幾多、攞幾多）。

**離職**：
1. 個人帶走嘅 original bundle——本來就係個人嘅，冇「刪除」問題
2. 公司 agent 複製/吸收咗嘅副本（對話記錄、併入公司 memory 嘅 records）→ **L2**：刪除要跨 bundle 傳播到所有副本
3. 衍生嘢（agent 學識嘅 skills、summaries、embeddings）→ **L3**：derived artifacts 逐項記錄 + 逐項證明清除
4. 公司要向個人（或審計方）**證明**刪除完成 → **L4** erasure receipt

## Design acceptance questions（RFC L2/L4 部分必須回答）

1. Partial handover：scope 選擇機制點樣令「冇交付嘅 profile」**結構上**唔可能流入公司 bundle（唔係靠 caller 自覺）？
2. Cross-bundle propagation：離職刪除時，公司 agent 內部所有副本點樣被可靠觸及（proof-of-reach）？
3. Derived artifacts：skills/summaries/embeddings 嘅記錄邊界喺邊？receipt 嘅 `derived_artifacts_verified` 喺呢個場景下點判？
4. **Known limitation（必須聲明）**：吸收咗入 model weights 嘅 learned behavior 屬 machine unlearning 範圍，唔喺 MBCP 機械證明能力內——receipt 只覆蓋有 manifest/記錄嘅 artifact。

## 點解呢個場景係 canonical

- 一個場景同時逼出 L1（離職當下的 bundle 內刪除）、L2（副本傳播）、L3（衍生清除）、L4（可驗收條）四層
- 有監管味：就業個人資料 → PDPO/GDPR 應用場景，係審計師對話同 enterprise pitch 嘅第一頁故事
