# MBCP SPEC — v0.1（草案，凍結前）

> 狀態：v0.1 凍結條件未達（見 GOVERNANCE.md）。本檔係 profile 規範嘅骨架；實作細節以 schemas/ + tests/ 為準。

## 0. 與既有標準嘅關係

| 標準 | 關係 |
|---|---|
| UMP 0.1+ | **底座**。record shape（kind/body/scope/time/lifecycle/relations/provenance/consent/integrity）繼承 UMP；本 spec 唇 re-specify，只定義 profile-level 附加要求 |
| Agent Skills | 互補：skills = per-repo progressive disclosure；MBCP = 跨 bundle 載入裁決 |
| OWASP AISVS C08 | 語言接口：suite scenarios 直接 map 去 AISVS C08 requirement ID；並補 C08 未覆蓋嘅跨副本 erasure proof |

## 1. 差異化欄位（UMP 未定義，MBCP 新增）

### 1.1 `load_policy`（跨 bundle 載入裁決）
```yaml
load_policy:
  priority: critical | standard | opportunistic   # 跨 bundle 合併時嘅優先序
  max_chars: 4096                                  # 本 class 嘅載入預算
  on_budget_exceed: truncate_last | skip | error   # 超預算時嘅 deterministic 行為
  merge: append_first_wins | append_last_wins | error_on_conflict   # 跨 bundle 合併語意
```
要求（可測）：同一組 bundles + 同一 consumer 版本 → 載入結果 byte-deterministic。

### 1.2 刪除可證（tombstone + proof-of-reach）
- tombstone = monotonic record：target id、timestamp、reason、衍生 artifact 清單（facts/edges/chunks/embedding-cache keys）。
- Importers MUST tombstone-first（先刪後加），令 stale bundle 不能復活已刪內容。
- 刪除等級 L1–L4：
  - L1 bundle 內刪除（本 bundle 再無該記錄）
  - L2 跨 bundle propagation（所有引用 bundle 均收 tombstone）
  - L3 衍生工件清除證明（derived artifacts 清單全數勾銷）
  - L4 回執（erasure receipt：可交俾第三者驗證「刪除已發生」）

### 1.3 consent 繼承（UMP）+ 跨 profile 一致
UMP `consent{retention, exportable, redact}` 原樣繼承；MBCP 額外要求：consent 違反 = conformance fail（唔係 warning）。

## 2. Conformance 等級（MBCP 層）

| 級 | 要求 |
|---|---|
| P0 | UMP L0（parse/emit）+ 本 spec load_policy 忠實執行（deterministic round-trip） |
| P1 | P0 + tombstone-first import + L1/L2 刪除 |
| P2 | P1 + L3/L4（proof-of-reach + erasure receipt）= **badge 級**（刪除傳播係用戶同 regulator 真正會測嘅保證） |
| P3 | P2 + meta-validation（unknown-field retention）+ cross-bundle conflict fixtures 全過 |

## 3. 測試套件（suite 即產品）

- Scenarios versioned（`tests/scenarios/*.yaml`）；每個 scenario：input bundles → deterministic expected outcome。
- Runner 對任何 conforming 實作可雙向重跑；輸出 per-implementation report（fail set + scenario IDs）。
- 品質指標：雙模型 fail-set 重疊度（Kimi K3 生成 / GLM 獨立驗證）；重疊 = 盲區警報。

## 4. Importers（分銷 wedge，唔算 conformance 證據）

首三 target：ChatGPT export、Claude `/memories`、Letta `.af`。之後：Hermes profiles（內部工具）、Mem0 dump、純 Markdown/AGENTS.md 樹。
要求：每個 importer 附 sensitivity 標記；無 consent 欄位嘅來源 → import 時打 `consent: {exportable: false}` 預設。

## 5. Non-goals

新 JSON envelope、新 protocol、agent runtime、vector DB、一般 GRC、托管多租戶 SaaS（第一年）、自稱 certification（見 GOVERNANCE.md）。
