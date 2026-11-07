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

#### 載入裁決細則（v0.1 fix round 1，可測）
- **Class budget**：`max_chars` 係成個 priority class 嘅預算，唔係 per-record。有效 class budget = 該 class 所有入選 records 中嘅**最小** `max_chars`（最保守、與輸入順序無關），逐 record 累積消耗。任何 record 唔可以藉住自己報大數嚟繞過同 class 嘅細預算（no budget laundering）。
- **Mixed merge modes**（deterministic resolution）：同一 id 嘅 copies 中，任何一個 declare `error_on_conflict` → 即刻 `MergeConflict`；否則**全部** declare `append_last_wins` → 最後者勝；其餘情況（包括 first/last 混合）→ 最先者勝。
- **Duplicate bundle id tiebreak**：manifests 排序 key = `(bundle.id, canonical SHA-256 of manifest)`。相同 bundle id 嘅多個 manifest 以內容 digest 決勝負，結果與 input 順序完全無關。

### 1.2 刪除可證（tombstone + proof-of-reach）
- tombstone = monotonic record：target id、timestamp、reason、衍生 artifact 清單（facts/edges/chunks/embedding-cache keys）。
- Importers MUST tombstone-first（先刪後加），令 stale bundle 不能復活已刪內容。
- **Load path 同樣 enforce**：`load()` 必先收集所有 input bundles 嘅 tombstones，任何被 target 嘅 record 唔會出現喺結果——stale bundle 喺 load 階段都唔可以復活已刪內容。`lifecycle: "deleted"` 嘅 records 同樣被 filter（`archived` 保留）。
- **Tombstone dedupe**：同一 `target_id` 多個 tombstones → `deleted_at`/`reason` 取最新者，但 `derived_artifacts` 取**全部 copies 嘅 sorted UNION**（L3 證據唔可以因 merge 而縮水）。
- 刪除等級 L1–L4：
  - L1 bundle 內刪除（本 bundle 再無該記錄）
  - L2 跨 bundle propagation（所有引用 bundle 均收 tombstone）
  - L3 衍生工件清除證明（derived artifacts 清單全數勾銷）
  - L4 回執（erasure receipt：可交俾第三者驗證「刪除已發生」）

### 1.2.1 L1 已知限制（v0.1）
L1 receipt 係 immutable artifact——`recover()` 移除咗 receipt 未報告嘅 digest 之後，該 target 嘅在冇 receipt 永遠無法通過 `verify_receipt`（fail-closed，唔會出假 ok），且冇 re-issuance/healing path；re-issuance 語意（supersession）與 L2 跨 bundle propagation 一併設計。

### 1.3 consent 繼承（UMP）+ 跨 profile 一致
UMP `consent{retention, exportable, redact}` 原樣繼承；MBCP 額外要求：consent 違反 = conformance fail（唔係 warning）。

### 1.4 Canonicalization：只 normalize 結構，唔 normalize 值
- Canonical form 保證：object keys 遞歸排序（UTF-8 code point byte order）、無多餘 whitespace、拒 NaN/Infinity。
- **值原樣保留（verbatim）**：user strings——包括 RFC3339 timestamps 嘅 sub-second precision 同 UTC offset——一律唔改寫。Canonicalization 只 normalize **結構**；`json.loads(canonical_bytes(x)) == x` 對所有 conforming values 成立（parse-back equality，有測試）。Timestamp 改寫會摧毀事件次序資訊，屬 lossy，禁止。
- Manifest 排序嘅 content-digest tiebreak 用呢個 canonical form 嘅 SHA-256。

### 1.5 Load-time validation（SC-SCHEMA）
`load()` 對 input 做**結構性**驗證：
- **Unknown extra fields → passthrough retained**（P3 unknown-field retention）：record 任何額外欄位原樣保留喺輸出。
- **Malformed structure → `LoadValidationError`**（唔係 KeyError/TypeError）：缺 required fields、類型錯、enum 值唔合法、`integrity.digest` 唔係 64 位小寫 hex，一律 reject。
- 嚴格 schema validation（`additionalProperties: false`）只用於 **build path**（`build_bundle`/`validate_*`）；load path 係 tolerant reader。

### 1.6 Integrity digest（SC-INT）
- `load()` 驗證每個 record 嘅 `integrity.digest`（SHA-256 of canonical body）；**digest 唔 match → 該 record 被 drop**（唔會原樣載入）。
- `truncate_last` 截斷 body 之後：re-digest（digest 改為 truncated body 嘅 SHA-256）**兼 mark** `integrity.truncated = true`。冇剩餘預算（或 body 非 string）→ 成個 record drop。

## 2. Conformance 等級（MBCP 層）

| 級 | 要求 |
|---|---|
| P0 | UMP L0（parse/emit）+ 本 spec load_policy 忠實執行（deterministic round-trip） |
| P1 | P0 + tombstone-first import + L1/L2 刪除 |
| P2 | P1 + L3/L4（proof-of-reach + erasure receipt）= **badge 級**（刪除傳播係用戶同 regulator 真正會測嘅保證） |
| P3 | P2 + meta-validation（unknown-field retention）+ cross-bundle conflict fixtures 全過 |

## 3. 測試套件（suite 即產品）

- Scenarios versioned（`tests/scenarios/*.yaml`）；每個 scenario：input bundles → deterministic expected outcome。檔案係 YAML 1.2 嘅 JSON syntax 子集（JSON ⊂ YAML 1.2），令 runner 保持純 stdlib。
- Runner（`tools/run_scenarios.py`）**只用 public API**（`mbcp.load` / `mbcp.import_bundle` / `mbcp.canonical_bytes`），無 white-box imports；對任何 conforming 實作可雙向重跑；輸出 per-implementation report（fail set + scenario IDs）。
- **Test-count guard**（`tools/test_count_guard.sh`）：count 全部測試 = `tests/test_*.py` 嘅 `def test_` 數目 + `tests/scenarios/*.yaml` 檔案數；任何 ref 之間數目下跌而無 spec 修訂 = CI fail。`--self-test` 用 `fixtures/deliberate_violation/` 整一個刪咗測試嘅 doctored tree，證明個 gate 真係會 fail（防假綠）。
- 品質指標：雙模型 fail-set 重疊度（Kimi K3 生成 / GLM 獨立驗證）；重疊 = 盲區警報。

## 4. Importers（分銷 wedge，唔算 conformance 證據）

首三 target：ChatGPT export、Claude `/memories`、Letta `.af`。之後：Hermes profiles（內部工具）、Mem0 dump、純 Markdown/AGENTS.md 樹。
要求：每個 importer 附 sensitivity 標記；無 consent 欄位嘅來源 → import 時打 `consent: {exportable: false}` 預設。

## 5. Non-goals

新 JSON envelope、新 protocol、agent runtime、vector DB、一般 GRC、托管多租戶 SaaS（第一年）、自稱 certification（見 GOVERNANCE.md）。
