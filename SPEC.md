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
- **預算消耗順序**：同 class 內 records 按以下順序消耗預算：priority class（critical > standard > opportunistic）→ manifest 排序 key `(bundle.id, canonical SHA-256)` → bundle 內出現位置。同 class 嘅所有喺選拔中存活嘅 records 一齊排隊，唔分 bundle。
- **`max_chars` 單位**：Unicode code points（Unicode scalar values）——唔係 UTF-8 bytes，唔係 UTF-16 code units。截斷同預算計量同用此單位（對 CJK 內容同 ASCII 有同一語意）。

### 1.2 刪除可證（tombstone + proof-of-reach）
- tombstone = monotonic record：target id、timestamp、reason、衍生 artifact 清單（facts/edges/chunks/embedding-cache keys）。
- Importers MUST tombstone-first（先刪後加），令 stale bundle 不能復活已刪內容。
- **Load path 同樣 enforce**：`load()` 必先收集所有 input bundles 嘅 tombstones，任何被 target 嘅 record 唔會出現喺結果——stale bundle 喺 load 階段都唔可以復活已刪內容。`lifecycle: "deleted"` 嘅 records 同樣被 filter（`archived` 保留）。
- **`lifecycle: "deleted"` 係 id-wide 刪除訊號**（v0.1 precision pass 收緊）：load path 對 `lifecycle:"deleted"` 嘅處理同 tombstone 同等——凡任何 input bundle 入面存在 `lifecycle:"deleted"` 嘅 copy，該 id 喺**所有** bundles 嘅 active copies 都唔會載入（唔止嗰個 copy 本身）。收緊理由：per-record filter 令「同 id 另一 bundle active」成為復活路徑。`archived` 唔係刪除訊號；被 deleted id 嘅 archived copies 一樣被排除，同 tombstone。
- **Tombstone dedupe**：同一 `target_id` 多個 tombstones → `deleted_at`/`reason` 取最新者，但 `derived_artifacts` 取**全部 copies 嘅 sorted UNION**（L3 證據唔可以因 merge 而縮水）。
- **`deleted_at` 比較**：dedupe 嘅新舊判斷按 RFC3339 instant（timezone-aware datetime）比較，唔係字串比較——`2026-06-01T00:00:00+08:00` 晚於同刻嘅 `Z` 表示。無法 parse 嘅 `deleted_at` → `LoadValidationError`。
- **Dedupe tie**：多個 tombstone `deleted_at` 相同時，canonical SHA-256 最大者勝（order-independent，同 manifest 排序嘅 content-digest tiebreak 原則一致）。
- **寫入邊界同樣 enforce（v0.1 audit 收緊）**：`put_bundle`/`import_bundle` 對任何 `(id, integrity.digest)` 已被 tombstone journal 針對嘅 record copy **拒收**（typed error）——復活後門喺 ingest path 封死，「cannot resurrect」唔止係 load path 契約，亦係寫入契約。
- **`lifecycle: "deleted"` 訊號嘅 integrity 前提（v0.1 audit 收緊，取代早前「signal survives digest-drop」讀法）**：id-wide 刪除訊號只由**通過 integrity digest 驗證**嘅 `lifecycle:"deleted"` copy 產生；digest 驗證失敗嘅 copy 唔產生訊號（fail-closed 方向改為「刪除訊號必須 authentic」——未認證刪除通道收緊，audit §10）。
- **Duplicate tiebreak（v0.1 audit 收緊）**：同一 id 多個 active copies 而無 merge mode 宣告時，winner = **canonical SHA-256 較大者**（order-independent，同 manifest 排序/tombstone dedupe 嘅 content-digest tiebreak 同一哲學）；取代「bundle id 字典序 first-wins」（attacker 可揀 bundle 名令 stale copy 勝出）。merge mode 宣告仍優先於 tiebreak。
- **Import 對 store 嘅刪除**：`import_bundle` 嘅 tombstone-first「先刪後加」涵蓋兩邊——store 既有 records 中任何被（store 或 incoming）tombstone 針對嘅 id 一併移除，incoming records 先加入。跨 root propagation 嘅正確性建喺呢個語意上。
- 刪除等級 L1–L4：
  - L1 bundle 內刪除（本 bundle 再無該記錄）
  - L2 跨 bundle propagation（所有引用 bundle 均收 tombstone）
  - L3 衍生工件清除證明（derived artifacts 清單全數勾銷）
  - L4 回執（erasure receipt：可交俾第三者驗證「刪除已發生」）

### 1.2.1 L1 已知限制（v0.1）
L1 receipt 係 immutable artifact——`recover()` 移除咗 receipt 未報告嘅 digest 之後，該 target 嘅在冇 receipt 永遠無法通過 `verify_receipt`（fail-closed，唔會出假 ok），且冇 re-issuance/healing path；re-issuance 語意（supersession）與 L2 跨 bundle propagation 一併設計。


### 1.2.2 Receipt supersession（v0.1）
`deletion-receipt.v0` 加 optional `supersedes`（被取代 receipt 嘅 `receipt_digest`，hex64）。Supersession 只有一個觸發位：`delete()` retry 喺 under-report 狀態（`verify_receipt ok:false` 因 evidence/recovery 增長）自動 re-issue 新 receipt 並指向舊 receipt。`verify_receipt` 對 superseded receipt：chain 完整（每個 supersedes 指向真實存在且 digest 相符嘅 receipt）而 chain 尾 receipt accounting 覆蓋全部已知 removal → `ok:true`；chain 斷裂（指向唔存在/mismatch 嘅 receipt）→ `ok:false`。Receipt 仍然 immutable——re-issue 係寫新 receipt，唔係改舊 receipt。

### 1.3 consent 繼承（UMP）+ 跨 profile 一致
UMP `consent{retention, exportable, redact}` 原樣繼承；MBCP 額外要求：consent 違反 = conformance fail（唔係 warning）。

### 1.4 Canonicalization：只 normalize 結構，唔 normalize 值
- Canonical form 保證：object keys 遞歸排序（UTF-8 code point byte order）、無多餘 whitespace、拒 NaN/Infinity。
- **值原樣保留（verbatim）**：user strings——包括 RFC3339 timestamps 嘅 sub-second precision 同 UTC offset——一律唔改寫。Canonicalization 只 normalize **結構**；`json.loads(canonical_bytes(x)) == x` 對所有 conforming values 成立（parse-back equality，有測試）。Timestamp 改寫會摧毀事件次序資訊，屬 lossy，禁止。
- **字串編碼**：canonical JSON 直接輸出 UTF-8 字元（`ensure_ascii=false` 語意），非 ASCII 字元唔做 `\uXXXX` escape。兩種編碼都係合法 JSON 但 digest 唔同——跨實作 digest 對帳（L2/L4）以本句為準。
- Manifest 排序嘅 content-digest tiebreak 用呢個 canonical form 嘅 SHA-256。
### 1.5 Load-time validation（SC-SCHEMA）
`load()` 對 input 做**結構性**驗證：
- **Unknown extra fields → passthrough retained**（P3 unknown-field retention）：record 任何額外欄位原樣保留喺輸出。
- **Malformed structure → `LoadValidationError`**（唔係 KeyError/TypeError）：缺 required fields、類型錯、enum 值唔合法、`integrity.digest` 唔係 64 位小寫 hex，一律 reject。
- **Build path manifest 必填**：`build_bundle`/`validate_bundle`（build path）要求 manifest 帶齊 `bundle`、`mbcp_version`、`records`、`tombstones` 四個 keys（缺 key = build-path error；空 array 合法）。Load path 保持 tolerant reader（缺 key 容忍成空 list，P3）——不對稱係明文設計，唔係遺漏。
- **`load_policy.max_chars` 最少 1（v0.1 audit 收緊）**：0 會清零整個 priority class（一條 hostile record 靜默滅掉所有 critical 記憶，availability 攻擊面）。Build path 拒收 0/負值；load path 同樣拒收（`LoadValidationError`）——兩邊都堵，唔靠 producer 自律。
- **Id grammar（v0.1 audit 收緊，涵蓋 record id）**：`record.id` 與 `bundle.id` 同一 grammar——record `^[A-Za-z0-9._:-]{1,128}$`（bundle 64：`^[A-Za-z0-9._-]{1,64}$`；`..` 拒收）。**`:` 明文合法（v0.1 裁定）**：importer namespace prefix（`chatgpt:<conv-id>`、`hermes-sess:<id>`）係來源標識內嵌 id 嘅正確形狀；`:` 無 traversal/NFC/filename 風險（record id 唔會變檔名）。**所有 id 比對前先 Unicode NFC normalize**（tombstone `target_id` vs record id、duplicate resolution）——NFD 變體唔可以繞過 tombstone filter；id 儲存仍然 verbatim（normalize 係比對語意，唔係改寫）。大小寫變體（`Rec-1` vs `rec-1`）grammar 仍然容許、NFC 唔處理——已知殘餘，記 BACKLOG。
- 嚴格 schema validation（`additionalProperties: false`）只用於 **build path**（`build_bundle`/`validate_*`）；load path 係 tolerant reader。

### 1.6 Integrity digest（SC-INT）
- `load()` 驗證每個 record 嘅 `integrity.digest`（SHA-256 of canonical body）；**digest 唔 match → 該 record 被 drop**（唔會原樣載入）。
- `truncate_last` 截斷 body 之後：re-digest（digest 改為 truncated body 嘅 SHA-256）**兼 mark** `integrity.truncated = true`。冇剩餘預算（或 body 非 string）→ 成個 record drop。（「body 非 string」分支喺 §1.5 驗證後不可達，保留為防禦性語意：若未來 load path 放寬驗證，非 string body 嘅行為係 drop 唔係 reject。）
- **截斷預算計量**：truncated record 消耗嘅係截斷後長度（即用晒該 class 剩餘預算）——預算計「收貨幾多」唔計「原本有幾多」，截斷後同 class 冇再有多 record 可以載入。
- v0.1 digest-drop 為靜默；v0.2 起 `load()` 回傳值附 dropped-ids 通道（見 §3a）。

## 2. Conformance 等級（MBCP 層）

> **v0.1 audit 收緊註記（2026-11-08，Isaac 批準）**：propagation pack 嘅 `pack_digest` 計入 `source_root`（唔只 tombstone digest list）——唔同 source root 嘅同一 tombstone set 係唔同 pack、唔可以撞同一 ack（audit §7）。schema `propagation-pack.v0` 同步。

| 級 | 要求 |
|---|---|
| P0 | UMP L0（parse/emit）+ 本 spec load_policy 忠實執行（deterministic round-trip） |
| P1 | P0 + tombstone-first import + L1/L2 刪除 |
| P2 | P1 + L3/L4（proof-of-reach + erasure receipt）= **badge 級**（刪除傳播係用戶同 regulator 真正會測嘅保證） |
| P3 | P2 + meta-validation（unknown-field retention）+ cross-bundle conflict fixtures 全過 |

## 3. 測試套件（suite 即產品）

- Scenarios versioned（`tests/scenarios/*.yaml`）；每個 scenario：input bundles → deterministic expected outcome。檔案係 YAML 1.2 嘅 JSON syntax 子集（JSON ⊂ YAML 1.2），令 runner 保持純 stdlib。
- Runner（`tools/run_scenarios.py`）**只用 public API**（`mbcp.load` / `mbcp.import_bundle` / `mbcp.canonical_bytes`），無 white-box imports；對任何 conforming 實作可雙向重跑；輸出 per-implementation report（fail set + scenario IDs）。
- **Scenario expect 比對語意**（每個欄位嘅 compare mode 喺 scenario 檔明文，唔接受隱式約定）：
  - `record_ids`：精確有序比對（list equality）。
  - `bodies`：按 id 對照；每個 id 嘅 body 精確相等。
  - `digests_valid: true`：所有輸出 records 嘅 `integrity.digest` == SHA-256(canonical(輸出 body))（截斷 re-digest 後）。
  - `digests`：per-id 精確 digest 比對——`{id: hex}`，每個列出 id 嘅輸出 `integrity.digest` 必須逐字元相等（load-03 用此鎖死 raw-UTF8 canonical bytes）。
  - `truncated`：精確有序比對。
  - `tombstones`：**只比對 scenario 檔明文 `compare:` 欄位清單入面嘅 keys**（例如 `compare: ["target_id","reason","derived_artifacts"]`）——未被列嘅 keys 唔比對。
  - 未喺 expect 出現嘅欄位一律唔比對。
- **Test-count guard**（`tools/test_count_guard.sh`）：count 全部測試 = `tests/test_*.py` 嘅 `def test_` 數目 + `tests/scenarios/*.yaml` 檔案數；任何 ref 之間數目下跌而無 spec 修訂 = CI fail。`--self-test` 用 `fixtures/deliberate_violation/` 整一個刪咗測試嘅 doctored tree，證明個 gate 真係會 fail（防假綠）。
- 品質指標：雙模型 fail-set 重疊度（Kimi K3 生成 / GLM 獨立驗證）；重疊 = 盲區警報。

### §3a 公開 API 契約（cross-implementation contract）

跨實作契約只有三個函數；其餘（build-path helpers）唔屬契約，各實作自由。

- `load(bundles) -> list[record]`：輸入 manifest dict list；回傳 record dict list——records verbatim（unknown fields 保留）、截斷已套用、順序 deterministic（§1.1）；結構錯 → `LoadValidationError`；merge 衝突 → `MergeConflict`；budget error → `BudgetExceeded`。
- `import_bundle(store, bundle) -> {"records": [...], "tombstones": [...]}`：回傳**新**狀態 dict，唔 mutate `store` 或 `bundle`；store 係同結構 dict。
- `canonical_bytes(value) -> bytes`；`canonical_sha256(value) -> str`（canonical bytes 之 SHA-256 hex，小寫）。
- Scenario runner（`tools/run_scenarios.py` 同任何第三方 runner）只可以用呢三個函數對 inputs 做裁決；expect 比對語意見上節。

## 4. Importers（分銷 wedge，唔算 conformance 證據）

首三 target：ChatGPT export、Claude `/memories`、Letta `.af`。之後：Hermes profiles（內部工具）、Mem0 dump、純 Markdown/AGENTS.md 樹。
要求：每個 importer 附 sensitivity 標記；無 consent 欄位嘅來源 → import 時打 `consent: {exportable: false}` 預設。

## 5. Non-goals

新 JSON envelope、新 protocol、agent runtime、vector DB、一般 GRC、托管多租戶 SaaS（第一年）、自稱 certification（見 GOVERNANCE.md）。
