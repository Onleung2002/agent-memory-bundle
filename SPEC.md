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

### 1.2.3 Root lock（v0.1 audit 收緊：§3 racing writers）

> All mutations of a service root by `delete()`, `recover()`, and propagation intake are serialized under a
> bounded re-entrant advisory lock (`flock LOCK_EX` on `<root>/.mbcp.lock`; `lock_timeout`, default 10 s;
> expiry raises the typed `LockTimeoutError`). This is a serialization/liveness guarantee among cooperating
> writers, NOT a security boundary: the lock is advisory, the OS releases it if a holder crashes, and removing
> the lock file while held voids cross-process exclusion. Same-process re-entrancy (nested locked calls on one
> thread) is enforced by a per-root owner plus condition variable with a per-thread held count, and never
> self-deadlocks. `put_bundle` and propagation export (`export_propagation_pack`) are also under the lock for their full
> duration (ADV-C2-3 closed 2026-11-10): a put can no longer land mid-delete (the born-inventory-divergent
> receipt hole) and an export cannot read the journal torn mid-delete. `record_pending_propagation` stays
> outside the lock by design — it appends one O_APPEND line (best-effort attempts audit, never consulted by
> `verify_receipt`); in-memory-only `import_bundle` needs no lock. Cross-process exclusion is pinned by a
> two-OS-process test (tests/test_flock_cross_process.py). Bundle-id 檔案定址（`get_bundle`/`delete` 嘅
> bundle_id handle→filename lookup）保持 verbatim——case-variant bundle id 係唔同檔案；fail-closed
> （unknown bundle typed error），唔係比對語意一部分。

### 1.2.4 Receipt store inventory（v0.1 audit 收緊：§13）

> Every deletion receipt records an `inventory` block: the sorted list of ALL bundle ids in the service root
> immediately before the deletion, and the canonical SHA-256 of that sorted list (order-independent by
> construction). `verify_receipt` always checks the block's internal consistency; a receipt without the block
> fails the revised schema (receipts issued before this revision are invalid — breaking by design).
> `verify_receipt(check_inventory=True)` additionally compares the recorded set to the store's CURRENT live id
> set (point-in-time reconciliation) and fails closed naming added and missing ids. The default remains OFF: a
> receipt is a historical record and store growth after issuance does not falsify it. A bare
> `build_receipt` call without store context records the EMPTY set; service-issued receipts always record the
> real pre-deletion set.

### 1.2.5 Recovery error split（v0.1 audit 收緊：A-2 closure）

> `recover()` never silently ignores a bundle manifest: genuinely unreadable entries (`OSError`/`KeyError` —
> directory-shaped, permissions, vanished) are skipped and counted in `last_recovery_skipped_unreadable`
> (reset at the start of each run); malformed content (`TypeError`/`ValueError`, including non-finite JSON
> constants) raises a typed `DeletionError` naming the file. The delete/verify scan is fail-closed: any
> unreadable manifest raises typed and is never treated as absent.

### 1.2.6 L4 cryptographic attestation（v0.1 Round B：ed25519 簽名）

> **簽乜（兩個 artifact）：**
> 1. **Deletion receipt envelope**：對 `{integrity, receipt}` canonical bytes 做 **ed25519** 簽名。Receipt 加 `attestation_sig`（hex128）+ `key_id` 欄位。`verify_receipt` 加 signature 驗證步——**fail-closed**：簽名缺失、簽名不符 key、或 envelope tampered，三式全部 typed reject（named problem，冇 silent downgrade）。
> 2. **Propagation pack**：pack-level 簽名，同一 root keypair；intake 驗簽先收——現有 attestation digest chain 之上加 signature 層。
>
> **Key 管理模型（Isaac 裁決 2026-11-10）：**
> - **Per-root keypair**：private key 檔案喺 service root 底（`.mbcp.key`，permissions 0600，dotfile 排除所有掃描/inventory，同 `.mbcp.lock` 同款）；public key 內嵌 receipt + 對應 `key_id`。
> - **Passphrase 保護唔做**（0600 就夠；passphrase 會令 unattended delete/recover flow 破功）。
> - **Key rotation 語意延後**（`key_id` 已預留；rotation 語意 G2 前定）。
> - **誠實威脅模型（一字唔准美化）**：private key 同 store 同 root——**store 被完全攻破等於 key 被攻破**；簽名防「局部篡改」（改 receipt/pack 內容、偽造第三者 receipt），唔防「全 root compromise」。第三方驗證需要 out-of-band pubkey anchor（conformance registry record 或 export 內 pubkey 欄）——呢個係 regulator 用例嘅正確路徑，簽名本身唔提供 trust root。
>
> **術語法照舊**：GOVERNANCE 原則 2 適用——簽名係 attestation 強化，唔產生 certificate/certified 狀態；升級路徑措辭 = self-declaration → verifier-attested → **cryptographically-signed**。
>
> **Round B hotfix 收緊（second audit，2026-11-11）：**
> - **Keypoint validation**：`authorize_source`/`load_keypair` 拒絕 small-order、identity、non-canonical encoding 嘅 pubkey（typed reject）——identity-pubkey 零私鑰偽造 primitive（W1）喺 accept-list 配置層封死。
> - **Key loss ≠ first use**：`ensure_keypair` 係 fail-closed——root 內已存在任何 receipt/journal 而私鑰檔缺失時，typed error 要求顯式 rotate；**唔准靜默重生命名新 identity**（W2——靜默重生會令 third-party verifier 靜默失去 chain tail）。
> - **Pending typed contract**：`retry_pending_propagation` 對所有 typed failure（包括 `DeletionError`）保證「失敗 → 新 pending line appended」契約；schema-invalid 但自洽簽名嘅 pack 喺 signed-only gate 就被拒；dead-lettered pack 唔可以經 `record_pending_propagation` 重新入隊（terminal 係真 terminal）。

### 1.2.7 Propagation intake authorization（v0.1 audit §5 收緊：fail-closed）

> Propagation intake **必須 fail-closed**：root 未配置 authorized-source accept-list 時，**typed reject 所有 pack**——唔設「accepted-unverified 照收」行為 tier。理由（Isaac 裁決 2026-11-10）：呢個係 §1.2「刪除訊號必須 authentic」（Round C Batch 1 §10 裁定）喺 L2 嘅直接延伸——unverified pack 可以觸發刪除，等於未認證刪除通道由 L2 重返，同成個 Round C 收緊方向自相矛盾。多 root 部署 config accept-list 係 conformance 正常要求。
> Accept-list 係 root config 檔（授權 source 嘅 `key_id` + pubkey）；verified/unverified 分級**只准喺 intake receipt 記錄層做觀測**（記 intake 等級），唔可以做行為 tier。

### 1.2.8 Pending retry semantics（v0.1 audit §15 收緊）

> Pending propagation entry 帶 retry 計數 + `next_attempt_at`；成功 ack 後移除；重複失敗超過上限進入**死信狀態**（typed visible，唔會無限 retry；唔會靜默放棄）。**Retry 只重發已簽名 pack**——未簽名 pack 唔進 pending 通道。

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
- **Id grammar（v0.1 audit 收緊，涵蓋 record id）**：`record.id` 與 `bundle.id` 同一 grammar——record `^[A-Za-z0-9._:-]{1,128}$`（bundle 64：`^[A-Za-z0-9._-]{1,64}$`；`..` 拒收）。**`:` 明文合法（v0.1 裁定）**：importer namespace prefix（`chatgpt:<conv-id>`、`hermes-sess:<id>`）係來源標識內嵌 id 嘅正確形狀；`:` 無 traversal/NFC/filename 風險（record id 唔會變檔名）。**所有 id 比對前先 Unicode NFC normalize + ASCII case-insensitive**（tombstone `target_id` vs record id、duplicate resolution、write boundary——grammar 只容 ASCII，case 變體係純 ASCII 問題；v0.1 Batch 3 裁定收埋 case 殘餘）；id 儲存仍然 verbatim（normalize/casefold 係比對語意，唔係改寫）。
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
