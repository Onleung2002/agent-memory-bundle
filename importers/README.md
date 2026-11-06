# Importers (M2) — 每個 importer 附 sensitivity 標記；來源無 consent 欄位 → 預設 `consent.exportable=false`

Importers 係分銷 wedge，**唔算** conformance 證據（SPEC §4）。每個 importer 係
stateless parser：輸入原生 export，輸出一個 schema-valid MBCP bundle；刪除語意交由
`mbcp.import_bundle`（tombstone-first）執行。

| importer | 來源格式 | `provenance.sensitivity` | consent 預設 |
|---|---|---|---|
| `chatgpt.py` | ChatGPT 「Export data」→ `conversations.json` | `sensitive` | `exportable: false` |
| `hermes.py` | Hermes profile dir（`memories/*.md` §-delimited + `sessions/*.json(l)` + `profile.yaml`） | `sensitive` | `exportable: false` |

Sensitivity 詞彙（Isaac 裁決 2026-11-06，BACKLOG M2 #6）**精確係**
`{public, internal, sensitive, secret}`，由 `schemas/bundle-record.v0.json` 嘅 enum
喺 build path 執行。兩個 importer 都用 `sensitive` 做保護性預設（chatgpt =
user-authored consumer export 內容；hermes = local agent state，包括 private
memories）——永遠唔會預設 `public`。Machine-checkable invariant：
`sensitivity="secret"` 同 `consent.exportable=true` 一齊出現會喺 build path 被拒
（`importers/_common.py::check_sensitivity_invariant`）。

## Usage

```python
from importers import chatgpt, hermes
from mbcp import L1DeletionService

service = L1DeletionService("/srv/mbcp-store")
bundle = chatgpt.build_import_bundle(
    "export/",                 # dir containing conversations.json, or the file
    owner="user-123",
    imported_at="2026-11-06T00:00:00Z",
    tombstones=service.all_tombstones(),      # ← REQUIRED，唔准省略
)
manifest = hermes.build_import_bundle(
    "~/profiles/demo",
    owner="user-123",
    default_created="2026-11-06T00:00:00Z",   # markdown has no timestamps
    tombstones=service.all_tombstones(),      # ← REQUIRED，唔准省略
)
```

`parse_export` / `parse_profile` 回傳 sorted record list（唔使 tombstones，因為佢哋
只 parse，唔 build bundle）；`build_import_bundle` 額外包成 manifest，**tombstones
係 required keyword argument**，省略會即刻 TypeError；`import_export` /
`import_profile` 直接 import 入 store（tombstones 經 kwargs 透傳，同樣 required）。

## Tombstone-first wiring (必要，而家係強制)

Importer 唔知邊啲記錄已被刪——所以**每次 re-import 都要帶 deletion service 嘅
tombstones**，否則 stale export 會復活已刪記錄（`tests/test_m2_integration.py`
有 contract test 證明呢點）：

```python
bundle = chatgpt.build_import_bundle(
    "export/", owner="user-123",
    tombstones=service.all_tombstones(),        # ← 關鍵；省略即 TypeError
)
store = import_bundle(store, bundle)            # delete 先行，add 後行
```

## Determinism / id stability

- ChatGPT record id = `chatgpt:<conversation_id>`；transcript 沿 `current_node`
  branch 由 root 排起，branch 缺失時 fallback 到 `(create_time, node id)` 排序，
  所以 mapping dict 次序不影響輸出。
- Hermes memory record id = content-addressed
  `hermes-mem-<sha256(profile, file, entry)[:16]>`——entry 重新排序/搬 profile
  目錄都唔會改變 id，tombstone 仍然命中。重複 entry 會 dedupe 成一條。
- 兩個 importer 都唔會改寫已存在嘅 RFC3339 字串（verbatim passthrough）；epoch
  數字轉 UTC RFC3339 並保留 sub-second precision。ChatGPT
  `system`/`tool`/`function`、Hermes `system`/`tool` 訊息會丟棄（平台
  scaffolding，唔係 user memory）。

## 已知限制（honest scope）

- Hermes markdown 無 timestamp → memory entry 用 `default_created`（呼叫者提供，
  通常係 import 時間）。Sessions 有自己 timestamp。
- ChatGPT export 無 consent 欄位 → 一律 `exportable: false`；唔會猜測授權。
- 呢兩個 importer 只覆蓋 SPEC §4 首三個 target 其中兩個（ChatGPT、Hermes）；
  Claude `/memories`、Letta `.af` 未做。
- 刪除只做到 L1（bundle 內）；L2–L4 見 `mbcp/deletion.py` 嘅 receipt
  `limitations`，唔可以當 L4 erasure certificate 用。

## Tests

```bash
python3 tools/run_tests.py        # includes test_importer_chatgpt / _hermes / _deletion_l1 / _m2_integration
python3 tools/run_scenarios.py
```
