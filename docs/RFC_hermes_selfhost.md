# RFC: Hermes Self-Host Deployment — MBCP as the Memory Backend of the Hermes Profile System

**Status:** APPROVED — Isaac per-item ruling 2026-11-14 (B-Q1 to B-Q6 all approved as recommended, see §8 裁決欄). Design only, zero code.
**Date:** 2026-11-15
**Author:** controller (memory_bundle profile)
**Scope guard:** This deployment uses the MBCP library as-is. It modifies NO code under `mbcp/`. It is an internal deployment, not a library change.

---

## 1. 現狀基線（已核實）

- MBCP main @ 62451f0，M4 已收（suite 331u+24sc=355，CI green）。`mbcp/` API 已提供：`build_bundle` / `make_record` / `make_tombstone` / `L1DeletionService(root)`（`put_bundle` / `delete` / `recover`） / `export_propagation_pack` / `import_bundle`。
- 已核實的 API 形狀（本 RFC 引用前已逐一實跑確認）：
  - `make_record(record_id, kind, body, owner, *, source, created, lifecycle, retention, exportable, sensitivity, priority, max_chars, on_budget_exceed, merge)` — body 必須係 string（非 dict）；`sensitivity="secret"` + `exportable=True` 喺 build path 直接 ValueError（`check_sensitivity_invariant`）。
  - `build_bundle(bundle_id, records=(), tombstones=())` — 返回 manifest dict；`put_bundle(manifest)` 持 root advisory lock 原子落盤，tombstoned id 嘅 record copy 被 typed reject。
  - `L1DeletionService.delete(bundle_id, target_id, reason)` — 返回 receipt；idempotent；全 root 同 id 嘅 copy 都要清走先出 receipt。
  - `export_propagation_pack(root, target_ids=None)` — 出 tombstone journal 嘅 propagation pack（digest 綁 source_root + tombstone set）。
- Hermes profile 系統實況：`/opt/data/profiles/*/memories/` 每個 profile 有 `MEMORY.md`（+ `USER.md`）+ `.lock`。現有 8 個 profile：companystory_coo, controller, creativeco_coo, global_economist, interior_design, knowledge_base, memory_bundle, onemanco_coo, shirley-hr（共 9 個）。單個 MEMORY.md 現時 1–4KB。
- **Brief 與實況落差（必須裁決）**：brief 列嘅 profile 集 {knowledge_base, job_applicator, translator, global_economist, memory_bundle} — 當中 `job_applicator` 同 `translator` **喺磁碟上唔存在**；實際存在嘅 profile 集同 brief 唔同。見 §8 Q1。

---

## 2. 部署形態

**建議：cron 定期跑，一個 profile = 一個 MBCP service root，每個 profile 一個 bundle。**

- 執行者：Hermes profile 各自嘅 daily cron（或一個 dispatcher cron 遍歷所有 profile）。建議做法：**一個獨立 dispatcher cron job**（每 profile 一個 cron 會令 9 份 cron config 各自可 drift；dispatcher 讀 profile 清單單一來源）。Dispatcher 每日一次遍歷 profile 清單，逐個生成當日 bundle。
- Service root 位置：`/opt/data/profiles/<profile>/memory/mbcp_root/`（root 跟 profile 走，唔入 git；repo `agent-memory-bundle` 保持純 spec+suite，唔入運行數據）。備選：集中一個 `/opt/data/mbcp_roots/<profile>/`。見 §8 Q2。
- Root 初始化：`L1DeletionService(root)` 首次調用即建立 root；`ensure_keypair` 產 L4 signing key（root 自帶，無跨 root 依賴）。
- 讀路徑：Hermes profile 嘅 agent runtime 透過 `import_bundle` / `load` 由 MBCP root 讀返記憶。本 RFC 階段只定義「寫入側」；讀側（agent 開機時從 MBCP root 載入記憶）係實作階段 scope，設計上同 import_bundle 對接。

---

## 3. 資料來源邊界（硬規則）

**入 bundle 嘅只有一樣嘢：Hermes agent 已經寫入 `/opt/data/profiles/*/memories/` 嘅內容。** 明確排除：

1. **唔入 chat 原文**：任何 Telegram/chat 對話記錄、tool output、transcript 唔入 bundle。
2. **唔入個人 PII 紅線**：公司數據（LAV/奕橋、NLVC、家族辦公室客戶資料）唔入 AI — 已經喺入面嘅都唔會俾 bundle 增加暴露面。佢哋唔入 bundle。
3. **USER.md 建議排除**：`USER.md` 係 Isaac 個人 profile（姓名、職務、家庭、求職狀態）— 純個人 PII，唔係「記憶」。建議 bundle 只收 `MEMORY.md` 嘅內容。見 §8 Q3。
4. **來源自述**：每條 record `provenance.source = "hermes:<profile>"`，可追溯返邊個 profile 嘅邊段 MEMORY.md 內容。

---

## 4. 語意映射（MBCP 操作 ↔ Hermes 記憶操作）

| Hermes 記憶操作 | MBCP 操作 | 備註 |
|---|---|---|
| 記一筆（新 fact 入 MEMORY.md） | `make_record` + `build_bundle` + `L1DeletionService.put_bundle(manifest)` | record_id 由 profile+content hash 生成（建議 `rec:hermes:<profile>:<sha256[:12]>`，同 MBCP id grammar 對齊） |
| 改一筆（fact 文字更新） | 同上（新 record 進入）+ `delete(bundle_id, old_target_id, reason)` | MBCP 語意冇 in-place update；修改 = 舊 id tombstone + 新 id record。見 §8 Q4 |
| 刪除一筆（Isaac / agent 收回一個 fact） | `L1DeletionService.delete(bundle_id, target_id, reason)` | 真正 receipt；`export_propagation_pack` 可出 tombstone pack |
| 跨 root 刪除傳播 | `export_propagation_pack` + 對方 root `import_bundle` | 本用例：同一 fact 唔同 profile 之間冇共享 id（每個 profile 獨立 id），跨 root 傳播僅喺未來「同 fact 跨 profile」時適用。見 §8 Q5 |

**實際發生頻率**：Hermes profile 嘅日常操作係「add/modify」——`MEMORY.md` 係 append/patch 式。`delete` 事件（Isaac 明確要求收回一個 fact）低頻但存在。因此本部署嘅主流程 = put_bundle；delete 係低頻但必須真嘅（唔准 silent skip）。

---

## 5. 頻率與 journal 增長率

- **每日一次 bundle 生成**（每 profile 一個）。建議 cron 時間：每日 03:00（profile 活動低峰）。
- **journal 增長率估算**（基於 2026-11-15 實測）：
  - 9 個 profile，每個 MEMORY.md 現時 1–4KB。
  - 每個 profile 日常新增 1–3 個 fact/日。若每 fact = 1 record（~1KB body + metadata），每日 journal 增長 ≈ 9–27 records/日，約 10–30KB/日。
  - 一年 ≈ 3,000–10,000 records / 10–30MB。**唔使做 compaction**；MBCP journal 本身 append-only，無需清理。
  - Bundle 建議 = **增量**（只含當日新/修改嘅 records），唔係每日全量 snapshot（全量會令 journal 以 365×現有記憶量/年增長，無謂）。
- **journal 設計選擇**：每個 profile 一個 root（journal 獨立）→ 冇跨 profile journal 增長。見 §8 Q2。

---

## 6. 敏感度分層

| Profile | 內容性質 | 敏感度標記 | exportable |
|---|---|---|---|
| knowledge_base | 研究筆記、框架、business case（Isaac 決策過程中嘅知識） | `standard` | True |
| job_applicator（若存在） | 求職資料、職位描述、公司接觸 | `secret` | False（build path invariant：secret+exportable 直接 ValueError） |
| translator | 翻譯工作記憶 | `standard` | True |
| global_economist | 經濟研究筆記 | `standard` | True |
| memory_bundle | MBCP project 本身嘅 memory（controller 操作） | `standard` | True |
| 其餘 4 個（companystory_coo / creativeco_coo / onemanco_coo / interior_design / shirley-hr / controller） | 創作/營運/管理記憶 | `standard` | True |

**規則**：
- secret + exportable=True 喺 build path 直接被拒（`check_sensitivity_invariant`）— 這是機器檢查嘅 invariant，唔靠自覺。
- 求職資料類 profile 任何 record 均標 `sensitivity="secret"`，`exportable=False`，即係 bundle 內可見但唔會被 export_propagation_pack 傳出去。
- 呢條分層唔入 spec — 係部署層 config，唔改 MBCP library。

---

## 7. 失敗模式（fail-closed 通知）

**規則：cron miss 或 bundle build 失敗時唔會靜默 — 必須通知。**

1. **cron miss**：dispatcher 每日 03:00 起。若 06:00 前仍未見該 profile 當日 bundle manifest → 通知（Hermes profile 通知渠道 / Telegram）。
2. **bundle build 失敗**（schema validation fail、sensitivity invariant fail、root lock timeout）：`make_record`/`build_bundle`/`put_bundle` 任何 typed error → 不落盤、不 retry-overwrite、當日通知+log。
3. **通知格式**：明文「profile X: <date> bundle build failed — <error>」→ log 入 `/opt/data/profiles/<profile>/memory/mbcp_root/` 旁邊嘅 dispatcher log + Telegram 通知。唔好淨係 log。
4. **冇唔寫就唔記**：失敗唔會靜默變成「無 bundle」——必須對每個 profile 當日有明確「成功」或「失敗」記錄，唔好有灰區。

---

## 8. Open Questions（Isaac 裁決 2026-11-14，B-Q1 至 B-Q6 全部照建議批）

| # | 問題 | 建議 | 裁決 | 理由 |
|---|---|---|---|---|
| Q1 | **Profile 集範圍**：brief 列 {knowledge_base, job_applicator, translator, global_economist, memory_bundle}，實際磁碟係 9 個（job_applicator / translator 唔存在）。部署範圍係邊個：A) 5 個（brief 原列，缺 job_applicator/translator 則跳過）；B) 9 個（磁碟全部）；C) 磁碟全部 + 5 個 brief 列名嘅特別標記（job_applicator 將來出現時自動入 secret tier） | C（建議） | **批 C**。範圍 = 磁碟全部 9 個 profile；brief 名列 5 個做特別敏感度標記；job_applicator 將來出現時自動入 secret tier。Isaac 備註：job_applicator/translator 唔存在係 brief 筆誤，controller 捉得啱 | Brief 名列嘅 profile 有特別敏感度分層；磁碟全部 profile 都有記憶。缺嘅 profile 出現時自動入套 |
| Q2 | **Root 位置**：root 跟 profile（`/opt/data/profiles/<profile>/memory/mbcp_root/`）定集中一個目錄（`/opt/data/mbcp_roots/<profile>/`） | 跟 profile（建議） | **批**：`/opt/data/profiles/<profile>/memory/mbcp_root/` | 備份/遷移 profile 時 root 跟住走 |
| Q3 | **USER.md 建唔建入 bundle**：USER.md 係 Isaac 個人 profile（PII），建議排除，只收 MEMORY.md | 排除（建議） | **批**：排除 | USER.md 係人 PII，唔係「記憶」 |
| Q4 | **改動語意**：MBCP 冇 in-place update；改一筆 = tombstone 舊 id + 新 record。呢個語意接唔接受？ | 接受（建議） | **批**：append-only 語意 | tombstone + new record 係 append-only 原生語意，符合可審計 |
| Q5 | **跨 root 傳播**：export_propagation_pack 喺本用例實際用唔用？同 fact 跨 profile 係咪存在？ | 暫不使用（建議） | **批**：暫不使用 | 每個 profile 獨立 id，同 fact 唔共享 id；跨 root 傳播係未來 scope |
| Q6 | **Dispatcher 實現者**：design doc 是本 RFC；實作時 dispatcher cron script 係 worker 寫，定係 controller 做 | worker（Kimi core）寫 + verifier（GLM）實跑核實 | **批**：worker 寫，controller 唔寫 code | 照 milestone 鐵律：寫碼唔係 controller |

---

## 9. 誠實框架（承諾措辭）

- 本部署係 **internal deployment**：*internal daily use by the Hermes profile system*。唔准對外宣稱 production adoption。
- 若有對外故事，措辭係：*MBCP has an internal daily use by the Hermes profile system (self-hosted), not yet a public external adoption*。
- 唔准用 verification / verification-grade claim 之外嘅任何更高保護等級措辭。

---

## 10. 實作階段（Isaac 批准後）

- worker = Kimi core；verifier = GLM（唔同 model 家族）。
- 驗證要求（非白盒）：
  1. 實際跑一個 profile 嘅 bundle 生成一次，肉眼核實 bundle 結構正確。
  2. 對一個生成咗嘅 bundle 真係 `delete` 一筆 → 真係攞返 deletion receipt → 真係 `verify_receipt` 驗過。
  3. 每步都係真實操作，唔係白盒假綠。
- 誠實條款：internal deployment 措辭照 §9。

---

*Design only. No code in this commit. RFC commit message: `docs: RFC Hermes self-host deployment (design only)`.*
