# RFC: External Anchor Tool — MBCP receipt digest 嘅第三方 timestamp 錨定

狀態：**DRAFT — 待 Isaac 批准，批准前零新 code**
作者：controller（memory_bundle profile）；日期：2026-11-15
依據：Isaac 工作流 brief（2026-11-14）、SECURITY.md 誠實條款節、SPEC §1.2（supersession）、GOVERNANCE 原則 2（術語法）
術語註記：本文全篇遵守 GOVERNANCE 原則 2——唔用「certi-」族詞彙做任何 conformance 宣稱。RFC3161 協議內部會涉及 X.509 信任鏈文件，本文一律稱「TSA 信任鏈 / TSA 公鑰鏈」，係協議術語唔係能力宣稱。

---

## 0. 現狀基線

- M4 已收（main=76aef91，CI success）。deletion receipt 有 L4 ed25519 簽名（per-root keypair，`.mbcp.key` 0600），verify fail-closed。
- 已知誠實窿（SECURITY.md §16 已披露嘅延伸）：**receipt 體系係 self-referential**。所有驗證素材（journal、evidence、key）都住喺同一個 service root 入面。第三方想證明「呢張 receipt 喺某個時間點已經存在，而且之後無被改寫」，而家冇任何 out-of-band 出路——root writer 可以事後重造整套 artifact（甚至連簽名重簽，因為 key 同 root 同域）。
- SAIHM（draft-saihm-memory-protocol-03）用公鏈 audit log 解呢個問題。MBCP 嘅 P-A 對標定位（2026-11-14 裁決）係「portable cross-root deletion accountability」——第三方 timestamp 證據正正係呢個定位缺嘅嗰塊。
- 本工作位置：**root 旁邊嘅 artifact 層**，standalone 工具。唔入 `mbcp/` 核心。

## 1. Scope 邊界（硬約束）

呢個工具**唔做**以下任何一樣：

1. 唔改 `mbcp/` 任何檔案——零 import、零 monkey-patch、零 wrapper 改動
2. 唔改 receipt 格式（`deletion-receipt.v0` schema 不動，`supersedes` 語意不動）
3. 唔改 SPEC.md / GOVERNANCE.md / kill criteria（SSOT 唔受此工具影響）
4. 唔改 journal / tombstone / evidence 既有目錄結構
5. 唔改現有 verify path（`verify_receipt` 行為照舊）

工具只做三件事：**讀** receipt digest → **提交** RFC3161 TSA → **存** token 入 bundle root 新目錄，另加一條獨立驗證命令。佢係 MBCP 嘅 *consumer*，唔係 *component*。

檔案允許範圍（實作階段建議）：新目錄 `anchor/`（standalone 腳本，stdlib-only 延續 repo 哲學；RFC3161 提交用 stdlib 可實現——TimestampRequest 結構簡單，驗證交 openssl 外部命令）。`tests/`、`tools/` 照常可以加 test。

## 2. 提交對象：兩條路嘅 trade-off

### 路線 A：RFC3161 公共 TSA（建議主路）

用 stdlib 構造 Time-Stamp Request（SHA-256 digest of receipt canonical bytes），POST 俾公共 TSA（例：freetsa.org，免費、無需帳號），收返 RFC3161 token（DER 編碼），本地存檔。

- **優點**：信任根喺 MBCP 信任域**之外**——第三方只需要 openssl + TSA 公鑰鏈就可以獨立驗證，唔需要信 MBCP 任何 code；時間來源係 TSA 嘅時鐘，唔係 root 本地時鐘（直接補 §0 嘅時鐘信任窿）；零成本、零帳號、零基礎設施。
- **缺點**：①依賴第三方可用性（見 §6 失敗模式）；②公共 TSA 嘅長期存續唔受我哋控制——token 驗證需要 TSA 信任鏈，若 TSA 日後消失/換 key，舊 token 驗證會斷（要存低當時嘅 TSA 公鑰鏈 snapshot 一齊入 evidence，見 §4）；③免費公共 TSA 無 SLA，唔可以攞嚟做任何法律級宣稱（呢點本來就唔喺誠實條款範圍內，見 §5）。
- **建議**：freetsa.org 做預設 endpoint，endpoint 做 config 可換（唔寫死）。

### 路線 B：本地 Merkle transparency log

工具自己維護一條 append-only Merkle log（每個 anchor 事件一葉，root hash 定期輸出供對外 publish）。

- **優點**：無外部依賴、離線可用、log 本身 tamper-evident（改任何歷史葉會令 root hash 對唔上）。
- **缺點**：**信任根仍然喺 root 自己度**——log 同 root 同域，root writer 可以成條 log 重造（重算所有 root hash）。佢只解「局部篡改可偵測」，唔解「全 root 重造偽造時間」。對 §0 嗰個窿係**冇效**嘅。
- **定位**：唔可以做主路。但佢有一個正當副用途：作為 TSA 不可用期間嘅 *pending queue* 語意層（見 §6），以及多次 TSA 提交嘅批次結構。

**建議**：主路 = A；B 唔做獨立功能，只保留「pending 事件用 append-only JSONL 記錄」（同 tombstone journal 同構，唔叫佢 transparency log，避免 overclaim）。

### 開放問題 Q1

Q1：係咪接受「主路 = RFC3161 公共 TSA、freetsa.org 預設、Merkle log 唔做」？定係你想要 B 都一齊落（例如做俾 self-host 場景用）？

## 3. 錨定對象：anchor 乜嘢

- **Anchor 嘅 digest preimage = receipt 嘅 canonical bytes**（即 `integrity.digest` 計算嘅同一 preimage，SHA-256）。咁第三方驗證鏈係：token 內 hash == receipt canonical digest → receipt digest == `integrity.digest` → `verify_receipt` ok。
- **建議 anchor 粒度**：每條 supersession chain 嘅 **chain-tail receipt** 一個 anchor（舊 receipt 被 tail 覆蓋，單獨 anchor 佢無增量價值）；加一個 **journal snapshot digest**（全 journal canonical digest）做 root-level 錨，令「journal 之後無新增刪除」都可以表述。
- **唔 anchor**：非 chain-tail 舊 receipt（除非 Isaac 裁決要）、ack/propagation artifact（可以日後擴展，M 唔入 scope）。

### 開放問題 Q2

Q2：anchor 粒度照「chain-tail receipt + journal snapshot」行？定係要全部 receipt（含被 supersede 嘅）都 anchor？

## 4. Token 存放位置

- 新目錄：**`evidence/anchors/`**（喺 bundle root 內，evidence 層延伸；唔掂 journal、唔掂 `evidence/` 既有 receipt 檔案區）。
- 每個 anchor 一對檔案：
  - `evidence/anchors/<receipt_digest>.tsr` — RFC3161 token（DER 原始 bytes）
  - `evidence/anchors/<receipt_digest>.meta.json` — 提交 metadata：`{receipt_digest, tsa_endpoint, submitted_at (本地 RFC3339, 僅顯示用—權威時間喺 token 內), request_sha256, token_sha256, tsa_trust_chain_snapshot_path}`
- TSA 信任鏈 snapshot：第一次成功提交時，將 TSA 公鑰鏈文件 fetch/存入 `evidence/anchors/trust/<endpoint>/`——**呢個係關鍵**：TSA 日後消失/換 key 時，第三方仲可以用 snapshot 驗證舊 token（snapshot 本身嘅 authentic要先由提交者自行 out-of-band 核對一次，呢點寫入誠實條款）。
- `evidence/anchors/` 內所有檔案 **immutable**：寫入後唔覆寫、唔刪除；重複提交同一 digest 會攞到新 token，存做 `<digest>.<n>.tsr`（n 遞增），唔覆寫舊 token（多個 timestamp 只會加強證據，唔會互相矛盾）。

### 開放問題 Q3

Q3：`evidence/anchors/` 目錄名同埋「immutable + 版本遞增唔覆寫」語意，照接受？

## 5. 驗證命令（第三方視角）

設計目標：**第三方完全唔需要 MBCP code**——只需要 openssl（RFC3161 驗證係 openssl 原生功能）同 receipt 檔案。呢個係成個工具嘅核心價值主張。

驗證流程（三步，全部有確定輸出；實作 round 落地精確命令並實跑留档）：

1. **Token → Hash**：`openssl ts -reply -token_in <digest>.tsr -text` 讀出 token 內承諾嘅 message imprint hash（SHA-256, hex64）。
2. **Hash → Receipt**：對 receipt 檔案做 canonical 序列化 + SHA-256（呢一步用 MBCP canonical 規則；為令第三方唔使裝 MBCP，工具附一個 *獨立* canonical-replay 小腳本——只讀 SPEC §1.4 規則重算 digest，唔 import `mbcp/`），比對 == token hash，再比對 == receipt `integrity.digest`。
3. **Receipt → Receipt-verify**：`python -m mbcp verify-receipt`（或現有 CLI 入口）跑 `verify_receipt` → ok:True。

三步全綠 = 「呢張 receipt 嘅內容喺 TSA 時鐘嗰刻已存在，且以 MBCP 自身語意驗證通過」。

- `canonical-replay` 獨立腳本係新發明項：**分流判定**——佢係 implementation detail（SPEC §1.4 規則嘅 read-only 重實現，唔加新語意），唔 spec-worthy；但要帶一條 test：對 fixture receipts，replay digest == `mbcp.canonical` digest（防兩套實現 drift）。

### 開放問題 Q4

Q4：獨立 canonical-replay 腳本（俾無 MBCP 環境嘅第三方用）照接受？定係第三方就叫他裝 MBCP 套件、唔另開 replay 面？

## 6. 失敗模式（fail-closed 全表）

| 情境 | 行為 |
|---|---|
| TSA unreachable / timeout / 非 2xx | **唔寫任何 anchor 檔案**。事件記入 `evidence/anchors/pending.jsonl`（append-only：digest、endpoint、時間、錯誤類別），下次 run 重試。fail-closed：無 token 就無 anchor，冇「部分寫入」狀態。 |
| TSA 回應驗證唔過（token 內 hash 同 request 唔符 / 簽名驗唔過） | 唔入庫；pending.jsonl 記 `token_rejected`；明報 error。**唔會靜默接受爛 token**。 |
| 提交成功但本地寫檔失敗 | token 只喺記憶體，唔算 anchored；pending.jsonl 記 `persist_failed`，token bytes 唔保留（下次重新提交——TSA 無狀態，重提交無害）。 |
| 提交時 receipt digest 同磁碟上 receipt 而家嘅 digest 唔符（receipt 被改/被 supersede 咗） | 係 *stale-read* 訊號：中止提交、報 error，唔 anchor 一個已經唔存在嘅 preimage。 |
| 驗證命令任一步 fail | 輸出明確 fail 同失敗步驟編號；**唔會有「skip 驗證但報 ok」嘅輸出**。驗證命令唔接觸網絡。 |
| `evidence/anchors/` 內檔案被改（token bytes 同 meta 內 `token_sha256` 唔符） | 驗證命令 step 0 先查 meta digest 綁定，唔符即 fail 並明示「anchor 層被改」——呢個唔係 MBCP bug 係外部篡改訊號，但驗證結果必須係 fail 唔係 pass。 |

**Pending 語意**：`pending.jsonl` 有 entry = 該 digest 尚未 anchored，第三方出示清單時要如實顯示「pending / anchored」兩態，唔可以將 pending 當成功。呢個 fail-closed 哲學同 MBCP propagation pending 同構。

## 7. 誠實條款（逐字級）

1. **信任根聲明（逐字建議措辭，入工具 docstring + README 節）**：
   > 「RFC3161 timestamp 嘅信任根係該 TSA，唔係 MBCP。MBCP 對 TSA 嘅營運、時鐘準確性、金鑰保管冇任何控制或背書。TSA snapshot 檔案由提交者自行 out-of-band 核對後先入庫；呢個核對步驟唔由本工具自動完成。」
2. **能力宣稱上限（逐字）**：本工具提供嘅係「**third-party timestamped evidence**」——一張 receipt 喺某時刻已存在嘅第三方可驗證證據。佢**唔提供**：防篡改、防全 root 重造（有 timestamp 嘅舊版仍然可以俾 root writer 重造一套新 artifact 並重新 anchor——但舊 token 令「兩套版本同時自稱真」可被偵測，呢個係佢嘅真實價值）、erasure 保證、任何法律效力。
3. **禁詞機制**：實作 round 起將呢份禁詞清單做成 grep pin（needle 拼合防 self-match，照 M4 banned-word pin 慣例）：`certified` / `certification` / `tamper-proof` / `tamperproof` / `guarantee` / `guaranteed` / `forgery-proof`。README、docstring、meta.json 模板全掃，pin fire = verify fail。
4. **RFC3161 免費 TSA 無 SLA**：docstring 明示「freetsa.org 係 convenience endpoint，唔係 trust endorsement；可經 config 換任意 RFC3161 TSA」。

## 8. 實作階段計劃（批准後先執行）

- **Worker**：Kimi（core endpoint）。交付：`anchor/` standalone 工具 + tests + README 節。commit 只准 code+tests+docs。
- **Verifier**：GLM（唔同族），三項 adversarial repro 硬要求：
  1. **真驗證**：攞一個 worker 產生嘅真 token，對真 TSA 信任鏈實跑 openssl 驗證一次（唔係白盒 pass——要見到 openssl 真實輸出）
  2. **Mutation**：篡改 receipt 一個 byte 後，驗證鏈必須 fail（step 2 digest mismatch）——證明鏈真係有咬合
  3. **Fail-closed**：模擬 TSA unreachable（網絡層 block），確認零 anchor 寫入 + pending 記錄正確
  另加：banned-word pin mutation（注入違禁詞驗 pin fire）、stale-read 場景、pending 兩態展示。
- **Merge gate**：照 milestone 鐵律 worker → verifier → Isaac 裁決 → merge，CI 綠。
- **SECURITY.md 一句**：對外故事句（草擬：*「Deletion receipts 可以由獨立 anchor 工具提交 RFC3161 TSA 攞第三方 timestamp；第三方淨用 openssl + MBCP 獨立 canonical replay 即可驗證 receipt 嘅存在時間與完整性證據。」*）——**待 Isaac 裁決先由 controller commit**。

## 9. Open-questions 總表（等裁決）

| # | 問題 | 建議 |
|---|---|---|
| Q1 | 主路 = RFC3161 TSA、唔做 Merkle log | 接受 |
| Q2 | anchor 粒度 = chain-tail receipt + journal snapshot | 接受 |
| Q3 | `evidence/anchors/` + immutable 版本遞增 | 接受 |
| Q4 | 獨立 canonical-replay 腳本 | 接受（帶 anti-drift test） |
| Q5 | 工具位置 `anchor/`（repo 內新頂層目錄）vs `tools/` | 建議 `anchor/`——獨立目錄令「唔入 mbcp/」嘅邊界物理可見 |
| Q6 | SECURITY.md 一句措辭 | §8 草擬版，裁決後 commit |
| Q7 | freetsa.org 做預設 endpoint | 接受（config 可換） |

## 10. 明確唔做（non-goals）

- 唔做公鏈（SAIHM 嗰條路——P-A 對標已切分，唔跟）
- 唔做 TSA 高可用/多 TSA 冗餘提交（可日後擴展，YAGNI）
- 唔做法律級 timestamp（eIDAS/ESZN 類 qualified TSA 係另一個宇宙）
- 唔改任何現有驗證路徑嘅行為
