# MBCP HANDOVER — 維護者/Controller 交接紀錄

> SSOT 係 SPEC.md / GOVERNANCE.md / docs/BACKLOG.md。本檔係交接同 protocol 紀錄，唔係 requirement 來源。

## 現狀（2026-11-06，M2 已封存）

- main = `c0b04c7`（M2 merge `e8678b5` + 修正/docs/CI commit）。測試：147 unit + 9 scenarios = 156；guard baseline origin/main→HEAD = 54→156
- M2 全程見 `docs/MILESTONE_M2.md`；未拍板 backlog 見 `docs/BACKLOG.md`
- GitHub push 由 Isaac 做（controller container 無 credentials）；push 後 CI 需確認綠
- M3 未開工：第一步係 controller 出 `docs/RFC_L2_REISSUANCE_L4.md`（L2 propagation + receipt re-issuance/supersession + L4 正式化 + M1 carried 兩條 + 第二獨立實作評估），Isaac 批准前無新 code

## Protocol（M2 retrospective audit 後 Isaac 裁決，硬規則）

1. **Fix worker 只准 verdict 整合後 dispatch**：verifier 報告未整合（controller 抽查 + verdict 出咗）之前，唔好派 fix worker——M2 期間 mutation verify session 差 30 秒完成時已派 worker，兩個 agent 撞同一 working tree，逼 worker 轉 scratch clone 落地。
2. **同一 working tree 一次只准一個 agent**：任何 mutation/simulated-crash 類會改 working tree 嘅工作，期間嗰個 tree 對其他 agent 係封鎖區；需要平行就用獨立 clone/worktree。
3. **事件調查第一步查自己 dispatch 記錄**：出現「未預期嘅 branch 改動」時，先核對自己嘅 delegation/背景 process 紀錄，唔好先假設第三方 rogue agent（M2 事件正正係自己排程造成）。

## 分工慣例

- Worker = Kimi（coding fix）/ worker 原始輪歷史上曾用 deepseek；verifier = GLM，同 worker 唔同族
- Verifier 標準手段：independent repro + mutation testing（false-green = 必報發現）；controller 親手抽查 verifier 關鍵 claim
- BACKLOG / MILESTONE / HANDOVER 呢類 docs commit 由 controller 做，唔入 worker fix commit
- 測試一律 plain `python3`（pytest 冇裝）；YAML/step 名避免裸 `: `

## Controller 執行層觀察（Isaac 指示記錄）

- **Stall 故障觀察次數：2**（2026-11-10 記）。Controller（GLM-5.3-flash 執行層）兩次出現連續空轉 pattern——派工前發出一連串無意義 shell 命令（printf 標記）而唔執行真實 dispatch，每次自報後恢復、冇影響 repo state（worker commit 未郁、tree clean）。第一次喺 M4 Round A verify 派工前，第二次喺 Round C Batch 3 verify 派工前。**Isaac 指示：再出現第三次要查 root cause**（可能係長 context 下執行層 decision loop 問題）。觀察到嘅 mitigations：愈早自我察覺愈好；dispatch 動作應該喺單一 call 內完成，唔好拆做「準備→再準備→…→launch」。
