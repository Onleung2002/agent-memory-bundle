# Contributing to MBCP

MBCP（Memory Bundle Conformance Profile）係一個中立 conformance profile + 可執行測試套件。我哋唔造記憶格式、唔造 agent runtime——我哋做**考官**。貢獻前請讀 [SPEC.md](SPEC.md) 同 [GOVERNANCE.md](GOVERNANCE.md)。

## 開發環境

- 純 Python 3.11+ stdlib，**冇第三方依賴**（conformance suite 嘅設計約束——任何 conforming 實作都要可以喺乾淨環境重跑）。
- 冇 pytest。驗收一律：
  ```bash
  python3 tools/run_tests.py          # unit tests
  python3 tools/run_scenarios.py      # conformance scenarios
  bash tools/test_count_guard.sh origin/main HEAD   # test count non-decreasing
  bash tools/test_count_guard.sh --self-test
  python3 tools/test_inventory.py     # machine-countable inventory
  ```
- CI 會行齊上述 + actionlint + inventory cross-check。PR 冇全部綠唔會 merge。

## Conformance 聲明（最重要嘅貢獻類型）

如果你有自己嘅 memory-bundle 實作，最高價值嘅貢獻係：

1. 對住 `tests/scenarios/*.yaml` + `SPEC.md` §3a（公開 API 契約）寫你嘅實作——**唔好參考 `mbcp/` 源碼**；照 SPEC 行，歧義你會撞到，撞到嘅位請開 issue（呢個係 SPE 嘅 fuzzing）。
2. 提交 implementation report：per-scenario pass/fail + 你對每個 FAIL 嘅診斷（你嘅 bug 定 SPEC 歧義）。
3. 合格記錄會入 conformance registry（`docs/REGISTRY.md`，機器可讀 format 見 registry schema）。

## 提交紀律

- 一個 commit 一件事；commit message 講「做咗咩」唔係「改咗邊個檔案」。
- 測試同 code 同 commit——唔接受「code 先、test 後補」。
- SPEC / GOVERNANCE / gate 準則改動係 maintainer 權——請開 issue 討論，唔好直接 PR。
- 安全相關發現：見 [SECURITY.md](SECURITY.md)，唔好開 public issue。

## 誠實框架（請原樣理解，勿引申）

- 本 project 嘅 artifact（receipt、pack、ack）提供 **digest-chain integrity only**；無簽名前（L4 路線 = ed25519，進行中），tamper-evidence 建基於 root writer 自己唔偽造，**唔係防偽保證**。請勿喺任何宣傳文案描述超出呢個框架。
- 「刪除可證」係 machine-checkable 嘅收據語意，唔係法律意見；GDPR Art.17 適用性由你嘅 DPO/律師判斷。

## 語言

Project 文件以繁體中文（香港）為主；issue/PR 英文繁中皆可。
