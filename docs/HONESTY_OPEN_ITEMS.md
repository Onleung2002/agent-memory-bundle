# 誠實開口清單（honesty open items）— 2026-11-14

用途：下下次 SPEC touch 時一齊修嘅 spec-lag 措辭項，唔係 code bug（全部 fail-closed 下游、無洗白通道）。來源：M4 Round B audit2 hotfix verify（BACKLOG 記載）。

## H3 — supersession 觸發位數

SPEC §1.2.2 寫「一個」觸發位；實作有**兩個**觸發位（evidence ∪ recovery 嘅第二條路徑）。方向：SPEC 補句寫明兩個觸發位。conservative direction，無錯誤行為。

## H4 — write-boundary id-level 措辭

SPEC 話 write-boundary 拒收 (id, digest) pairs；實作係 **id-level**（更嚴：同 id 任何 digest 都拒）。方向：SPEC 措辭對齊 id-level，加一句 why（寬鬆到 pair-level 會留復活窗口）。

## H5 — receipt 層 exact compare

receipt 層兩處 compare 係 exact（唔係 subset）。方向：SPEC 補句「exact，唔係 subset」——conservative 方向，第三方唔會誤以為 subset-pass 係 ok。

## 附帶（已落 SECURITY.md，2026-11-14）

- A-3 availability 限制 → SECURITY.md #6
- keypair per-instance cache 語意 → SECURITY.md #7

## 程序

呢三條係純措辭，唔動 code/tests。下次任何原因要 touch SPEC 時，三條一個 docs commit 帶埋，唔好單獨開 milestone。
