# 离线安全复核 12802 — 合成关单附件交接簿

Windows 原生 + Go 标准库，无外部依赖。输入与验证全部为本地合成数据。

## 题意对应

| 要求 | 实现位置 |
| --- | --- |
| 本地交接簿 | `internal/ledger`（追加式日志 + 每部门附件包） |
| 独立验证（不复用交接簿代码） | `internal/audit`（自行解析日志与附件包、自行重放策略） |
| 批准来自两个不同控制根，绑定摘要/两边租户/前一版/授权代 | `internal/model.ApprovalBinding` + `Keyring.VerifyApprovalSet` |
| 区分“相同内容重投”与“同号异摘要拒绝” | `Submit` 第 3 步：同版本同摘要同租户 → `duplicate_same_content`；同版本异摘要 → `conflict_same_version_different_digest` |
| 屏障重演“撤销已落盘、交接回执仍迟到” | `scenarios.BarrierRevocationThenLateReceipt`（两线程 + `Rendezvous` 屏障） |
| 屏障重演“已承诺但未给调用方回应”的重启 | `scenarios.BarrierCommittedButUnacknowledged`（`Config.CrashAfterJournalAccept` + `ledger.Recover`） |
| 恢复结果可从实际附件与核对日志复算 | `ledger.Recover` + `audit.Verify`（重算摘要、批准、托管、版本链） |
| 独立穷举复查短交错 | `internal/exhaustive`（真实交接簿 vs 独立参照模型，遍历全部排列） |
| 五万条多案记录、只重算有关案卷、对照全量报告 | `internal/dataset` + `internal/report`（`Full` vs `Incremental`，逐案比对） |

## 设计要点

**三条证据来源。** `journal.jsonl`（提交链，含托管变更与已接受交接）、
`reconciled.jsonl`（自足核对日志：镜像 genesis 与每次托管变更、记录每次尝试及其
决策上下文）、`packs/attachments-<租户>.bin`（实际附件字节，头里自带自描述元数据）。

**崩溃模型。** 一次交接在“两个部门的包都已落盘 + journal 记录已 fsync”时算提交完成。
如果此后、在写核对记录与回包之前进程死亡，`Recover` 会从 journal 与实际附件重建缺失
的核对记录，并先用 `audit` 级别的字节校验确认两部门副本确实存在且摘要一致——绝不
把缺失/损坏的字节“修复”成假成功。

**决策顺序（交接簿与参照模型一致）：** 形状/租户 → 附件完整性 → 版本级幂等
（重投 vs 冲突）→ 托管（撤销/未知即拒）→ 授权代 → 双根批准 → 版本序号 → 提交。
幂等检查先于托管，因此“撤销后迟到的原样重投”仍被判为重投，而“撤销后迟到的首次
提交”被判为 `custodian_revoked`。

**核对日志自足。** 每次尝试都记录 `journal_head_at_decision`、当时的授权代、前一已
接受版本、以及两边的托管快照。独立验证器据此在对应 journal 前缀上重算托管与版本
基线，再逐条复判结果与原因。

**独立验证器不 import 交接簿。** `internal/audit` 只共享不可变的 `internal/model`
密码学/编码类型，自行实现日志与附件包解析、托管重放、批准校验与完整策略复判。

## 运行

```sh
go test ./...          # 全部测试（含 5 万条规模测试与穷举交错）
go test ./... -short   # 规模测试改用小语料，快速回归
```

规模测试 `TestIncrementalMatchesFull` 生成恰好 50,000 条记录（20,000 个案卷、每案
1–4 个连续版本），分别做全量重算与只重算受影响案卷，并要求两者在这些案卷上逐字节
一致、且跳过其余案卷。

## 目录

```
cmd/selfcheck      可直接运行的行为自检（与测试同源场景）
internal/model     共享类型：摘要、批准绑定、链式记录、包元数据、公钥环
internal/wire      落盘格式：两条哈希链日志 + 每部门追加式附件包
internal/ledger    交接簿：托管、提交裁决、崩溃恢复
internal/audit     独立验证器（不依赖 ledger/wire/fixture）
internal/fixture   合成世界：控制根密钥、租户、托管人、签名请求
internal/scenarios 屏障与重启场景（测试与 selfcheck 共用）
internal/exhaustive 短交错穷举：真实交接簿 vs 独立参照模型
internal/dataset   5 万条多案语料生成
internal/report    逐案全量 / 增量报告与比对
```
