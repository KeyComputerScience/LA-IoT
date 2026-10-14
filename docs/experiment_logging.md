<!-- SPDX-License-Identifier: Apache-2.0 -->
# 实验日志与端到端开销

本次交付只编写源码、测试和日志模板，没有运行 Python、测试、加密、网络服务或实验。文件中的测试数值是断言输入，不是论文实验数据。

## 统一事件

`laiot.events.EventLogger` 写出 `LAIOT_EVENT {JSON}`。构造时明确提供 `run_id`、`seed`、`clock_domain`；服务可将 `sink` 设为 `sys.stderr`，与命令输出分开。每次 `emit(event, node_id=..., round_id=..., sequence=0, ...)` 记录本进程单调时钟。设备或进程重启后使用新时钟域。日志只接受已定义的元数据字段；禁止写入原始读数、私钥、PSK、AES密钥或完整明文。`detail`只放公开的短错误代码。

旧版事件字段仍受支持。新增字段包括：

| 字段 | 含义 |
|---|---|
| `scope` | `host`、`application`、`link`或`simulation` |
| `participants`、`n_expected` | 调度的完整源名单与数量 |
| `source_id` | 由控制器记录事件时，对应的源身份 |
| `duration_ms` | 本进程实际测得的阶段耗时 |
| `link_id`、`sender`、`receiver` | 实际观测的有向链路 |
| `traffic_class` | 四选一：`originals`、`partials`、`control`、`results` |
| `frame_id`、`attempt` | 同一物理帧及其实际发送尝试编号 |
| `wire_bytes` | 在声明链路层实际发出的长度 |
| `airtime_s` | 实际记录的该次帧发送占用时间，可省略 |
| `report_bytes` | 应用层序列化长度，与链路字节分开 |

`ROUND_RELEASE`仅由权威调度端记录一次。`REPORT_ACCEPT`表示源报告完整验证后已入库；相同报告重试用`DELIVERY_RETRY`，不增加源数。接收端在验证结果并解密后记录`RESULT_ACCEPT`。控制器收到并验证接收端回执后记录`ROUND_COMPLETE`。超时记录`ROUND_TIMEOUT`；失败和未完成轮次也保留。

例如40%丢包时验证了12/20个源：`n_verified=12`，状态为`timeout`或`incomplete`，没有完成轮次的E2E时延。12个已验证源不能记为一次成功聚合。

## 时间与时钟映射

`laiot.end_to_end`将两种时间分开：

- `e2e_latency_ms`：调度释放到接收端`RESULT_ACCEPT`。两端必须使用真实共同钟或已有证据的时钟映射。
- `jct_ms`：调度释放到最终交付决定。如果控制器记录了经认证回执的`ROUND_COMPLETE`，该值包括回执返回时间，可在控制器自己的时钟域计算。它不是精确的接收端接受时刻。

时钟映射JSON包含`common_domain`和`mappings`。每个映射需声明`domain`、`offset_us`、正数`scale`、`error_bound_us`、`artifact`及`artifact_sha256`，采用 `common_us = scale * local_us + offset_us`。工具验证证据文件哈希；哈希本身不证明校时准确，误差界限来自校时实验。缺少映射时相关时间字段留空，不直接相减两个主机的单调时钟。直接共同钟也需由实际实验配置建立。

## 四类成本分开统计

只有实际链路采集器发出的 `event=SEND, scope=link, direction=tx` 进入通信总量。Linux服务的应用层`SEND`只记录`report_bytes`，不会冒充802.15.4帧。驱动或抓包适配器须记录完整头部、ACK、每一跳、每一次重传，并为每次发送提供唯一的`link_id/sender/frame_id/attempt`组合。

1. 原始报告转发计入`originals`，包括它们在所有跳上的发送。
2. 中继部分聚合计入`partials`，与原件分开。
3. 路由、ACK及其他控制消息计入`control`；结果密文和结果认证回执计入`results`。同一帧只选一个类别。
4. 控制器分别用`CONTROLLER_VERIFY`、`RECOVERY`、`BFV_REENCRYPT`、`RECONSTRUCTION`记录实际阶段耗时。只有独立计时的阶段才填值；不能把一个总时间按比例拆分。外包总时间不能再次与内部阶段相加。
5. 瓶颈链路由实验配置明确指定。`bottleneck_wire_bytes`仅统计该链路的发送，不能用全网多跳字节代替。负载优先使用实际发送时间除以观测窗口；否则可用实际线缆/无线帧比特数除以明确容量和窗口，并标明该计算口径。链路重传已计入实际发送。

只有保存了声明网络范围的完整帧采集日志，才将`traffic_trace_complete`设为`true`。缺少完整链路采集时，通信与瓶颈总量留空。该开关是实验者的采集范围声明，并不自动证明采集完整。

## 标准化与汇总入口

以下命令供后续实际运行，本次未执行。先按仓库说明安装包，再调用：

```sh
python large_scale_evaluation/code/network_adapter.py normalize --logs run/controller.log run/recipient.log --output run/events.csv
python -m laiot.end_to_end --events run/events.csv --config run/accounting.json --output run/rounds.csv
python large_scale_evaluation/code/analyze_results.py --rounds run/rounds.csv --output run/summary
```

`accounting.json`声明`common_clock_domain`，可选`clock_mappings`文件路径、`scheme`、`scenario_id`、`bottleneck_link_id`、`link_capacity_bps`和`traffic_trace_complete`。源名单可来自`ROUND_RELEASE.participants`，也可在`rounds`中逐轮提供`run_id/round_id/participants`并交叉核对。使用真实run和链路参数，不填示意性能值。

`rounds.csv`保留缺失字段为空。分析脚本按独立run汇总，全部轮次进入完成率；完整覆盖的分项成本才进入该run的均值。缺失仪器记录不填零。内存需要独立填写实际`host_peak_rss_bytes`；聚合总耗时可填写独立测得的`aggregation_processing_ms`，不会由通信量推算。峰值内存取每个run的最大值，分项时延和字节取每轮均值。

## 能耗

`integrate_measured_power`对实际功率采样按梯形积分，`W * s * 1000 = mJ`。每条trace对应一个明确、互不重叠的`physical_scope_id`，例如一块Pi；同一Pi上源进程和中继进程共享一次整板采样，不得当两块板相加。要求全部物理板、相同窗口以及明确边界采样。失败轮次也在原测量窗口内。工具不会从Pi CPU频率推算MCU能耗。

已有`analyze_results.py --power ... --energy-profile ...`保留实测与模型分开分析，并验证校准文件、范围和时间窗。模型Energest输入需要实际采样计数、正确ticks换算和独立功率模型；不能把CPU、整板与无线电全功率重复相加。只有整板测量时，不声称已单独测得CPU和无线电能耗。

## Contiki-NG执行证据

`large_scale_evaluation/contiki`仍是可编译集成前的执行证据源码，不包含Pico平台移植、802.15.4驱动或完整加密固件。新版`LAIOT_ENERGEST`输出包含实际`ENERGEST_SECOND`、本地时间和累计ticks。

```sh
python large_scale_evaluation/code/network_adapter.py normalize-energest --logs run/contiki.log --output run/state_intervals.csv
```

这一步仅把相邻累计ticks差除以实际tick率，得到秒，不生成能耗或伪造网络事件。旧版`node=... cpu=...`日志没有时间戳，需要`--metadata run/legacy_snapshots.json`。文件的`snapshots`逐条声明日志相对路径`log`、行号`line`、`run_id`、`seed`、字符串`node_id`、新启动对应的`clock_domain`、独立记录的`time_us`以及`ticks_per_second`。没有这些证据就停止转换；不能假定每次打印恰好间隔10秒。

保存固件、map、编译命令、实际提交、端口与驱动、启动日志、校时文件和抓包。源码存在、GET返回或文件哈希匹配均不代替设备实际执行与网络采集。

## 状态提交与日志恢复

`EventOutbox(logger)`复用调用者的SQLite连接，不另开数据库。初始化时调用`initialize(connection)`；在协议状态变更的同一个事务内调用`append(...)`，并给关键转换一个稳定的`event_id`。事务提交后调用`flush_pending(connection)`。先输出并flush日志，再标记已发布；若这两步之间崩溃，恢复时可能再次输出同一条记录，标准化器和汇总器按`event_id`核对并去重，相同ID的不同内容报错。

原始时间和时钟域写入数据库后保持不变，恢复时不会用新进程的时间替换。事务回滚的状态没有可发布事件。捕获端仍应持久保存stdout/stderr；流的flush不等同于外部日志收集器已落盘。普通未使用outbox的计时事件属于尽力记录，不能宣称崩溃后绝对完整。

事务内事件的时间是记录点，早于该事务提交返回。若研究需要将提交尾部计入精确时延，应增加明确的提交后边界记录，并交代持久化与记录间隙；不能把恢复时的发布时刻当作原来的数据接受时刻。报告计时口径和时钟映射误差界限应与图表一起保存。
