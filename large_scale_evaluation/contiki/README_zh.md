<!-- SPDX-License-Identifier: Apache-2.0 -->
这组文件是 Contiki-NG 4.8 执行证据的示例源码，未编译、未烧录、未运行。

它只提供 cooperative process、CoAP GET 资源和 Energest 累计计数。不要把它称为完整 LA-IoT 固件。RP2040/Pico 的平台移植、802.15.4 模块与驱动、报文认证、BFV、ML-KEM、分块传输和 MAC 帧跟踪均未在这里实现。

真实实验的执行依据应包括：

1. 固定 Contiki-NG v4.8 的实际提交与 Cooja 子模块提交；保存编译器、完整构建命令、平台与驱动源码。
2. 保存 ELF、map 文件及 SHA-256；将 `LA_IOT_BUILD_ID` 设为应用源码散列，而非 `UNSET`。记录 Pico 的静态内存、最大同时栈与堆、缓冲区、Flash。
3. 启动日志必须与硬件编号、固件散列、节点角色、run_id 对应。这里的 LAIOT_BOOT 只是应用日志，应同时保存系统启动日志。
4. 用真实客户端请求 `/la-iot/evidence`，保存 LAIOT_COAP 日志及网络抓包；该 GET 只验证资源运行，不证明加密或聚合已执行。
5. LAIOT_ENERGEST 为累计 ticks，计算相邻快照差并除以同一次启动的 ENERGEST_SECOND。遇重启、计数回绕或时钟域变化，应分段而非直接相减。
6. CPU 活跃状态含内存与系统基础耗电时，radio 功耗应使用额外分量；不能同时把整板功耗、CPU 总功耗和 radio 总功耗直接相加。电流模型来自对应无线电及实测校准。
7. 每次应用报文、CoAP block、6LoWPAN fragment、MAC 重传应有可关联的标识。上述例程没有 MAC 帧采集钩子，应在实际驱动中补充。

Contiki-NG 官方依据见 `../references.bib`。官方文档说明平台能力与 API，实际设备执行仍需上述构建和运行证据。


## 统一日志与 ticks 转换

本目录源码增加了 `LA_IOT_RUN_ID`、`LA_IOT_RUN_SEED`、`LA_IOT_CLOCK_DOMAIN`。实际构建时明确设置这三个值及 `LA_IOT_BUILD_ID`；字符串宏仅使用安全的ASCII字母、数字、斜杠、短横线和下划线，避免破坏JSON。每次重启更换时钟域；节点编号自动追加到域名。`UNSET`仅是源码占位，不能作为实验身份。

启动时和周期定时器输出JSON形式的 `LAIOT_ENERGEST`，包括本机 `clock_time()` 换算的 `time_us`、实际 `ENERGEST_SECOND` 和累计CPU/LPM/DEEP/TX/LISTEN ticks。该时间属于本机时钟；若 `clock_time()` 回绕，重新分段和标注时钟域。正式能耗窗口另需准确的起止快照，不能将周期输出当作精确的轮次边界。

后续实际运行后可使用以下转换入口（本次未执行）：

```sh
python large_scale_evaluation/code/network_adapter.py normalize-energest --logs run/contiki.log --output run/state_intervals.csv
```

旧版 `LAIOT_ENERGEST node=...` 缺少时间戳。转换时传 `--metadata run/legacy_snapshots.json`，对每行明确提供日志路径、行号、run/seed/node、时钟域、独立采集的 `time_us` 与 `ticks_per_second`。转换只生成状态持续秒数；再结合真实、避免重叠的功率校准，才可估计mJ。完整字段见 `../../docs/experiment_logging.md`。

这份例程没有发出假的 `SEND` 或无线帧日志。全网流量和瓶颈负载需在实际驱动、MAC或抓包转换器中采集，不能以CoAP GET计数替代。
