# LA-IoT 仓库静态审查

审查提交：d209d7328e767f502befc699f5832aa27e38b57a。读取了该提交的112个文件，并按Git blob散列核对快照。没有运行Python、导入模块、执行测试、安装依赖、配钥、启动服务或进行实验；没有修改远程仓库。

仓库已包含统一的src/laiot包、Apache-2.0 LICENSE/NOTICE、角色服务、标定、日志分析和测试源码。当前需要优先解决发布内容不同步、拥塞处理和统计分母问题。

## 一、优先修复

### 1. P1：新版示例与旧消融脚本不兼容

[Ablation Analysis/aggregation_ablation.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/Ablation%20Analysis/aggregation_ablation.py#L78)只接受旧八字段，examples/workloads.json新增了reading_scale、precision_scale、equal_weight_precision、unit、calibration_sha256。因此[文档中的示例命令](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/examples/README.md#L34)会在输入校验时被拒绝。脚本第352行默认参考目录joint_watermark_iot也未在仓库中提供。

同一脚本第41行仅有四个组，而[新增测试](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/tests/test_calibration_metrics.py#L121)要求uniform_pqc。旧等权组将precision固定为1，忽略示例指定的10，使源总权重从20变为2，同时改变了先验相对作用；旧脚本还没有连通物理单位RMSE与NLL。

建议完整同步两个消融脚本，统一五组定义、schema、标定尺度、默认laiot入口和测试。示例中权重16、4的等权对照可使用10、10，保持数据权重总量20。

### 2. P1：临时拥塞可能导致有效原件被删除

[src/laiot/coap_transport.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/coap_transport.py#L328)在传输/缓存资源不足时也返回BAD_REQUEST；第487行将该响应当作ReportRejected。[src/laiot/services.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/services.py#L626)收到此异常便删除中继候选。

触发条件：控制器暂时达到接收并发或缓存上限。有效原件可能被永久移出中继队列，源此前已得到中继接收确认。

建议把临时资源不足与永久无效报告区分开：拥塞返回可重试响应并退避；只有明确永久无效的候选才删除。密码校验失败仍使用统一拒绝信息。

### 3. P1：一个失败报告阻塞中继其他源

[src/laiot/services.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/services.py#L620)逐个等待send_report；[src/laiot/coap_transport.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/coap_transport.py#L426)默认每次交换等待120秒、最多两次整报告尝试。

触发条件：排在前面的报告遭遇丢包或控制器不响应。后面的完整报告也被迫等待，可能超过轮次期限。

建议使用有界并发队列、每源独立退避，并按轮次剩余时间限制交换超时。

### 4. P1：没有任何日志的预定轮次漏出完成率分母

[src/laiot/end_to_end.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/end_to_end.py#L154)只遍历日志中出现的轮次；第305行读取完整预定轮次表，却未补齐完全缺失的轮次。[large_scale_evaluation/code/analyze_results.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/large_scale_evaluation/code/analyze_results.py#L217)随后用CSV行数作为完成率分母，能耗每预定轮次也使用同样的行数。

例如预定10轮，只有9轮日志且9轮成功，当前路径会输出100%而非90%。这是依据代码分支的静态推导，未执行该案例。

建议以预定轮次表为主建立结果集。无日志轮次保留为incomplete，成本保持未知；或者拒绝缺少预定轮次的输入，不可静默丢弃。

### 5. P1：轮次生命周期缺少明确的就绪与交付终止

[src/laiot/services.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/services.py#L209)在控制器构造时持久化release/deadline，[src/laiot/services.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/services.py#L462)随后才绑定网络端点。端口占用或接口未就绪时，轮次已开始计时，修复重启后仍沿用旧期限。

此外，[src/laiot/services.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/services.py#L469)在结果生成后对离线接收端持续重试，缺少结果交付的截止状态。当前超时逻辑只覆盖缺少源报告的情况。

建议监听就绪后显式释放轮次；区分finalized、delivered和delivery_timeout，持久化交付期限与重试预算。

## 二、版本、对比与开销口径

### 6. P2：IoT Application仍是另一套旧实现

[IoT Application/la_iot_cca.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/IoT%20Application/la_iot_cca.py#L38)使用v4，[src/laiot/la_iot_cca.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/la_iot_cca.py#L43)使用v5。README称现代章节入口已重定向，但该目录仍保留独立实现。

[IoT Application/la_iot_cca_security.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/IoT%20Application/la_iot_cca_security.py#L418)仅检查外层源MAC便占用报告/序列位置；新版包先验证AEAD、内层MAC或BFV内容再入库。持有有效源凭据的错误报告在旧入口中可先占位，随后更正报告被视为冲突。该现象不构成对新版敏感加密封装的破解。

建议该目录改为兼容入口，唯一维护src/laiot；确需保留历史代码时移入明确的legacy目录并停止推荐使用。

### 7. P2：网络分析器仍能比较不匹配的基线运行

[large_scale_evaluation/code/analyze_results.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/large_scale_evaluation/code/analyze_results.py#L356)按scenario和metric查找两组均值并直接计算改善比例，没有核对跨方案seed集合、输入/拓扑/攻击配置散列。

例如LA-IoT与基线采用不同seed，只要scenario名称相同，仍会生成比例。新baselines.py已验证适配器配对元数据，但当前网络分析入口没有消费其paired_baselines.json。

建议在原始轮次层按seed和完整配置散列连接，保留未配对记录，基于成对差值计算区间。

### 8. P2：通信、能耗和瓶颈负载结束窗口需统一

[src/laiot/end_to_end.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/end_to_end.py#L220)累计同轮全部帧，而第237行瓶颈负载使用release到terminal窗口；能耗分析也按release到decision截取。

接收端已接受结果后，中继部分结果仍可能发送。这些帧可能进入总流量却未进入同一能耗窗口，或触发瓶颈窗口校验错误。

建议分别记录任务完成时刻与成本统计结束时刻，使用明确一致的成本窗口，保留完成后的重试/部分聚合流量。

### 9. P2：缺少两个隐藏文件，交付清单也未对应当前发布内容

SOURCE_DELIVERY.json列出的113个文件中，101个内容散列匹配；2个缺失，10个内容不同。

缺失：.github/workflows/manual-checks.yml、.gitignore。

内容不同：两个Ablation Analysis脚本，以及IoT Application的八个Python文件。这与上面的示例/旧入口问题对应，说明当前发布版本没有完整同步交付清单。

建议补齐隐藏文件，保留手动触发验证，重新生成对应当前发布版本的文件清单；无需重加已有Apache-2.0许可证。

### 10. P2：压缩效果应按完整报文记录

[src/laiot/la_iot_bayesian.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/la_iot_bayesian.py#L136)压缩后又补齐至原始payload长度。因此固定编码长度时，内层水印单元长度不变。

建议同时记录stored_len、填充后长度、密文长度、完整包长度和逐跳发送字节。内部压缩率不能直接作为无线流量节省。

### 11. P2：BFV接收端补充密钥配对防错

[src/laiot/la_iot_cca_security.py](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/src/laiot/la_iot_cca_security.py#L548)检查参数并保存外部给定context_id，未核对实际私钥与预定公钥是否配对。误放另一组相同参数的私钥时，启动检查仍可能通过，错误延迟至解密阶段。

建议在显式配置/启动检查中验证密钥配对，并增加交换同参数私钥的测试。本项是部署防错，不代表敏感封装IND-CCA被攻破。

## 三、用于论文复核需要补充的材料

1. **周期上报与多轮调度：**当前CLI一次source调用发送一个冻结报告，角色配置只绑定一个round。补充复用既有密钥的轮次登记、就绪后统一释放、序列递增、20秒等实际截止和轮次切换；对完成历史大载荷归档，保留必要哈希/序列/交付记录。
2. **真实IoT接入：**Pico采集固件、RP2040/Contiki平台与外接IEEE 802.15.4模块/驱动版本、border router设置、构建/map/启动记录。现有[Contiki说明](https://github.com/KeyComputerScience/LA-IoT/blob/d209d7328e767f502befc699f5832aa27e38b57a/large_scale_evaluation/contiki/README_zh.md#L2)明确该代码是执行证据例程，不能替代完整板级应用。
3. **可复核实验数据：**原始角色日志、预定轮次表、功率采样、校时文件、逐跳帧记录、标定与参考真值、结果CSV和图表输入散列。当前模板不能替代这些记录；未附记录也不等于作者从未实验。
4. **可复核基线：**FGAMD、PATM、FL-IoV实际参考实现或作者实现、提交版本、适配器、相同输入/拓扑/攻击配置与计费边界。现有适配器是接口，仓库未附三种方案实现。
5. **环境与发行：**保存实际解析出的依赖版本与构建信息、Pi/Nano系统和CPU策略；补充Cooja .csc、节点类型、种子、完成运行记录；修复后人工执行已有测试并保存结果，创建版本标签和release。

## 处理顺序

先完整同步交付文件和消融入口，再修复拥塞/队列/轮次生命周期，随后修正完成率、配对及成本窗口；最后补齐真实部署与实验记录。此次不改变代码，也不把静态审查当作运行通过或密码安全证明。

