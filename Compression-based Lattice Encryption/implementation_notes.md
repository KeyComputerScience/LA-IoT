# 方法与接口

`compression_lattice_encryption.tex` 是可插入原稿的小节。
Python 文件已生成，未运行、导入或测试，也未安装依赖。

## 数据处理

1. `alpha=1, beta=1`：读数附加可移除的认证标记，编码后进行格加密。
2. `alpha=0, beta=0`：BFV 加密 `[tau*x_0, ..., tau*x_3, tau]`。
3. 两路序列化结果使用 zlib 无损压缩；体积增加时保留原字节。
4. 可信 controller 解密敏感数据，验证并移除标记，使用共同 BFV 公钥重新加密统计量。
5. controller 合并统计量并加入一次先验，授权接收方解密后用 `Fraction` 计算贝叶斯后验。

各读数对应同一窗口中的共同未知量，采用独立高斯测量误差模型。
`tau` 为校准误差方差的倒数，代码使用整数读数、整数精度和整数先验均值。
每个向量位置分别计算后验均值，公共方差为 `1 / 总精度`。
结果以精确分数表示。BFV 同态阶段进行整数统计量的加法；分数在最终解密后计算。

## 文件

- `la_iot_bayesian.py`：设备打包、controller 接收与聚合、授权方计算后验。
- `la_iot_ring_lwe.py`：格加密的密钥生成、加解密、系数压缩与解压。
- `requirements.txt`：BFV 所用 TenSEAL 依赖；Python 版本为 3.10+。

两个 Python 文件放在同一目录。默认每条报告包含四个整数读数。
默认格参数为 `n=512, q=12289, eta=1, d_u=12, d_v=10`。
默认 BFV 参数为 `poly_modulus_degree=8192, plain_modulus=1032193`。
代码在初始化时检查明文范围，并为每个节点、每个轮次接收一条报告。
controller 保存格私钥与 BFV 公钥，授权接收方单独保存 BFV 私钥。
设备策略、校准精度和密钥在传输前配置；聚合输出经认证通道交付授权接收方。

## 调用示例

下列示例仅作为调用说明，未执行。

```python
import secrets
import la_iot_ring_lwe as lattice
from la_iot_bayesian import (
    ProtocolConfig, NodePolicy, DeviceClient, TrustedController,
    AuthorizedDecryptor, generate_bfv_contexts, bfv_context_id, lattice_key_id,
)

config = ProtocolConfig()
pk_lattice, sk_lattice = lattice.keygen()
bfv_public, bfv_secret = generate_bfv_contexts(config)

policies = {"sensor-A": NodePolicy(alpha=1), "sensor-B": NodePolicy(alpha=0)}
psks = {node: secrets.token_bytes(32) for node in policies}
devices = {
    node: DeviceClient(config, node, policy, psks[node], bfv_public, pk_lattice)
    for node, policy in policies.items()
}
controller = TrustedController(
    config, "round-001", policies, psks, bfv_public, sk_lattice,
    lattice_key_id(pk_lattice),
)
controller.receive(devices["sensor-A"].make_report([10, 20, 30, 40], "round-001", 1))
controller.receive(devices["sensor-B"].make_report([12, 22, 32, 42], "round-001", 1))

decryptor = AuthorizedDecryptor(config, bfv_secret, bfv_context_id(bfv_public))
posterior = decryptor.decrypt_posterior(controller.finalize())
# posterior.means: 四个 Fraction 后验均值
# posterior.variance: Fraction 后验方差
```

## 定义来源

- [格加密](https://cims.nyu.edu/~regev/papers/ideal-lwe.pdf)
- [系数压缩与解压，§4.2.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [BFV 向量接口](https://github.com/OpenMined/TenSEAL/blob/main/tenseal/tensors/bfvvector.py)
- [高斯模型的贝叶斯更新](https://people.stat.sc.edu/hitchcock/slides535day5spr2014.pdf)
