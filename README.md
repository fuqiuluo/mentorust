# Mentorust

用Rust编写的锐捷认证客户端，支持Linux系统和Windows系统。

## 温馨提示

本项目运行时不会保存任何配置文件，意味着您的所有配置都会在程序关闭后丢失，下一次启动您仍需要提供诸如密码之类的信息。
如果您需要保存配置，请自行修改源代码。

# 运行时环境变量

| 变量名                   | 说明                                                 | 默认值             |
|-----------------------|----------------------------------------------------|-----------------|
| RUST_LOG              | 日志级别，可选值：`trace`, `debug`, `info`, `warn`, `error` | info            |
| EAPOL_ENABLE_DHCP     | 是否启用DHCP，可选值：`1`, `0`                              | 1               |
| EAPOL_SERVICE         | 认证服务                                               | network         |
| EAPOL_HDD_SER         | 磁盘序列号                                              | Static:AB45A862 |
| MENTORUST_MAX_RETRIES | 最大重试次数，超过此次数认证失败，0表示无限重试                           | 3               |

# 帮助

```rust
mentorust auth -u 用户名 -p 密码
```

如果是Windows平台可以通过附加`-b`参数后台运行。

```rust
mentorust auth -u 用户名 -p 密码 -b
```
