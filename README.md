# QuickRoute

快速识别 Linux VPS 到中国大陆的三网回程线路。默认追踪大陆 31 个省级行政区的电信、联通、移动共 93 个目标，并实时显示进度；只做路由识别，不测速、不上传报告、不修改系统网络配置。

## 快速使用

一键运行：

```bash
curl -fsSL https://raw.githubusercontent.com/leeska/QuickRoute/main/quickroute | python3 -
```

或克隆运行：

```bash
git clone https://github.com/leeska/QuickRoute.git
cd QuickRoute
./quickroute
```

`quickroute` 是单文件程序，要求 Python 3.9+。如果系统没有 `nexttrace`，QuickRoute 会从 `nxtrace/NTrace-core` 最新 GitHub Release 下载匹配架构的 `nexttrace-tiny` 到用户缓存目录，并使用 Release API 提供的 SHA256 digest 强制校验。

## 常用参数

```bash
./quickroute                              # IPv4 TCP，全国 31×3 共 93 个目标
./quickroute --province gd --isp ct,cu    # 只测广东电信/联通
./quickroute --province bj,sh,gd          # 只测北京、上海、广东三网
./quickroute --ipv6                  # IPv6
./quickroute --protocol udp          # UDP traceroute
./quickroute --timeout 12 --parallel 9
./quickroute --json                  # 稳定 JSON 结构
./quickroute --details               # 附原始 NextTrace 输出
./quickroute --no-progress           # 关闭实时进度条
./quickroute --classify-file trace.txt
./quickroute --nexttrace /path/to/nexttrace
```

完整参数见 `./quickroute --help`。

## 线路标签

- 电信：`163`、`CN2 GT`、`CN2 GIA`、`CTG GIA`
- 联通：`4837`、`9929`、`10099`，并保留 `10099→4837/9929` 组合
- 移动：`CMI`、`CMIN2`、`CMIN2→CMI`
- 教育/科研：`CERNET`、`CERNET2`、`CSTNET`
- 目标已到达但骨干 ASN 不可见：`电信接入`、`联通接入`、`移动接入`；这表示运营商接入已确认，但不会伪造为 `163`、`CN2`、`4837` 等精确骨干标签
- 没有可解析路由：`错误`，并在表格后显示具体原因

识别以 NextTrace 返回的 ASN 顺序为主证据，并使用常见中国骨干 IP 前缀补齐缺失 ASN。路由会随 BGP、负载和目的地址变化；隐藏跳、TCP 过滤及定位服务异常都可能影响结果。工具显示的是测试时刻到指定省级目标的路径，不代表整个省、整个运营商或所有业务流量。

## 范围与安全

- 默认每目标 1 次查询、最多 24 跳、单任务 20 秒超时；并发数按可用内存自动选择，256MB 小机通常为 3，高内存机器最多为 9。
- 不安装系统包，不执行 `curl | bash`，不创建 chroot/rootfs。
- 不上传结果、无遥测、无广告。
- 自动下载仅来自 NextTrace 官方 GitHub Release，要求 SHA256 digest，并设有 64 MiB 硬上限。
- 每条追踪运行在独立进程组；超时会终止整组，单任务内部错误不会中断其他结果。

## 许可证与来源

项目采用 AGPL-3.0。回程目标与流程基于 `xykt/NetQuality` 的 AGPL-3.0 实现重新整理；详细归属见 [NOTICE](NOTICE)。
