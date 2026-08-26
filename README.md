# QuickRoute

快速识别 Linux VPS 到中国大陆的三网回程线路。默认并行追踪北京、上海、广东的电信/联通/移动共 9 个目标，只做路由识别，不测速、不上传报告、不修改系统网络配置。

## 快速使用

安全的一行命令（先下载到临时文件，再执行）：

```bash
d=$(mktemp -d) && curl -fsSL https://raw.githubusercontent.com/leeska/QuickRoute/main/quickroute -o "$d/quickroute" && curl -fsSL https://raw.githubusercontent.com/leeska/QuickRoute/main/quickroute_lib.py -o "$d/quickroute_lib.py" && python3 "$d/quickroute"; rc=$?; rm -rf "$d"; exit $rc
```

或克隆运行：

```bash
git clone https://github.com/leeska/QuickRoute.git
cd QuickRoute
./quickroute
```

要求 Python 3.9+。如果系统没有 `nexttrace`，QuickRoute 会从 `nxtrace/NTrace-core` 最新 GitHub Release 下载匹配架构的 `nexttrace-tiny` 到用户缓存目录，并使用 Release API 提供的 SHA256 digest 强制校验。

## 常用参数

```bash
./quickroute                         # IPv4 TCP，9 个默认目标
./quickroute --city gd --isp ct,cu   # 只测广东电信/联通
./quickroute --ipv6                  # IPv6
./quickroute --protocol udp          # UDP traceroute
./quickroute --timeout 12 --parallel 9
./quickroute --json                  # 稳定 JSON 结构
./quickroute --details               # 附原始 NextTrace 输出
./quickroute --classify-file trace.txt
./quickroute --nexttrace /path/to/nexttrace
```

完整参数见 `./quickroute --help`。

## 线路标签

- 电信：`163`、`CN2 GT`、`CN2 GIA`、`CTG GIA`
- 联通：`4837`、`9929`、`10099`，并保留 `10099→4837/9929` 组合
- 移动：`CMI`、`CMIN2`、`CMIN2→CMI`
- 教育/科研：`CERNET`、`CERNET2`、`CSTNET`
- 无法从可见 ASN 路径确认：`Hidden` 或 `Unknown`

识别以 NextTrace 返回的 ASN 顺序为证据。路由会随 BGP、负载和目的地址变化；隐藏跳、ICMP/TCP 过滤及定位服务异常都可能影响结果。工具显示的是测试时刻到指定目标的路径，不代表整省、整个运营商或所有业务流量。

## 范围与安全

- 默认每目标 1 次查询、最多 24 跳、单任务 20 秒超时，并行执行。
- 不安装系统包，不执行 `curl | bash`，不创建 chroot/rootfs。
- 不上传结果、无遥测、无广告。
- 自动下载仅来自 NextTrace 官方 GitHub Release，并要求 SHA256 digest。

## 许可证与来源

项目采用 AGPL-3.0。回程目标与流程基于 `xykt/NetQuality` 的 AGPL-3.0 实现重新整理；详细归属见 [NOTICE](NOTICE)。
