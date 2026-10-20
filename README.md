# Cloudflare CDN IP 本地优选

定时运行 `cf_domain_manager.py`，从 AdGuard Home 查询日志中筛选出「解析到 Cloudflare IPv4 网段」的域名并维护为 CSV，同时通过 DoH 定期复检，剔除已不再走 Cloudflare 的域名；再由 `cf_best_hosts.py` 生成 hosts 文件。
将生成的 hosts 文件加入 AdGuard Home 的 DNS 黑名单，即可实现 Cloudflare CDN 域名的 IP 优选。


## 系统组成与文件说明

| 文件 | 说明 |
| --- | --- |
| `cf_domain_manager.py` | 域名筛选主脚本，配置区在文件顶部 |
| `cf_best_hosts.py` | 生成 `cf_hosts.txt` 的优选主机脚本 |
| `cf_domains.csv` | 维护结果（UTF-8 with BOM，可直接用 Excel 打开） |
| `cf_hosts.txt` | 生成的 hosts 文件，可直接合并到系统 hosts |
| `cf_hosts_exclude.txt` | 排除域列表，每行一个域名，排除该域及其所有子域 |
| `cf_domains_removed.csv` | 剔除审计记录 |
| `cloudflare_ips_v4.txt` | Cloudflare 网段缓存，默认 7 天过期 |
| `requirements.txt` | 依赖文件 |

## `cf_domain_manager.py`：域名筛选与维护

### 工作流程

1. 读取 AdGuard Home 最近 `LOOKBACK_HOURS` 小时（默认 1 小时）的查询日志；
2. 下载/读取 `https://www.cloudflare.com/ips-v4` 的网段列表；
3. 找出 A 记录命中这些网段的域名，合并进 `cf_domains.csv`；
4. 剔除 CSV 中「最后访问时间」达到 `STALE_DAYS` 天（默认 7 天）的域名；
5. 用配置的 DoH 逐个解析剩余域名：**任意一个 DoH 返回 CF 段 IP 就保留**，只有全部有效解析结果都不在 CF 段才剔除；
6. 被剔除的域名追加记录到 `cf_domains_removed.csv`，方便回溯。

### 配置

所有配置都在 `cf_domain_manager.py` 顶部：

| 变量 | 说明 |
| --- | --- |
| `AG_URL` | AdGuard Home 管理地址，填到端口即可，例如 `http://127.0.0.1:3000` |
| `AG_USERNAME` / `AG_PASSWORD` | AG 登录账号；未开启登录验证时留空 |
| `LOOKBACK_HOURS` | 每次回看多少小时的 AG 日志，默认 `1.0` |
| `STALE_DAYS` | 最后访问时间达到多少天即剔除，默认 `7` |
| `DOH_ENDPOINTS` | DoH 服务 |
| `DOH_HTTP2` | 是否用 httpx 走 HTTP/2，默认 `True` |
| `DOH_TIMEOUT` / `DOH_WORKERS` | 单个 DoH 超时、并发数 |
| `AG_PAGE_SIZE` | AG 日志分页大小，默认 500 |
| `CF_CACHE_DAYS` | CF 网段缓存有效期 |

脚本预设阿里 DoH：

```text
https://223.5.5.5/dns-query
```

### 运行

```bash
pip install -r requirements.txt
python cf_domain_manager.py
```

可选参数：

```bash
python cf_domain_manager.py --hours 3       # 本次回看 3 小时
python cf_domain_manager.py --stale-days 14 # 改成 14 天未访问才剔除
python cf_domain_manager.py --skip-doh      # 只拉 AG 日志、维护 CSV，不做 DoH 复检
python cf_domain_manager.py --csv D:\data\cf.csv
```

依赖：Python 3.8+；HTTP/2 DoH 需要 `httpx[http2]`（`requirements.txt` 已固定为 0.24.1）。

### CSV 字段

| 字段 | 说明 |
| --- | --- |
| `域名` | 小写、去掉末尾点 |
| `首次收录时间` | 第一次在 AG 日志中命中 CF 段的时间 |
| `最后访问时间` | 最近一次在 AG 日志中命中 CF 段的时间（DoH 复检不会更新它） |
| `最近命中IP` | 最近一次 AG 命中或 DoH 复检得到的 CF IPv4 |
| `命中IP段` | 该 IP 所属的 CF CIDR |
| `累计命中次数` | 每次运行在 AG 日志窗口内命中次数的累计值，可近似看作活跃度 |
| `最近验证时间` | 最近一次 DoH 复检时间 |
| `验证状态` | 最终 CSV 中为 `通过` / `解析失败` / `待验证`；`未通过` 和 `无解析` 会进入剔除审计 |
| `备注` | `解析失败` 的原因 |

### 剔除规则

1. **7 天未访问**：按 `最后访问时间` 计算，达到 `STALE_DAYS` 天即删除（默认 `>= 7 天`）。
2. **DoH 复检不通过**：
   - 组内只要有任意一个 DoH 返回的 A 记录落在 CF 段：保留；
   - 所有拿到 A 记录的 DoH 都不在 CF 段：删除；
   - 所有 DoH 都明确返回 NXDOMAIN / 无 A 记录：删除；
   - 全部 DoH 请求异常、无法判断：**保留**，状态记为 `解析失败`，下次再复检。

`cf_domains_removed.csv` 记录被删除域名、删除时间与原因。

## `cf_best_hosts.py`：生成优选 Hosts

`cf_best_hosts.py` 读取 `cf_domains.csv`，生成可直接给系统使用的 `cf_hosts.txt`：

```bash
python cf_best_hosts.py
```

流程：

1. 读取 `cf_domains.csv` 和排除域文件 `cf_hosts_exclude.txt`，先剔除命中排除项的域名及其所有更次级域名；
2. 解析 `PREFERRED_HOSTS` 中若干个优选地址的 A 记录，使用 `DOH_ENDPOINTS` 中的 DoH，汇总成 Cloudflare IPv4 候选池；
3. 对候选 IP 做 TCP 443 延迟测试，过滤掉不可用或延迟大于 `MAX_LATENCY_MS`（默认 1000ms）的 IP，取最快的前 `TOP_IP_COUNT` 个（默认 3）；
4. 单个域名默认使用最快 IP；
5. 同一注册域下存在多个域名时（`a.com`、`www.a.com`、`lib.a.com`、`test.lib.a.com` 视为同一域），按 `SAME_IP_PER_GROUP` 处理：`True` 时整组共用一个从 top3 随机选出的 IP，`False` 时每个域名各自随机；
6. 优选地址全部失效、或所有 IP 都超过延迟阈值时，输出空的 `cf_hosts.txt`。

排除规则：域名等于排除项，或域名以 `.<排除项>` 结尾时排除。例如排除 `t.example.com` 会排除 `t.example.com`、`t.t.example.com`，但不会排除 `www.example.com`。排除文件每行一个域名，空行和 `#` 注释会被忽略，支持写 `*.example.com`。

### 配置（脚本顶部）

| 变量 | 说明 |
| --- | --- |
| `PREFERRED_HOSTS` | 优选地址列表，默认 `cf.090227.xyz` |
| `DOH_ENDPOINTS` | 解析优选地址用的 DoH `223.5.5.5` |
| `EXCLUDE_PATH` | 排除域文件，默认 `cf_hosts_exclude.txt` |
| `TOP_IP_COUNT` | 采用最快 IP 的数量，默认 `3` |
| `SAME_IP_PER_GROUP` | `True`：同一注册域共用一个随机 IP；`False`：每个域名各自随机 |
| `MAX_LATENCY_MS` | 延迟阈值，默认 `1000` 毫秒 |
| `LATENCY_ATTEMPTS` | 每个 IP 的 TCP 测试次数，默认 3 次取中位数 |
| `SPEED_WORKERS` | 测速并发数，默认 16 |

`cf_best_hosts.py` 会动态加载同目录下的 `cf_domain_manager.py`，复用其 DoH 查询与 CF 网段判断。

## 整体注意事项

- AG 的查询日志需要在 AG 中启用，且日志保留时长要覆盖 `LOOKBACK_HOURS`。
- 域名很多时 DoH 复检会变慢，可调大 `DOH_WORKERS`；注意别把公共 DoH 打限流。
- 用 Excel 打开 `cf_domains.csv` 时脚本可能无法写回（Windows 文件占用），请先关闭 Excel。
- 脚本会把 AG 密码明文写在配置区，注意信息安全。