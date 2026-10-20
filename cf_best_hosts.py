# -*- coding: utf-8 -*-
"""
CF 优选 Hosts 输出

从 cf_domains.csv 读取域名，按以下步骤生成 cf_hosts.txt：
1. 解析若干「优选地址」的 A 记录，汇总成 Cloudflare IPv4 候选池；
2. 对候选 IP 做 TCP 443 延迟测试，取速度最快的前 N 个（默认 3 个）；
3. 单域名默认使用最快 IP；同一注册域下多个域名则从前 N 个中随机分配；
4. 优选地址全部失效、或所有候选 IP 延迟都大于阈值（默认 1000ms）时，
   输出空的 cf_hosts.txt。

依赖同目录下的 cf_domain_manager.py 提供 DoH 与 CF 段判断。
"""

import argparse
import csv
import importlib.util
import ipaddress
import logging
import os
import random
import socket
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ============================================================================
# 配置区：按需修改
# ============================================================================

# 优选地址：脚本会解析这些域名的 A 记录，汇总成候选 IP 池
PREFERRED_HOSTS = [
    "cf.090227.xyz",
]

# 解析优选地址使用的 DoH
DOH_ENDPOINTS = [
    "https://223.5.5.5/dns-query",
]

# 取速度最快的几个 IP 作为 hosts 可用地址
TOP_IP_COUNT = 3

# 同一注册域下有多个域名时：
#   True  = 整组共用一个从 top N 中随机选出的 IP
#   False = 每个域名各自从 top N 中随机选一个 IP
SAME_IP_PER_GROUP = False

# 延迟阈值（毫秒）：大于该值的 IP 不采用；全部超过则输出空 hosts
MAX_LATENCY_MS = 1000

# 测速参数：TCP 连接端口、尝试次数、单次超时
LATENCY_PORT = 443
LATENCY_ATTEMPTS = 3
LATENCY_TIMEOUT = 2.0
SPEED_WORKERS = 16

# 文件位置（相对脚本所在目录）
BASE_DIR = Path(__file__).resolve().parent
CSV_PATH = BASE_DIR / "cf_domains.csv"
HOSTS_PATH = BASE_DIR / "cf_hosts.txt"
EXCLUDE_PATH = BASE_DIR / "cf_hosts_exclude.txt"

# 筛选脚本
FILTER_MODULE_CANDIDATES = [
    BASE_DIR / "cf_domain_manager.py",
]

TIME_FMT = "%Y-%m-%d %H:%M:%S"
LOG = logging.getLogger("cf-hosts")

# 常见多级后缀：用于把子域名归到同一个注册域
MULTI_LEVEL_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "com.tw", "com.mo",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "ne.jp", "or.jp",
    "co.kr", "or.kr",
    "com.au", "net.au", "org.au",
    "co.nz", "net.nz",
    "com.sg", "com.my", "com.br", "com.ru", "com.tr", "com.mx",
    "com.ar", "co.in", "co.za", "com.es", "com.fr", "com.de",
    "co.il", "com.sa", "com.ua", "com.pl", "com.vn", "com.ph",
    "com.pk", "com.bd", "com.np", "com.kw", "com.qa", "com.om",
    "com.bh", "com.jo", "com.lb", "com.cy", "com.mt", "com.gr",
    "com.pt", "com.it", "com.se", "com.no", "com.dk", "com.fi",
    "com.nl", "com.be", "com.ch", "com.at", "com.ie", "com.cz",
    "com.sk", "com.hu", "com.ro", "com.bg", "com.hr", "com.si",
    "com.rs", "com.ba", "com.mk", "com.al", "com.ee", "com.lv",
    "com.lt", "com.by", "com.kz", "com.uz", "com.az", "com.ge",
    "com.am", "com.md",
}


def load_filter_module():
    """加载同目录的筛选脚本，复用其 DoH 查询和 CF 段判断。"""
    for path in FILTER_MODULE_CANDIDATES:
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location("cf_domain_filter_module", str(path))
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, path
    raise RuntimeError("找不到筛选脚本：%s" % " / ".join(str(p) for p in FILTER_MODULE_CANDIDATES))


def load_domains(path):
    """读取 cf_domains.csv 中的域名，去重、转小写。"""
    if not path.exists():
        LOG.warning("CSV 不存在：%s", path)
        return []

    domains = set()
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            domain = (row.get("域名") or row.get("domain") or "").strip().rstrip(".").lower()
            if not domain or any(ch.isspace() for ch in domain):
                continue
            try:
                ipaddress.ip_address(domain)
                continue  # 跳过 IP 字面量
            except ValueError:
                pass
            domains.add(domain)
    return sorted(domains)


def load_exclusions(path):
    """读取排除域 txt；每行一个域名，# 开头为注释。"""
    if not path.exists():
        LOG.info("排除域文件不存在，跳过：%s", path)
        return []

    entries = set()
    with open(path, "r", encoding="utf-8-sig") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            domain = line.rstrip(".").lower()
            if domain.startswith("*."):
                domain = domain[2:]
            if not domain or any(ch.isspace() for ch in domain):
                LOG.warning("忽略无效排除项：%s", raw.strip())
                continue
            entries.add(domain)
    return sorted(entries)


def match_exclusion(domain, exclusions):
    """返回命中的排除域；domain 等于排除域或属于其更次级域名才算命中。"""
    for suffix in exclusions:
        if domain == suffix or domain.endswith("." + suffix):
            return suffix
    return ""


def filter_excluded(domains, exclusions):
    """过滤掉排除域及其所有更次级域名，返回 (保留, [(被排除域名, 命中项)])。"""
    if not exclusions:
        return list(domains), []
    kept = []
    removed = []
    for domain in domains:
        hit = match_exclusion(domain, exclusions)
        if hit:
            removed.append((domain, hit))
        else:
            kept.append(domain)
    return kept, removed


def registrable_domain(domain):
    """
    按注册域把子域名归组：
    """
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    suffix = ".".join(labels[-2:])
    if suffix in MULTI_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def resolve_preferred(cf, networks, preferred_hosts):
    """解析所有优选地址的 A 记录，返回属于 CF 段的 IPv4 候选池。"""
    endpoints = list(DOH_ENDPOINTS)
    if not endpoints:
        LOG.error("DOH_ENDPOINTS 为空")
        return []

    pool = set()
    timeout = getattr(cf, "DOH_TIMEOUT", 8)
    for host in preferred_hosts:
        found = set()
        for url in endpoints:
            try:
                rcode, ips = cf.query_doh(url, host, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                LOG.debug("DoH %s 解析 %s 失败：%s", url, host, exc)
                continue
            if rcode == 0:
                found.update(ips)

        valid = []
        for ip_text in sorted(found):
            try:
                ip = ipaddress.ip_address(ip_text)
            except ValueError:
                continue
            if ip.version != 4:
                continue
            matched, _cidr = cf.cf_match([str(ip)], networks)
            if matched:
                valid.append(str(ip))

        if valid:
            LOG.info("优选地址 %s：%d 个 CF IPv4（%s）", host, len(valid), ", ".join(valid))
        else:
            LOG.warning("优选地址 %s 未解析到有效 CF IPv4", host)
        pool.update(valid)

    LOG.info("候选 IP 池：%d 个", len(pool))
    return sorted(pool)


def tcp_latency(ip):
    """多次 TCP 连接取中位数，返回毫秒；全部失败返回 None。"""
    samples = []
    attempts = max(1, int(LATENCY_ATTEMPTS))
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, LATENCY_PORT), timeout=LATENCY_TIMEOUT):
                samples.append((time.perf_counter() - start) * 1000.0)
        except OSError:
            continue
    if not samples:
        return None
    return statistics.median(samples)


def measure_all(ips):
    """并发测速，返回 {ip: 毫秒或 None}。"""
    results = {}
    workers = max(1, min(int(SPEED_WORKERS), len(ips)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(tcp_latency, ip): ip for ip in ips}
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                latency = future.result()
            except Exception as exc:  # noqa: BLE001
                LOG.debug("测速异常 %s：%s", ip, exc)
                latency = None
            results[ip] = latency
            if latency is None:
                LOG.info("测速 %-15s 不可用", ip)
            else:
                LOG.info("测速 %-15s %7.1f ms", ip, latency)
    return results


def assign_ips(domains, top_ips):
    """
    单域名用最快 IP；同一注册域下多个域名从 top N 随机。
    SAME_IP_PER_GROUP=True 时整组共用一个随机 IP，否则每个域名各自随机。
    top_ips: [(ip, latency), ...]，按速度升序。
    """
    groups = {}
    for domain in domains:
        groups.setdefault(registrable_domain(domain), []).append(domain)

    assignments = {}
    ips = [ip for ip, _latency in top_ips]
    for root, members in sorted(groups.items()):
        members = sorted(members)
        if len(members) == 1:
            assignments[members[0]] = top_ips[0][0]
            continue

        if SAME_IP_PER_GROUP:
            chosen = random.choice(ips)
            LOG.info("同域多域名 %s（%d 个）共用随机 IP %s", root, len(members), chosen)
            for domain in members:
                assignments[domain] = chosen
            continue

        shuffled = list(ips)
        random.shuffle(shuffled)
        LOG.info("同域多域名 %s（%d 个），逐个从 top%d 随机分配", root, len(members), len(shuffled))
        for index, domain in enumerate(members):
            assignments[domain] = shuffled[index % len(shuffled)]
    return assignments


def write_hosts(path, assignments, top_ips, candidate_count, usable_count):
    """写 hosts；没有可用 IP 或没有域名时写空文件。"""
    if not assignments or not top_ips:
        text = ""
    else:
        if SAME_IP_PER_GROUP:
            group_note = "# 同一注册域下多个域名共用一个随机 IP；不同注册域可能恰好相同"
        else:
            group_note = "# 同一注册域下多个域名各自从 top N 随机分配；不同注册域可能恰好相同"
        lines = [
            "# Cloudflare 优选 Hosts",
            "# 生成时间: %s" % datetime.now().strftime(TIME_FMT),
            "# 候选 IP: %d，可用: %d，采用前 %d" % (candidate_count, usable_count, len(top_ips)),
            group_note,
        ]
        for rank, (ip, latency) in enumerate(top_ips, 1):
            lines.append("#   %d. %-15s %7.1f ms" % (rank, ip, latency))
        lines.append("")

        # 先按注册域排序，保证同一个域的域名连续；组内再按完整域名排序
        grouped = {}
        for domain in assignments:
            grouped.setdefault(registrable_domain(domain), []).append(domain)
        for root in sorted(grouped):
            for domain in sorted(grouped[root]):
                lines.append("%s %s" % (assignments[domain], domain))
        text = "\n".join(lines) + "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(str(tmp), str(path))
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise RuntimeError("写入 hosts 失败（文件可能被占用）：%s，%s" % (path, exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="根据 cf_domains.csv 生成 Cloudflare 优选 hosts")
    parser.add_argument("--top", type=int, default=TOP_IP_COUNT, help="采用速度最快的 IP 数量，默认 %d" % TOP_IP_COUNT)
    parser.add_argument("--max-ms", type=float, default=MAX_LATENCY_MS, help="延迟阈值（毫秒），默认 %g" % MAX_LATENCY_MS)
    parser.add_argument("--csv", default=None, help="输入 CSV，默认脚本目录下 cf_domains.csv")
    parser.add_argument("--hosts", default=None, help="输出 hosts，默认脚本目录下 cf_hosts.txt")
    parser.add_argument("--exclude", default=None, help="排除域 txt，默认脚本目录下 cf_hosts_exclude.txt")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt=TIME_FMT)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    csv_path = Path(args.csv) if args.csv else CSV_PATH
    hosts_path = Path(args.hosts) if args.hosts else HOSTS_PATH
    exclude_path = Path(args.exclude) if args.exclude else EXCLUDE_PATH
    top_count = max(1, int(args.top))
    max_latency = float(args.max_ms)

    try:
        domains = load_domains(csv_path)
        LOG.info("CSV 域名：%d 个（%s）", len(domains), csv_path)

        exclusions = load_exclusions(exclude_path)
        if exclusions:
            LOG.info("排除域：%d 项（%s）", len(exclusions), exclude_path)
        domains, removed = filter_excluded(domains, exclusions)
        for domain, hit in removed:
            LOG.info("排除域名 %s（命中 %s）", domain, hit)
        if removed:
            LOG.info("按排除域过滤掉 %d 个域名，剩余 %d 个", len(removed), len(domains))

        if not domains:
            LOG.warning("排除后没有域名，输出空 hosts")
            write_hosts(hosts_path, {}, [], 0, 0)
            return 0

        cf, module_path = load_filter_module()
        LOG.info("使用筛选模块：%s", module_path.name)
        networks = cf.load_cf_networks()

        candidates = resolve_preferred(cf, networks, PREFERRED_HOSTS)
        if not candidates:
            LOG.warning("所有优选地址都失效，输出空 hosts")
            write_hosts(hosts_path, {}, [], 0, 0)
            return 0

        LOG.info("开始测速 %d 个候选 IP（TCP %d，超时 %.1fs）", len(candidates), LATENCY_PORT, LATENCY_TIMEOUT)
        latencies = measure_all(candidates)
        usable = sorted(
            [(ip, ms) for ip, ms in latencies.items() if ms is not None and ms <= max_latency],
            key=lambda item: item[1],
        )
        if not usable:
            LOG.warning("所有候选 IP 均不可用或延迟大于 %g ms，输出空 hosts", max_latency)
            write_hosts(hosts_path, {}, [], len(candidates), 0)
            return 0

        top_ips = usable[:top_count]
        LOG.info("采用前 %d 个 IP：%s", len(top_ips),
                 ", ".join("%s(%.1fms)" % (ip, ms) for ip, ms in top_ips))

        assignments = assign_ips(domains, top_ips)
        write_hosts(hosts_path, assignments, top_ips, len(candidates), len(usable))
        LOG.info("完成：%d 个域名 -> %d 个 IP；hosts：%s",
                 len(assignments), len(set(assignments.values())), hosts_path)
        return 0
    except Exception as exc:  # noqa: BLE001
        LOG.exception("生成 hosts 失败：%s", exc)
        try:
            write_hosts(hosts_path, {}, [], 0, 0)
        except Exception:  # noqa: BLE001
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
