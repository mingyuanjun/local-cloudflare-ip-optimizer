# -*- coding: utf-8 -*-
"""
本地 Cloudflare CDN 优选域名维护

流程：
1. 从 AdGuard Home 查询日志中取最近 N 小时（默认 1 小时）的解析记录；
2. 找出 A 记录落在 Cloudflare IPv4 段（https://www.cloudflare.com/ips-v4）内的域名；
3. 合并写入 cf_domains.csv（域名、首次收录、最后访问时间、命中 IP/段、累计命中次数等）；
4. 剔除 CSV 中最后访问时间超过 STALE_DAYS 天（默认 7 天）的域名；
5. 用两个 DoH 逐个重新解析剩余域名，只要任一 DoH 命中 Cloudflare 段就保留，
   全部解析结果都不在 CF 段才剔除。
"""

import argparse
import base64
import csv
import ipaddress
import json
import logging
import os
import random
import re
import struct
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

# httpx + h2 用于 HTTP/2 DoH；未安装时自动退回标准库 HTTP/1.1
try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

try:
    import h2  # noqa: F401
    _HAS_H2 = True
except ImportError:  # pragma: no cover
    _HAS_H2 = False

# ============================================================================
# 配置区：按需修改
# ============================================================================

# AdGuard Home 管理地址（必改）：只需填到端口，不要带 /control
AG_URL = "http://127.0.0.1:3000"
AG_USERNAME = ""
AG_PASSWORD = ""

# 取最近多少小时的 AG 解析记录
LOOKBACK_HOURS = 1.0

# CSV 中最后访问时间达到多少天即剔除
STALE_DAYS = 7

# Cloudflare IPv4 段列表
CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
# 上面的地址被 WAF 拦截时使用的备用接口
CF_IPV4_FALLBACK_URL = "https://api.cloudflare.com/client/v4/ips"
# 本地缓存有效期（天），过期会重新下载；下载失败时继续沿用旧缓存
CF_CACHE_DAYS = 7

# 使用的 DoH
DOH_ENDPOINTS = [
    "https://223.5.5.5/dns-query",
]
# 是否优先使用 httpx 的 HTTP/2 通道；httpx/http2 不可用时自动退回 urllib
DOH_HTTP2 = True
DOH_TIMEOUT = 6          # 单个 DoH 请求超时（秒）
DOH_WORKERS = 6          # DoH 并发数

# AG 查询日志分页参数
AG_PAGE_SIZE = 500
AG_MAX_PAGES = 1000       # 防止异常情况下无限翻页
AG_TIMEOUT = 15

# 固定文件位置（相对脚本所在目录，不受启动目录影响）
BASE_DIR = Path(__file__).resolve().parent
CSV_PATH = BASE_DIR / "cf_domains.csv"
REMOVED_PATH = BASE_DIR / "cf_domains_removed.csv"
CF_CACHE_PATH = BASE_DIR / "cloudflare_ips_v4.txt"

HTTP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
TIME_FMT = "%Y-%m-%d %H:%M:%S"
CSV_FIELDS = [
    "域名",
    "首次收录时间",
    "最后访问时间",
    "最近命中IP",
    "命中IP段",
    "累计命中次数",
    "最近验证时间",
    "验证状态",
    "备注",
]

LOG = logging.getLogger("cf-cdn")
# httpx 默认会把每个请求打到 INFO，这里压到 WARNING，避免刷屏
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ============================================================================
# 通用工具
# ============================================================================


def parse_ag_time(value):
    """解析 AdGuard Home 的 RFC3339 时间，返回本地时区的 naive datetime。"""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # 兼容 +0800 这种没有冒号的时区写法
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    # Go 的 RFC3339Nano 可能有 9 位小数，fromisoformat 只接受 6 位
    text = re.sub(r"\.(\d{1,9})", lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def parse_csv_time(value):
    """解析 CSV 中记录的时间，返回 naive datetime。"""
    if not value:
        return None
    text = str(value).strip()
    for fmt in (TIME_FMT, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def fmt_time(dt):
    return dt.strftime(TIME_FMT) if dt else ""


def normalize_domain(name):
    if not name:
        return None
    domain = str(name).strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        return None
    if any(ch.isspace() for ch in domain):
        return None
    return domain


def _url_host(url):
    return urlsplit(url).netloc or url


# ============================================================================
# Cloudflare IPv4 段
# ============================================================================


def _download(url, timeout=20, accept="text/plain"):
    req = urllib.request.Request(url, headers={"User-Agent": HTTP_UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _download_cf_range_text():
    errors = []
    try:
        return _download(CF_IPV4_URL, accept="text/plain")
    except Exception as exc:  # noqa: BLE001
        errors.append("%s: %s" % (CF_IPV4_URL, exc))
    try:
        payload = json.loads(_download(CF_IPV4_FALLBACK_URL, accept="application/json"))
        cidrs = (payload.get("result") or {}).get("ipv4_cidrs") or []
        if cidrs:
            return "\n".join(cidrs) + "\n"
        errors.append("%s: 返回内容中没有 ipv4_cidrs" % CF_IPV4_FALLBACK_URL)
    except Exception as exc:  # noqa: BLE001
        errors.append("%s: %s" % (CF_IPV4_FALLBACK_URL, exc))
    raise RuntimeError("Cloudflare 段下载失败：" + "；".join(errors))


def _parse_cf_networks(text):
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            LOG.warning("忽略无法识别的 CF 段：%s", line)
            continue
        if network.version == 4:
            networks.append(network)
    if not networks:
        raise RuntimeError("Cloudflare 段列表为空或格式不正确")
    return networks


def load_cf_networks():
    """读取 CF 段：优先使用未过期缓存，否则下载并刷新缓存。"""
    text = None
    cache_age_days = None
    if CF_CACHE_PATH.exists():
        cache_age_days = (datetime.now() - datetime.fromtimestamp(CF_CACHE_PATH.stat().st_mtime)).total_seconds() / 86400.0
        if cache_age_days < CF_CACHE_DAYS:
            try:
                text = CF_CACHE_PATH.read_text(encoding="utf-8-sig")
                LOG.info("使用本地 CF 段缓存（%.1f 天前更新）：%s", cache_age_days, CF_CACHE_PATH.name)
            except OSError as exc:
                LOG.warning("读取 CF 段缓存失败：%s", exc)

    if text is None:
        try:
            text = _download_cf_range_text()
            CF_CACHE_PATH.write_text(text, encoding="utf-8")
            LOG.info("已更新 CF IPv4 段缓存：%s", CF_CACHE_PATH.name)
        except Exception as exc:  # noqa: BLE001
            if CF_CACHE_PATH.exists():
                LOG.warning("CF 段下载失败，继续使用旧缓存（%.1f 天前）：%s", cache_age_days or 0, exc)
                text = CF_CACHE_PATH.read_text(encoding="utf-8-sig")
            else:
                raise RuntimeError("无法获取 Cloudflare IPv4 段，且没有本地缓存：%s" % exc)

    networks = _parse_cf_networks(text)
    LOG.info("已加载 Cloudflare IPv4 段 %d 条", len(networks))
    return networks


def cf_match(ip_texts, networks):
    """返回 (命中的 IPv4, 对应 CIDR)，没有命中返回 (None, None)。"""
    for ip_text in ip_texts:
        try:
            ip = ipaddress.ip_address(str(ip_text).strip())
        except ValueError:
            continue
        if ip.version != 4:
            continue
        for network in networks:
            if ip in network:
                return str(ip), str(network)
    return None, None


# ============================================================================
# AdGuard Home 查询日志
# ============================================================================


def _ag_request_json(url):
    headers = {"Accept": "application/json", "User-Agent": HTTP_UA}
    if AG_USERNAME:
        token = base64.b64encode(("%s:%s" % (AG_USERNAME, AG_PASSWORD)).encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=AG_TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise RuntimeError("AdGuard Home 认证失败（401），请检查 AG_USERNAME / AG_PASSWORD") from exc
        raise RuntimeError("AdGuard Home 请求失败：HTTP %s，%s" % (exc.code, url)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("无法连接 AdGuard Home：%s（%s）" % (url, exc.reason)) from exc
    except OSError as exc:
        raise RuntimeError("无法连接 AdGuard Home：%s（%s）" % (url, exc)) from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise RuntimeError("AdGuard Home 返回的不是有效 JSON：%s" % url) from exc


def fetch_ag_hits(cutoff, networks):
    """
    拉取 AG 日志并按域名聚合 CF 命中记录。

    返回 (hits, total_rows, window_rows)，hits 结构：
    {domain: {"first": datetime, "last": datetime, "count": int, "ip": str, "cidr": str}}
    """
    base = AG_URL.rstrip("/")
    hits = {}
    total_rows = 0
    window_rows = 0
    offset = 0
    pages = 0
    stop = False

    while pages < AG_MAX_PAGES and not stop:
        url = "%s/control/querylog?limit=%d&offset=%d" % (base, AG_PAGE_SIZE, offset)
        payload = _ag_request_json(url)
        rows = payload.get("data") or []
        if not rows:
            break
        pages += 1
        total_rows += len(rows)

        for row in rows:
            entry_time = parse_ag_time(row.get("time"))
            if entry_time is None:
                continue
            if entry_time < cutoff:
                # 日志按时间倒序返回，遇到窗口外的记录即可停止
                stop = True
                continue
            window_rows += 1

            question = row.get("question") or {}
            domain = normalize_domain(question.get("name"))
            if not domain:
                continue
            answers = row.get("answer") or []
            ip_texts = [
                item.get("value")
                for item in answers
                if str(item.get("type") or "").upper() == "A" and item.get("value")
            ]
            if not ip_texts:
                continue
            ip, cidr = cf_match(ip_texts, networks)
            if not ip:
                continue

            hit = hits.get(domain)
            if hit is None:
                hits[domain] = {"first": entry_time, "last": entry_time, "count": 1, "ip": ip, "cidr": cidr}
            else:
                if entry_time < hit["first"]:
                    hit["first"] = entry_time
                if entry_time >= hit["last"]:
                    hit["last"] = entry_time
                    hit["ip"] = ip
                    hit["cidr"] = cidr
                hit["count"] += 1

        if stop:
            break
        offset += len(rows)

    if pages >= AG_MAX_PAGES:
        LOG.warning("AG 日志翻页达到上限 %d 页，可能未取完整窗口", AG_MAX_PAGES)
    LOG.info("AG 日志读取 %d 页、%d 条，其中时间窗口内 %d 条", pages, total_rows, window_rows)
    return hits, total_rows, window_rows


# ============================================================================
# DNS over HTTPS 查询（RFC 8484 wire format，纯标准库实现）
# ============================================================================


def _encode_dns_name(domain):
    chunks = []
    for label in domain.rstrip(".").split("."):
        if not label:
            raise ValueError("非法域名：%s" % domain)
        raw = label.encode("ascii") if label.isascii() else label.encode("idna")
        if len(raw) > 63:
            raise ValueError("域名标签过长：%s" % domain)
        chunks.append(bytes([len(raw)]) + raw)
    name = b"".join(chunks) + b"\x00"
    if len(name) > 255:
        raise ValueError("域名过长：%s" % domain)
    return name


def build_dns_query(domain):
    qid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)  # RD=1，带一条 OPT
    question = _encode_dns_name(domain) + struct.pack("!HH", 1, 1)  # A IN
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)  # EDNS0，UDP payload 1232
    return qid, header + question + opt


def _skip_dns_name(packet, offset):
    limit = len(packet)
    while True:
        if offset >= limit:
            raise ValueError("DNS 报文截断")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= limit:
                raise ValueError("DNS 压缩指针截断")
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def parse_dns_response(packet, qid):
    """解析 DNS 响应，返回 (rcode, [IPv4...])。"""
    if len(packet) < 12:
        raise ValueError("DNS 响应过短")
    resp_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if resp_id != qid:
        raise ValueError("DNS 响应 ID 不匹配")
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(packet, offset)
        offset += 4
    ips = []
    for _ in range(ancount):
        offset = _skip_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("DNS 响应记录截断")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + rdlen > len(packet):
            raise ValueError("DNS 响应记录数据截断")
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ips.append(str(ipaddress.IPv4Address(packet[offset:offset + 4])))
        offset += rdlen
    return rcode, ips


_HTTPX_LOCAL = threading.local()


def _get_httpx_client():
    """每个线程复用一个 httpx.Client，复用 HTTP/2 连接。"""
    client = getattr(_HTTPX_LOCAL, "client", None)
    if client is None:
        client = httpx.Client(http2=True, timeout=DOH_TIMEOUT)
        _HTTPX_LOCAL.client = client
    return client


def _use_httpx():
    return bool(DOH_HTTP2 and httpx is not None and _HAS_H2)


def query_doh(url, domain, timeout=DOH_TIMEOUT):
    qid, query = build_dns_query(domain)
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": HTTP_UA,
    }

    if _use_httpx():
        response = _get_httpx_client().post(url, content=query, headers=headers, timeout=timeout)
        if response.status_code != 200:
            raise RuntimeError("HTTP %d" % response.status_code)
        return parse_dns_response(response.content, qid)

    headers["Connection"] = "close"
    req = urllib.request.Request(url, data=query, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return parse_dns_response(body, qid)


def resolve_via_group(domain, networks):
    """
    依次用两个 DoH 解析域名 A 记录，并用 CF 段判断归属。

    判定规则：只要有任意一个 DoH 返回的 A 记录落在 CF 段，就认为域名仍然
    属于 Cloudflare（不同 DoH 的解析结果可能不一致）。

    返回 (status, ips, cidr, detail)：
      status="ok"      找到 CF IP，ips=[该 IP]，cidr=所属段
      status="not_cf"  有 A 记录，但所有 DoH 的结果都不在 CF 段
      status="empty"   所有 DoH 都明确返回无 A 记录 / NXDOMAIN
      status="error"   全部 DoH 请求异常，无法判断
    """
    urls = DOH_ENDPOINTS
    if not urls:
        raise RuntimeError("DOH_ENDPOINTS 为空")

    details = []
    seen_ips = []
    saw_answer = False
    saw_empty = False

    for url in urls:
        host = _url_host(url)
        try:
            rcode, ips = query_doh(url, domain)
        except Exception as exc:  # noqa: BLE001
            details.append("%s: %s" % (host, type(exc).__name__))
            continue

        if rcode == 0:
            if not ips:
                saw_empty = True
                details.append("%s: 无 A 记录" % host)
                continue
            saw_answer = True
            seen_ips.extend(ips)
            ip, cidr = cf_match(ips, networks)
            if ip:
                return "ok", [ip], cidr, ""
            details.append("%s: %s" % (host, ",".join(ips[:3])))
        elif rcode == 3:
            saw_empty = True
            details.append("%s: NXDOMAIN" % host)
        else:
            details.append("%s: rcode=%d" % (host, rcode))

    if saw_answer:
        unique_ips = list(dict.fromkeys(seen_ips))
        return "not_cf", unique_ips, "", "；".join(details)
    if saw_empty:
        return "empty", [], "", "；".join(details)
    return "error", [], "", "；".join(details)


# ============================================================================
# CSV 维护
# ============================================================================


def load_records(path):
    records = {}
    path = Path(path)
    if not path.exists():
        return records
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return records
        for row in reader:
            domain = normalize_domain(row.get("域名"))
            if not domain:
                continue
            record = {field: (row.get(field) or "").strip() for field in CSV_FIELDS}
            record["域名"] = domain
            records[domain] = record
    return records


def write_records(records, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    ordered = sorted(records.values(), key=lambda item: item.get("最后访问时间") or "", reverse=True)
    try:
        with open(tmp, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for record in ordered:
                writer.writerow(record)
        os.replace(str(tmp), str(path))
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise RuntimeError("写入 CSV 失败（文件可能正被 Excel 占用）：%s，%s" % (path, exc)) from exc


def append_removed(rows):
    if not rows:
        return
    path = REMOVED_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists() or path.stat().st_size == 0
    try:
        with open(path, "w" if is_new else "a", encoding="utf-8-sig" if is_new else "utf-8", newline="") as fh:
            writer = csv.writer(fh)
            if is_new:
                writer.writerow(["域名", "最后访问时间", "剔除时间", "剔除原因"])
            writer.writerows(rows)
    except OSError as exc:
        LOG.warning("写剔除记录失败（不影响主 CSV）：%s（%s）", path, exc)


def merge_hits(records, hits):
    """把本次 AG 命中合并进 CSV 记录，返回 (新增数, 更新数)。"""
    added = 0
    updated = 0
    for domain, hit in hits.items():
        record = records.get(domain)
        if record is None:
            records[domain] = {
                "域名": domain,
                "首次收录时间": fmt_time(hit["first"]),
                "最后访问时间": fmt_time(hit["last"]),
                "最近命中IP": hit["ip"],
                "命中IP段": hit["cidr"],
                "累计命中次数": str(hit["count"]),
                "最近验证时间": "",
                "验证状态": "待验证",
                "备注": "",
            }
            added += 1
            continue

        old_last = parse_csv_time(record.get("最后访问时间"))
        old_first = parse_csv_time(record.get("首次收录时间"))
        record["最后访问时间"] = fmt_time(max(old_last, hit["last"]) if old_last else hit["last"])
        record["首次收录时间"] = fmt_time(min(old_first, hit["first"]) if old_first else hit["first"])
        record["最近命中IP"] = hit["ip"]
        record["命中IP段"] = hit["cidr"]
        try:
            record["累计命中次数"] = str(int(record.get("累计命中次数") or 0) + hit["count"])
        except ValueError:
            record["累计命中次数"] = str(hit["count"])
        record["验证状态"] = "待验证"
        record["备注"] = ""
        updated += 1
    return added, updated


def prune_records(records, now, stale_days):
    """剔除最后访问时间达到 stale_days 天的记录，返回审计行。"""
    removed = []
    for domain, record in list(records.items()):
        last_seen = parse_csv_time(record.get("最后访问时间"))
        if last_seen is None:
            # 没有可解析的最后访问时间（例如手工添加），不按时间清理
            continue
        age_days = (now - last_seen).total_seconds() / 86400.0
        if age_days >= stale_days:
            removed.append((domain, record.get("最后访问时间", ""), fmt_time(now), "超过 %g 天未访问" % stale_days))
            del records[domain]
    return removed


# ============================================================================
# DoH 复检
# ============================================================================


def verify_records(records, networks):
    """用 DoH 复检所有域名，剔除已不在 CF 段的记录，返回审计行。"""
    if not records:
        return []
    if not DOH_ENDPOINTS:
        raise RuntimeError("DOH_ENDPOINTS 为空")
    total = len(records)
    LOG.info("开始 DoH 复检 %d 个域名（%d 个 DoH，并发 %d）", total, len(DOH_ENDPOINTS), DOH_WORKERS)

    results = {}
    with ThreadPoolExecutor(max_workers=max(1, int(DOH_WORKERS))) as pool:
        future_map = {pool.submit(resolve_via_group, domain, networks): domain for domain in records}
        finished = 0
        for future in as_completed(future_map):
            domain = future_map[future]
            try:
                status, ips, cidr, detail = future.result()
            except Exception as exc:  # noqa: BLE001
                status, ips, cidr, detail = "error", [], "", "%s: %s" % (type(exc).__name__, exc)
            results[domain] = (status, ips, cidr, detail)
            finished += 1
            if finished % 25 == 0 or finished == total:
                LOG.info("DoH 复检进度 %d/%d", finished, total)

    removed = []
    verified = 0
    failed = 0
    now_text = fmt_time(datetime.now())
    for domain, (status, ips, cidr, detail) in results.items():
        record = records.get(domain)
        if record is None:
            continue
        record["最近验证时间"] = now_text

        if status == "ok":
            record["最近命中IP"] = ips[0]
            record["命中IP段"] = cidr
            record["验证状态"] = "通过"
            record["备注"] = ""
            verified += 1
        elif status == "not_cf":
            reason = "DoH 解析 %s 不在 CF 段" % ", ".join(ips[:3])
            record["验证状态"] = "未通过"
            record["备注"] = reason
            removed.append((domain, record.get("最后访问时间", ""), now_text, reason))
            del records[domain]
        elif status == "empty":
            record["验证状态"] = "无解析"
            record["备注"] = detail[:300]
            removed.append((domain, record.get("最后访问时间", ""), now_text, "DoH 无 A 记录"))
            del records[domain]
        else:
            record["验证状态"] = "解析失败"
            record["备注"] = detail[:300]
            failed += 1
            if failed <= 20:
                LOG.warning("DoH 解析失败，保留待下次复检：%s（%s）", domain, detail[:200])

    if failed > 20:
        LOG.warning("另有 %d 个域名 DoH 解析失败，均已保留，待下次复检", failed - 20)
    LOG.info("DoH 复检完成：通过 %d，剔除 %d，解析失败保留 %d", verified, len(removed), failed)
    return removed


# ============================================================================
# 主流程
# ============================================================================


def run(hours=None, stale_days=None, skip_doh=False, csv_path=None):
    hours = LOOKBACK_HOURS if hours is None else float(hours)
    stale_days = STALE_DAYS if stale_days is None else float(stale_days)
    csv_file = Path(csv_path) if csv_path else CSV_PATH

    started = datetime.now()
    LOG.info("=" * 60)
    LOG.info("本地 Cloudflare CDN 优选 开始：窗口 %.2f 小时，失效 %g 天", hours, stale_days)
    LOG.info("AdGuard Home：%s", AG_URL)
    LOG.info("CSV：%s", csv_file)
    if not DOH_HTTP2:
        LOG.info("DOH_HTTP2=False，DoH 使用标准库 HTTP/1.1")
    elif httpx is None:
        LOG.warning("未安装 httpx[http2]，"
                    "请执行 pip install \"httpx[http2]\"")
    elif not _HAS_H2:
        LOG.warning("httpx 已安装但缺少 h2，DoH 只能走 HTTP/1.1；请执行 pip install \"httpx[http2]\"")

    try:
        networks = load_cf_networks()
    except Exception as exc:  # noqa: BLE001
        LOG.error("%s", exc)
        return 2

    records = load_records(csv_file)
    LOG.info("CSV 现有域名 %d 个", len(records))

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).astimezone().replace(tzinfo=None)
    LOG.info("AG 日志时间窗口：%s ~ %s", fmt_time(cutoff), fmt_time(started))

    try:
        hits, total_rows, window_rows = fetch_ag_hits(cutoff, networks)
    except Exception as exc:  # noqa: BLE001
        LOG.error("获取 AG 日志失败，本次不修改 CSV：%s", exc)
        return 2

    LOG.info("窗口内命中 Cloudflare 段的域名 %d 个", len(hits))
    added, updated = merge_hits(records, hits)
    LOG.info("CSV 合并：新增 %d，更新 %d，当前共 %d", added, updated, len(records))

    stale_rows = prune_records(records, datetime.now(), stale_days)
    if stale_rows:
        LOG.info("按 %g 天未访问清理：%d 个", stale_days, len(stale_rows))
    try:
        write_records(records, csv_file)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 3

    removed = list(stale_rows)
    if not skip_doh:
        try:
            removed.extend(verify_records(records, networks))
        except Exception as exc:  # noqa: BLE001
            LOG.exception("DoH 复检异常，保留当前 CSV：%s", exc)
        try:
            write_records(records, csv_file)
        except RuntimeError as exc:
            LOG.error("%s", exc)
            return 3
    else:
        LOG.info("已跳过 DoH 复检（--skip-doh）")

    append_removed(removed)
    LOG.info("-" * 60)
    LOG.info("完成：CSV 共 %d 个域名；本次剔除 %d 个；耗时 %.1f 秒", len(records), len(removed),
             (datetime.now() - started).total_seconds())
    LOG.info("=" * 60)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="从 AdGuard Home 日志维护本地 Cloudflare CDN 优选域名")
    parser.add_argument("--hours", type=float, default=None, help="AG 日志回看小时数，默认 %.2f" % LOOKBACK_HOURS)
    parser.add_argument("--stale-days", type=float, default=None, help="超过多少天未访问即剔除，默认 %g" % STALE_DAYS)
    parser.add_argument("--skip-doh", action="store_true", help="只维护 AG 日志与 CSV，不做 DoH 复检")
    parser.add_argument("--csv", default=None, help="CSV 路径，默认脚本目录下 cf_domains.csv")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    return run(hours=args.hours, stale_days=args.stale_days, skip_doh=args.skip_doh, csv_path=args.csv)


if __name__ == "__main__":
    sys.exit(main())
