import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Callable
from models import LogEvent
from config_manager import Config

def parse_apache_time(time_str: str) -> Optional[datetime]:
    # Преобразовать время из Apache-логов вида '10/Nov/2025:13:55:36 +0100'.
    try:
        pure = time_str.split()[0]
        return datetime.strptime(pure, "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

def parse_iso_time(time_str: str) -> Optional[datetime]:
    # Формат: '2025-11-10T13:56:01'.
    try:
        return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None

# Регулярные выражения для логов
apache_pattern = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

proxy_pattern = re.compile(
    r'(?P<time>\S+) (?P<ip>\S+) (?P<method>\S+) '
    r'(?P<url>\S+) (?P<status>\d{3}) (?P<size>\d+)'
)

vpn_pattern = re.compile(
    r'(?P<time>\S+) '
    r'user=(?P<user>\S+) '
    r'ip=(?P<ip>\S+) '
    r'assigned=(?P<assigned>\S+) '
    r'action=(?P<action>\S+) '
    r'result=(?P<result>\S+)'
)

# Web-лог
def determine_web_event_type(url: str, status: int, size: int, user: Optional[str], cfg: Config) -> str:
    lower_url = url.lower()
    for kw in cfg.auth_keywords:
        if kw in lower_url:
            if status in (200, 302, 303):
                return "AUTH_SUCCESS"
            elif status in (401, 403):
                return "AUTH_FAILURE"
            else:
                return "AUTH_ATTEMPT"

    for kw in cfg.sensitive_keywords:
        if kw in lower_url:
            return "ACCESS_SENSITIVE"

    if size >= cfg.file_transfer_threshold:
        return "FILE_TRANSFER"

    if user and user != "-":
        return "ACCESS_AUTHENTICATED"

    return "ACCESS_OTHER"

def parse_web_log_line(line: str, cfg: Config) -> Optional[LogEvent]:
    m = apache_pattern.match(line)
    if not m:
        return None

    data = m.groupdict()
    ip = data.get("ip")
    user = data.get("user")
    if user == "-":
        user = None

    ts = parse_apache_time(data.get("time", ""))
    if ts is not None:
        offset_min = cfg.time_offsets_minutes.get("web", 0)
        ts = ts + timedelta(minutes=offset_min)

    status = int(data.get("status", "0"))
    size_str = data.get("size", "0")
    try:
        size = int(size_str) if size_str.isdigit() else 0
    except Exception:
        size = 0

    url = data.get("url", "-")

    event_type = determine_web_event_type(url, status, size, user, cfg)

    details = {
        "method": data.get("method", ""),
        "url": url,
        "status": str(status),
        "size": str(size),
    }

    return LogEvent(
        source="web",
        raw_line=line.rstrip("\n"),
        timestamp=ts,
        ip=ip,
        user=user,
        event_type=event_type,
        details=details,
    )


# Proxy-лог
def determine_proxy_event_type(url: str, status: int, size: int, cfg: Config) -> str:
    lower_url = url.lower()
    for kw in cfg.sensitive_keywords:
        if kw in lower_url:
            return "ACCESS_SENSITIVE"

    if size >= cfg.file_transfer_threshold:
        return "FILE_TRANSFER"

    return "PROXY_ACCESS"

def parse_proxy_log_line(line: str, cfg: Config) -> Optional[LogEvent]:
    m = proxy_pattern.match(line)
    if not m:
        return None

    data = m.groupdict()
    ts = parse_iso_time(data.get("time", ""))
    if ts is not None:
        offset_min = cfg.time_offsets_minutes.get("proxy", 0)
        ts = ts + timedelta(minutes=offset_min)

    ip = data.get("ip")
    url = data.get("url", "")
    status = int(data.get("status", "0"))
    size = int(data.get("size", "0"))
    event_type = determine_proxy_event_type(url, status, size, cfg)

    details = {
        "method": data.get("method", ""),
        "url": url,
        "status": str(status),
        "size": str(size),
    }

    return LogEvent(
        source="proxy",
        raw_line=line.rstrip("\n"),
        timestamp=ts,
        ip=ip,
        user=None,
        event_type=event_type,
        details=details,
    )


# VPN-лог
def parse_vpn_log_line(line: str, cfg: Config) -> Optional[LogEvent]:
    m = vpn_pattern.match(line)
    if not m:
        return None

    data = m.groupdict()
    ts = parse_iso_time(data.get("time", ""))
    if ts is not None:
        offset_min = cfg.time_offsets_minutes.get("vpn", 0)
        ts = ts + timedelta(minutes=offset_min)

    user = data.get("user")
    ip = data.get("ip")
    assigned = data.get("assigned")
    action = data.get("action")
    result = data.get("result")

    if action == "login":
        if result == "success":
            event_type = "AUTH_SUCCESS"
        else:
            event_type = "AUTH_FAILURE"
    else:
        event_type = "VPN_EVENT"

    details = {
        "assigned_ip": assigned,
        "action": action,
        "result": result,
    }

    return LogEvent(
        source="vpn",
        raw_line=line.rstrip("\n"),
        timestamp=ts,
        ip=ip,
        user=user,
        event_type=event_type,
        details=details,
    )


# Реестр парсеров (плагинная архитектура)
ParserFunc = Callable[[str, Config], Optional[LogEvent]]
PARSERS: Dict[str, ParserFunc] = {
    "web": parse_web_log_line,
    "proxy": parse_proxy_log_line,
    "vpn": parse_vpn_log_line,
}
