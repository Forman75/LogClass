from typing import List, Dict
from collections import Counter
from models import LogEvent
from config_manager import Config

def classify_event(event: LogEvent, cfg: Config) -> None:
    # Классификация события по юридической значимости (класс A/B/C/D).
    w = cfg.scoring
    score = 0
    reasons = []

    if event.user:
        score += w.weight_user
        reasons.append("есть учётная запись пользователя")

    if event.ip:
        score += w.weight_ip
        reasons.append("записан IP-адрес клиента")

    if event.source == "vpn":
        score += w.weight_vpn_source
        reasons.append("событие на VPN-сервере (обычно связка учётка-IP более надёжна)")

    if event.event_type in ("AUTH_SUCCESS", "AUTH_FAILURE", "AUTH_ATTEMPT"):
        score += w.weight_auth_event
        reasons.append("аутентификация / попытка входа")

    if event.event_type in ("ACCESS_SENSITIVE", "FILE_TRANSFER", "CONFIG_CHANGE"):
        score += w.weight_sensitive_event
        reasons.append("доступ к чувствительному ресурсу или изменение конфигурации")

    if event.timestamp is None:
        score += w.penalty_no_time
        reasons.append("не удалось однозначно определить время события")

    if score >= 4:
        event.evidential_class = "A"
    elif score >= 2:
        event.evidential_class = "B"
    elif score >= 1:
        event.evidential_class = "C"
    else:
        event.evidential_class = "D"
        if not reasons:
            reasons.append("недостаточно данных для уверенной юридической оценки")

    event.notes = "; ".join(reasons)


def classify_events(events: List[LogEvent], cfg: Config) -> None:
    for ev in events:
        classify_event(ev, cfg)


def compute_class_stats(events: List[LogEvent]) -> Dict[str, int]:
    counter = Counter()
    for ev in events:
        if ev.evidential_class:
            counter[ev.evidential_class] += 1
    return dict(counter)


def compute_source_stats(events: List[LogEvent]) -> Dict[str, int]:
    counter = Counter()
    for ev in events:
        counter[ev.source] += 1
    return dict(counter)
