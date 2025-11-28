import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List

CONFIG_FILE = "rules.json"

@dataclass
class ScoringWeights:
    # Весовые коэффициенты для классификации цифровых следов.
    weight_user: int = 2
    weight_ip: int = 1
    weight_vpn_source: int = 1
    weight_auth_event: int = 1
    weight_sensitive_event: int = 1
    penalty_no_time: int = -1


@dataclass
class Config:
    # Конфигурация правил и параметров анализа логов.
    sensitive_keywords: List[str] = field(default_factory=lambda: [
        "/admin", "/secure", "/confidential", "secret", "topsecret"
    ])
    auth_keywords: List[str] = field(default_factory=lambda: [
        "/login", "/signin", "auth", "authenticate"
    ])
    file_transfer_threshold: int = 100_000  # байт
    session_window_minutes: int = 30
    # смещение времени (минуты) для разных источников
    time_offsets_minutes: Dict[str, int] = field(default_factory=lambda: {
        "web": 0,
        "proxy": 0,
        "vpn": 0,
    })
    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    # юридические описания классов значимости
    class_descriptions: Dict[str, str] = field(default_factory=lambda: {
        "A": "Сильный цифровой след: однозначная связка учётной записи, IP-адреса и времени, "
             "как правило, подтверждённая несколькими независимыми источниками. Может "
             "рассматриваться как одно из ключевых доказательств при наличии контекста.",
        "B": "Значимый цифровой след: содержит существенные сведения (например, факт "
             "аутентификации или доступа к защищённому ресурсу), но имеются отдельные "
             "неопределённости (один источник, отсутствие части данных). Требует "
             "подкрепления другими доказательствами.",
        "C": "Вспомогательный цифровой след: отдельные технические данные, которые сами по себе "
             "не позволяют надёжно связать событие с конкретным лицом, но полезны в "
             "совокупности с другой информацией.",
        "D": "Слабый или спорный цифровой след: неполные, неоднозначные или легко "
             "оспариваемые данные. Могут использоваться лишь как ориентировочная "
             "информация и не должны служить единственной основой для выводов."
    })


DEFAULT_CONFIG = Config()


def load_config(path: str = CONFIG_FILE) -> Config:
    # Загрузить конфиг из JSON, либо вернуть конфиг по умолчанию.
    if not os.path.exists(path):
        return DEFAULT_CONFIG

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return DEFAULT_CONFIG

    def get(key, default):
        return data.get(key, default)

    cfg = Config()
    cfg.sensitive_keywords = get("sensitive_keywords", cfg.sensitive_keywords)
    cfg.auth_keywords = get("auth_keywords", cfg.auth_keywords)
    cfg.file_transfer_threshold = get("file_transfer_threshold", cfg.file_transfer_threshold)
    cfg.session_window_minutes = get("session_window_minutes", cfg.session_window_minutes)
    cfg.time_offsets_minutes = get("time_offsets_minutes", cfg.time_offsets_minutes)

    scoring_data = data.get("scoring", {})
    scoring = ScoringWeights()
    scoring.weight_user = scoring_data.get("weight_user", scoring.weight_user)
    scoring.weight_ip = scoring_data.get("weight_ip", scoring.weight_ip)
    scoring.weight_vpn_source = scoring_data.get("weight_vpn_source", scoring.weight_vpn_source)
    scoring.weight_auth_event = scoring_data.get("weight_auth_event", scoring.weight_auth_event)
    scoring.weight_sensitive_event = scoring_data.get("weight_sensitive_event", scoring.weight_sensitive_event)
    scoring.penalty_no_time = scoring_data.get("penalty_no_time", scoring.penalty_no_time)
    cfg.scoring = scoring

    # юридические описания классов — обновляем только тем, что есть в файле
    cd = data.get("class_descriptions")
    if isinstance(cd, dict):
        cfg.class_descriptions.update(cd)
    return cfg

def save_config(config: Config, path: str = CONFIG_FILE) -> None:
    # Сохранить конфиг в JSON.
    data = asdict(config)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
