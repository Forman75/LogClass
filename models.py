from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List


@dataclass
class LogEvent:
    # Нормализованное событие лога.
    source: str                 # 'web', 'proxy', 'vpn'
    raw_line: str
    timestamp: Optional[datetime]
    ip: Optional[str]
    user: Optional[str]
    event_type: str             # строковый тип: AUTH_SUCCESS, ACCESS_SENSITIVE
    details: Dict[str, str] = field(default_factory=dict)
    evidential_class: str = ""  # 'A', 'B', 'C', 'D'
    notes: str = ""             # пояснение к классификации
    session_id: Optional[int] = None  # ID сессии, если применимо

@dataclass
class Session:
    # Сессия пользователя или IP (цепочка событий).
    id: int
    key: str          # значение ключа (user или ip)
    key_type: str     # 'user' или 'ip'
    events: List[LogEvent] = field(default_factory=list)

    @property
    def start_time(self) -> Optional[datetime]:
        times = [e.timestamp for e in self.events if e.timestamp]
        return min(times) if times else None

    @property
    def end_time(self) -> Optional[datetime]:
        times = [e.timestamp for e in self.events if e.timestamp]
        return max(times) if times else None

    @property
    def sources(self) -> List[str]:
        return sorted({e.source for e in self.events})

    @property
    def classes(self) -> List[str]:
        return sorted({e.evidential_class for e in self.events if e.evidential_class})
