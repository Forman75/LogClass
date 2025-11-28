from typing import List, Dict
from datetime import timedelta
from models import LogEvent, Session
from config_manager import Config

def build_sessions(events: List[LogEvent], cfg: Config) -> List[Session]:
    # Объединение событий в сессии по user/IP и окну времени.
    events_sorted = sorted(
        events,
        key=lambda e: e.timestamp if e.timestamp is not None else 9999999999,
    )

    sessions: List[Session] = []
    last_session_for_key: Dict[str, Session] = {}

    window = timedelta(minutes=cfg.session_window_minutes)
    session_id_counter = 1
    for ev in events_sorted:
        key_type = "user" if ev.user else "ip" if ev.ip else None
        if key_type is None or ev.timestamp is None:
            ev.session_id = None
            continue

        key_val = ev.user if key_type == "user" else ev.ip
        assert key_val is not None

        key = f"{key_type}:{key_val}"
        prev_session = last_session_for_key.get(key)

        if prev_session and prev_session.end_time and ev.timestamp - prev_session.end_time <= window:
            prev_session.events.append(ev)
            ev.session_id = prev_session.id
        else:
            sess = Session(
                id=session_id_counter,
                key=key_val,
                key_type=key_type,
                events=[ev],
            )
            sessions.append(sess)
            ev.session_id = session_id_counter
            last_session_for_key[key] = sess
            session_id_counter += 1

    return sessions
