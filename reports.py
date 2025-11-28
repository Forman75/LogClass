from typing import List
import csv
import matplotlib.pyplot as plt
from models import LogEvent, Session
from classifier import compute_class_stats, compute_source_stats

def export_events_csv(events: List[LogEvent], path: str) -> None:
    # Экспорт событий в CSV.
    fields = [
        "timestamp", "source", "event_type",
        "user", "ip", "evidential_class", "notes", "raw_line"
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter=";")
        writer.writeheader()
        for ev in events:
            writer.writerow({
                "timestamp": ev.timestamp.isoformat(sep=" ") if ev.timestamp else "",
                "source": ev.source,
                "event_type": ev.event_type,
                "user": ev.user or "",
                "ip": ev.ip or "",
                "evidential_class": ev.evidential_class,
                "notes": ev.notes,
                "raw_line": ev.raw_line,
            })

def export_summary_markdown(events: List[LogEvent], sessions: List[Session], path: str) -> None:
    # Экспорт сводного отчёта в Markdown
    class_stats = compute_class_stats(events)
    source_stats = compute_source_stats(events)

    with open(path, "w", encoding="utf-8") as f:
        f.write("# Сводный отчёт по цифровым следам\n\n")
        f.write("## Статистика по классам значимости\n\n")
        f.write("| Класс | Количество |\n")
        f.write("|-------|------------|\n")
        for cls in sorted(class_stats.keys()):
            f.write(f"| {cls} | {class_stats[cls]} |\n")
        f.write("\n")
        f.write("## Статистика по источникам логов\n\n")
        f.write("| Источник | Количество событий |\n")
        f.write("|----------|--------------------|\n")
        for src in sorted(source_stats.keys()):
            f.write(f"| {src} | {source_stats[src]} |\n")
        f.write("\n")
        f.write("## Сессии пользователей / IP\n\n")
        f.write("| ID | Ключ | Тип ключа | Кол-во событий | Источники | Классы |\n")
        f.write("|----|------|-----------|----------------|-----------|--------|\n")
        for s in sessions:
            f.write(
                f"| {s.id} | {s.key} | {s.key_type} | "
                f"{len(s.events)} | {', '.join(s.sources)} | {', '.join(s.classes)} |\n"
            )
        f.write("\n")
        f.write("## Примеры слабых следов (классы C и D)\n\n")
        count = 0
        for ev in events:
            if ev.evidential_class in ("C", "D"):
                f.write(
                    f"- [{ev.evidential_class}] {ev.timestamp} {ev.source} {ev.event_type} "
                    f"(user={ev.user}, ip={ev.ip}) — {ev.notes}\n"
                )
                count += 1
                if count >= 20:
                    break
        if count == 0:
            f.write("_Слабых следов не обнаружено._\n")

def plot_class_distribution(events: List[LogEvent]) -> None:
    # График распределения событий по классам
    stats = compute_class_stats(events)
    if not stats:
        return
    classes = sorted(stats.keys())
    values = [stats[c] for c in classes]
    plt.figure()
    plt.bar(classes, values)
    plt.xlabel("Класс значимости")
    plt.ylabel("Количество событий")
    plt.title("Распределение событий по классам значимости")
    plt.tight_layout()
    plt.show()

def plot_source_distribution(events: List[LogEvent]) -> None:
    # График распределения событий по источникам логов
    stats = compute_source_stats(events)
    if not stats:
        return
    sources = sorted(stats.keys())
    values = [stats[s] for s in sources]
    plt.figure()
    plt.bar(sources, values)
    plt.xlabel("Источник логов")
    plt.ylabel("Количество событий")
    plt.title("Распределение событий по источникам")
    plt.tight_layout()
    plt.show()
