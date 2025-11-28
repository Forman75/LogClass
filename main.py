import os
from typing import List
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from models import LogEvent, Session
from config_manager import load_config, save_config, Config
from parsers import PARSERS
from classifier import classify_events
from correlator import build_sessions
from reports import (
    export_events_csv,
    export_summary_markdown,
    plot_class_distribution,
    plot_source_distribution,
)
from generator import generate_scenario_logs

class SettingsWindow(tk.Toplevel):
 #Окно настроек правил анализа и классификации.
    def __init__(self, master: tk.Tk, app: "LogClassifierGUI"):
        super().__init__(master)
        self.app = app
        self.config: Config = app.config

        self.title("Настройки правил")
        self.resizable(False, True)
        self.grab_set()
        self._build_ui()

    def _build_ui(self):
        cfg = self.config
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Ключевые слова
        kw_frame = ttk.LabelFrame(main_frame, text="Ключевые слова")
        kw_frame.pack(fill=tk.X, expand=False, pady=5)
        ttk.Label(kw_frame, text="Чувствительные ключевые слова (через запятую):").pack(anchor=tk.W)
        self.entry_sensitive = tk.Entry(kw_frame, width=80)
        self.entry_sensitive.pack(fill=tk.X, padx=2, pady=2)
        self.entry_sensitive.insert(0, ", ".join(cfg.sensitive_keywords))
        ttk.Label(kw_frame, text="Ключевые слова для аутентификации (через запятую):").pack(anchor=tk.W)
        self.entry_auth = tk.Entry(kw_frame, width=80)
        self.entry_auth.pack(fill=tk.X, padx=2, pady=2)
        self.entry_auth.insert(0, ", ".join(cfg.auth_keywords))

        # Параметры анализа
        params_frame = ttk.LabelFrame(main_frame, text="Параметры анализа")
        params_frame.pack(fill=tk.X, expand=False, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Порог крупной передачи файла (байт):", width=40).pack(side=tk.LEFT, anchor=tk.W)
        self.entry_threshold = tk.Entry(row1, width=15)
        self.entry_threshold.pack(side=tk.LEFT)
        self.entry_threshold.insert(0, str(cfg.file_transfer_threshold))
        row2 = ttk.Frame(params_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Окно сессии (минут):", width=40).pack(side=tk.LEFT, anchor=tk.W)
        self.entry_session_window = tk.Entry(row2, width=15)
        self.entry_session_window.pack(side=tk.LEFT)
        self.entry_session_window.insert(0, str(cfg.session_window_minutes))

        # Смещения времени
        offsets_frame = ttk.Frame(params_frame)
        offsets_frame.pack(fill=tk.X, pady=2)
        ttk.Label(offsets_frame, text="Смещения времени (минуты):").pack(anchor=tk.W)
        self.offset_entries = {}
        for src in ("web", "proxy", "vpn"):
            row = ttk.Frame(offsets_frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=f"{src}:", width=10).pack(side=tk.LEFT)
            e = tk.Entry(row, width=10)
            e.pack(side=tk.LEFT)
            e.insert(0, str(cfg.time_offsets_minutes.get(src, 0)))
            self.offset_entries[src] = e

        # Весовые коэффициенты
        weights_frame = ttk.LabelFrame(main_frame, text="Весовые коэффициенты классификации")
        weights_frame.pack(fill=tk.X, expand=False, pady=5)
        w = cfg.scoring

        def make_weight_row(parent, label_text, value_attr_name):
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=label_text, width=40).pack(side=tk.LEFT, anchor=tk.W)
            entry = tk.Entry(row, width=10)
            entry.pack(side=tk.LEFT)
            entry.insert(0, str(getattr(w, value_attr_name)))
            return entry

        self.entry_weight_user = make_weight_row(
            weights_frame, "Баллы за наличие учётной записи пользователя:", "weight_user"
        )
        self.entry_weight_ip = make_weight_row(
            weights_frame, "Баллы за наличие IP-адреса:", "weight_ip"
        )
        self.entry_weight_vpn = make_weight_row(
            weights_frame, "Баллы за источник VPN:", "weight_vpn_source"
        )
        self.entry_weight_auth = make_weight_row(
            weights_frame, "Баллы за событие аутентификации:", "weight_auth_event"
        )
        self.entry_weight_sensitive = make_weight_row(
            weights_frame, "Баллы за доступ к чувствительному ресурсу / конфигурации:", "weight_sensitive_event"
        )
        self.entry_penalty_no_time = make_weight_row(
            weights_frame, "Штраф за отсутствие однозначного времени события:", "penalty_no_time"
        )

        # Юридические описания классов
        desc_frame = ttk.LabelFrame(main_frame, text="Юридические описания классов значимости")
        desc_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.class_desc_texts = {}
        for cls in ("A", "B", "C", "D"):
            sub = ttk.Frame(desc_frame)
            sub.pack(fill=tk.BOTH, expand=True, pady=2)
            ttk.Label(sub, text=f"Класс {cls}:", anchor=tk.W).pack(anchor=tk.W)
            txt = tk.Text(sub, height=3, wrap="word")
            txt.pack(fill=tk.X, expand=False)
            txt.insert("1.0", cfg.class_descriptions.get(cls, ""))
            self.class_desc_texts[cls] = txt

        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Сохранить", command=self.on_save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.destroy).pack(side=tk.RIGHT)

    def on_save(self):
        try:
            # Ключевые слова
            sens_list = [s.strip() for s in self.entry_sensitive.get().split(",") if s.strip()]
            auth_list = [s.strip() for s in self.entry_auth.get().split(",") if s.strip()]

            # Параметры анализа
            threshold = int(self.entry_threshold.get())
            session_window = int(self.entry_session_window.get())

            offsets = {}
            for src, entry in self.offset_entries.items():
                offsets[src] = int(entry.get())

            # Весовые коэффициенты
            weight_user = int(self.entry_weight_user.get())
            weight_ip = int(self.entry_weight_ip.get())
            weight_vpn = int(self.entry_weight_vpn.get())
            weight_auth = int(self.entry_weight_auth.get())
            weight_sensitive = int(self.entry_weight_sensitive.get())
            penalty_no_time = int(self.entry_penalty_no_time.get())

            # Описания классов
            class_descriptions = {}
            for cls, txt in self.class_desc_texts.items():
                val = txt.get("1.0", tk.END).strip()
                class_descriptions[cls] = val

        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные числовые значения в настройках.")
            return

        # Применяем изменения к конфигу приложения
        cfg = self.app.config
        cfg.sensitive_keywords = sens_list
        cfg.auth_keywords = auth_list
        cfg.file_transfer_threshold = threshold
        cfg.session_window_minutes = session_window
        cfg.time_offsets_minutes = offsets
        w = cfg.scoring
        w.weight_user = weight_user
        w.weight_ip = weight_ip
        w.weight_vpn_source = weight_vpn
        w.weight_auth_event = weight_auth
        w.weight_sensitive_event = weight_sensitive
        w.penalty_no_time = penalty_no_time
        cfg.class_descriptions = class_descriptions

        # Сохраняем в файл и пересчитываем классификацию
        try:
            save_config(cfg)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию:\n{e}")
            return

        classify_events(self.app.events, cfg)
        self.app._rebuild_sessions()

        messagebox.showinfo("Настройки", "Настройки сохранены и применены.")
        self.destroy()


class LogClassifierGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Классификатор цифровых следов в логах")

        self.config: Config = load_config()
        self.events: List[LogEvent] = []
        self.sessions: List[Session] = []

        self.class_filter_var = tk.StringVar(value="Все")

        self._build_ui()
        self._rebuild_sessions()

    def _build_ui(self):
        # Верхняя панель
        top = ttk.Frame(self.master)
        top.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Label(top, text="Загрузить лог:").pack(side=tk.LEFT)
        ttk.Button(top, text="Web", command=lambda: self.load_log_file("web")).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Proxy", command=lambda: self.load_log_file("proxy")).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="VPN", command=lambda: self.load_log_file("vpn")).pack(side=tk.LEFT, padx=2)

        ttk.Button(top, text="Сгенерировать учебные логи", command=self.generate_demo_logs).pack(
            side=tk.LEFT, padx=10
        )

        # настройки и перезагрузка конфига
        ttk.Button(top, text="Перезагрузить конфиг", command=self.reload_config).pack(side=tk.RIGHT)
        ttk.Button(top, text="Настройки", command=self.open_settings).pack(side=tk.RIGHT, padx=5)

        # Фильтр по классу
        ttk.Label(top, text="Класс:").pack(side=tk.RIGHT, padx=(0, 2))
        class_combo = ttk.Combobox(
            top,
            textvariable=self.class_filter_var,
            values=["Все", "A", "B", "C", "D"],
            width=5,
            state="readonly",
        )
        class_combo.pack(side=tk.RIGHT)
        class_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_event_view())

        # Notebook с вкладками
        notebook = ttk.Notebook(self.master)
        notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Вкладка событий
        self.events_frame = ttk.Frame(notebook)
        notebook.add(self.events_frame, text="События")
        self._build_events_tab()

        # Вкладка сессий
        self.sessions_frame = ttk.Frame(notebook)
        notebook.add(self.sessions_frame, text="Сессии")
        self._build_sessions_tab()

        # Нижняя панель
        bottom = ttk.Frame(self.master)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        self.stats_label = ttk.Label(bottom, text="Событий: 0")
        self.stats_label.pack(side=tk.LEFT)
        ttk.Button(bottom, text="Показать слабые следы", command=self.show_weak_traces).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom, text="Экспорт CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom, text="Экспорт отчёта (MD)", command=self.export_md).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom, text="График по классам", command=lambda: plot_class_distribution(self.events)).pack(
            side=tk.RIGHT, padx=5
        )
        ttk.Button(bottom, text="График по источникам", command=lambda: plot_source_distribution(self.events)).pack(
            side=tk.RIGHT, padx=5
        )

    # Вкладка событий

    def _build_events_tab(self):
        frame = self.events_frame
        table_frame = ttk.Frame(frame)
        table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        columns = ("time", "source", "event", "user", "ip", "class")
        self.tree_events = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        for col, text, width, anchor in [
            ("time", "Время", 150, tk.W),
            ("source", "Источник", 80, tk.W),
            ("event", "Событие", 140, tk.W),
            ("user", "Пользователь", 120, tk.W),
            ("ip", "IP", 120, tk.W),
            ("class", "Класс", 60, tk.CENTER),
        ]:
            self.tree_events.heading(col, text=text)
            self.tree_events.column(col, width=width, anchor=anchor)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_events.yview)
        self.tree_events.configure(yscrollcommand=vsb.set)
        self.tree_events.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_events.bind("<<TreeviewSelect>>", self.on_event_select)

        # Детали события
        details_label = ttk.Label(frame, text="Подробности события:")
        details_label.pack(side=tk.TOP, anchor=tk.W)
        self.text_event_details = tk.Text(frame, height=10, wrap="word")
        self.text_event_details.pack(side=tk.TOP, fill=tk.BOTH, expand=False)
        self.text_event_details.configure(font=("Courier New", 9))

    # Вкладка сессий
    def _build_sessions_tab(self):
        frame = self.sessions_frame
        table_frame = ttk.Frame(frame)
        table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = ("id", "key", "key_type", "count", "sources", "classes")
        self.tree_sessions = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        for col, text, width, anchor in [
            ("id", "ID", 60, tk.CENTER),
            ("key", "Ключ", 150, tk.W),
            ("key_type", "Тип ключа", 80, tk.W),
            ("count", "Событий", 80, tk.CENTER),
            ("sources", "Источники", 120, tk.W),
            ("classes", "Классы", 100, tk.W),
        ]:
            self.tree_sessions.heading(col, text=text)
            self.tree_sessions.column(col, width=width, anchor=anchor)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_sessions.yview)
        self.tree_sessions.configure(yscrollcommand=vsb.set)
        self.tree_sessions.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_sessions.bind("<<TreeviewSelect>>", self.on_session_select)

        # Детали сессии
        details_label = ttk.Label(frame, text="Подробности сессии:")
        details_label.pack(side=tk.TOP, anchor=tk.W)
        self.text_session_details = tk.Text(frame, height=10, wrap="word")
        self.text_session_details.pack(side=tk.TOP, fill=tk.BOTH, expand=False)
        self.text_session_details.configure(font=("Courier New", 9))

    # Пересчёт сессий и таблиц

    def _rebuild_sessions(self):
        self.sessions = build_sessions(self.events, self.config)
        self.refresh_event_view()
        self.refresh_sessions_view()

    def refresh_event_view(self):
        for item in self.tree_events.get_children():
            self.tree_events.delete(item)

        selected_class = self.class_filter_var.get()
        for idx, ev in enumerate(self.events):
            if selected_class != "Все" and ev.evidential_class != selected_class:
                continue
            time_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
            self.tree_events.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    time_str,
                    ev.source,
                    ev.event_type,
                    ev.user or "—",
                    ev.ip or "—",
                    ev.evidential_class,
                ),
            )

        total = len(self.events)
        counts = {"A": 0, "B": 0, "C": 0, "D": 0}
        for ev in self.events:
            if ev.evidential_class in counts:
                counts[ev.evidential_class] += 1
        stats_text = (
            f"Событий всего: {total}  |  "
            f"A: {counts['A']}  B: {counts['B']}  "
            f"C: {counts['C']}  D: {counts['D']}"
        )
        self.stats_label.config(text=stats_text)

        self.text_event_details.delete("1.0", tk.END)

    def refresh_sessions_view(self):
        for item in self.tree_sessions.get_children():
            self.tree_sessions.delete(item)

        for sess in self.sessions:
            self.tree_sessions.insert(
                "",
                "end",
                iid=str(sess.id),
                values=(
                    sess.id,
                    sess.key,
                    sess.key_type,
                    len(sess.events),
                    ", ".join(sess.sources),
                    ", ".join(sess.classes),
                ),
            )

        self.text_session_details.delete("1.0", tk.END)

    # Обработчики выбора

    def on_event_select(self, event):
        selection = self.tree_events.selection()
        if not selection:
            return
        idx = int(selection[0])
        if idx < 0 or idx >= len(self.events):
            return
        ev = self.events[idx]

        lines = []
        lines.append(f"Источник: {ev.source}")
        lines.append(f"Тип события: {ev.event_type}")
        if ev.timestamp:
            lines.append(f"Время: {ev.timestamp.isoformat(sep=' ')}")
        else:
            lines.append("Время: неизвестно")
        lines.append(f"Пользователь: {ev.user or '—'}")
        lines.append(f"IP-адрес: {ev.ip or '—'}")
        lines.append(f"Класс значимости: {ev.evidential_class}")

        class_desc = self.config.class_descriptions.get(ev.evidential_class, "")
        if class_desc:
            lines.append(f"Юридическое толкование класса {ev.evidential_class}: {class_desc}")

        lines.append(f"Пояснение к классификации: {ev.notes or '—'}")
        lines.append(f"ID сессии: {ev.session_id if ev.session_id is not None else '—'}")

        if ev.details:
            lines.append("\nДополнительные поля:")
            for k, v in ev.details.items():
                lines.append(f"  {k}: {v}")

        lines.append("\nИсходная строка лога:")
        lines.append(ev.raw_line)

        self.text_event_details.delete("1.0", tk.END)
        self.text_event_details.insert(tk.END, "\n".join(lines))

    def on_session_select(self, event):
        selection = self.tree_sessions.selection()
        if not selection:
            return
        sess_id = int(selection[0])
        sess = next((s for s in self.sessions if s.id == sess_id), None)
        if not sess:
            return

        lines = []
        lines.append(f"Сессия ID: {sess.id}")
        lines.append(f"Ключ: {sess.key} (тип: {sess.key_type})")
        if sess.start_time and sess.end_time:
            lines.append(
                f"Период: {sess.start_time.isoformat(sep=' ')} — {sess.end_time.isoformat(sep=' ')}"
            )
        lines.append(f"Источники: {', '.join(sess.sources)}")
        lines.append(f"Классы событий: {', '.join(sess.classes)}")
        lines.append(f"Количество событий: {len(sess.events)}")
        lines.append("\nСобытия сессии:")
        for ev in sess.events:
            t = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
            lines.append(
                f"- {t} {ev.source} {ev.event_type} "
                f"(user={ev.user}, ip={ev.ip}, класс={ev.evidential_class})"
            )

        self.text_session_details.delete("1.0", tk.END)
        self.text_session_details.insert(tk.END, "\n".join(lines))

    # Действия
    def open_settings(self):
        SettingsWindow(self.master, self)

    def load_log_file(self, source_name: str):
        from parsers import PARSERS  # на случай горячей замены парсеров
        parser = PARSERS.get(source_name)
        if parser is None:
            messagebox.showerror("Ошибка", f"Неизвестный источник: {source_name}")
            return

        path = filedialog.askopenfilename(
            title=f"Выберите файл лога ({source_name})",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        added, skipped = 0, 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = parser(line, self.config)
                    if ev is None:
                        skipped += 1
                        continue
                    self.events.append(ev)
                    added += 1
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")
            return

        classify_events(self.events, self.config)
        self._rebuild_sessions()
        messagebox.showinfo(
            "Загрузка завершена",
            f"Источник: {source_name}\n"
            f"Добавлено событий: {added}\n"
            f"Пропущено строк: {skipped}",
        )

    def generate_demo_logs(self):
        directory = filedialog.askdirectory(
            title="Выберите папку для сохранения учебных логов (можно отменить, чтобы загрузить только в память)"
        )
        web_lines, proxy_lines, vpn_lines = generate_scenario_logs()

        def write_if_dir(fname: str, lines: List[str]):
            if directory:
                path = os.path.join(directory, fname)
                with open(path, "w", encoding="utf-8") as f:
                    for ln in lines:
                        f.write(ln + "\n")

        write_if_dir("web_demo.log", web_lines)
        write_if_dir("proxy_demo.log", proxy_lines)
        write_if_dir("vpn_demo.log", vpn_lines)

        from parsers import PARSERS
        for line in web_lines:
            ev = PARSERS["web"](line, self.config)
            if ev:
                self.events.append(ev)
        for line in proxy_lines:
            ev = PARSERS["proxy"](line, self.config)
            if ev:
                self.events.append(ev)
        for line in vpn_lines:
            ev = PARSERS["vpn"](line, self.config)
            if ev:
                self.events.append(ev)

        classify_events(self.events, self.config)
        self._rebuild_sessions()

        msg = "Учебные логи сгенерированы и загружены в программу."
        if directory:
            msg += f" Также сохранены файлы в папке: {directory}"
        messagebox.showinfo("Готово", msg)

    def reload_config(self):
        self.config = load_config()
        classify_events(self.events, self.config)
        self._rebuild_sessions()
        messagebox.showinfo("Конфигурация", "Конфигурация правил перезагружена из rules.json.")

    def show_weak_traces(self):
        weak_events = [e for e in self.events if e.evidential_class in ("C", "D")]
        if not weak_events:
            messagebox.showinfo("Слабые следы", "События классов C и D не обнаружены.")
            return

        win = tk.Toplevel(self.master)
        win.title("Слабые следы (классы C и D)")
        text = tk.Text(win, wrap="word", width=120, height=30)
        text.pack(fill=tk.BOTH, expand=True)

        for ev in weak_events:
            t = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
            class_desc = self.config.class_descriptions.get(ev.evidential_class, "")
            line = (
                f"[{ev.evidential_class}] {t} {ev.source} {ev.event_type} "
                f"(user={ev.user}, ip={ev.ip}) — {ev.notes}"
            )
            if class_desc:
                line += f" | Класс {ev.evidential_class}: {class_desc}"
            line += "\n"
            text.insert(tk.END, line)

    def export_csv(self):
        if not self.events:
            messagebox.showwarning("Экспорт", "Нет событий для экспорта.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            export_events_csv(self.events, path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить CSV:\n{e}")
            return
        messagebox.showinfo("Экспорт", f"CSV-файл сохранён: {path}")

    def export_md(self):
        if not self.events:
            messagebox.showwarning("Экспорт", "Нет данных для отчёта.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить отчёт (Markdown)",
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            export_summary_markdown(self.events, self.sessions, path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт:\n{e}")
            return
        messagebox.showinfo("Экспорт", f"Отчёт сохранён: {path}")


def main():
    root = tk.Tk()
    app = LogClassifierGUI(root)
    root.geometry("1000x700")
    root.mainloop()


if __name__ == "__main__":
    main()