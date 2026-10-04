import hashlib
import json
import os
import tkinter as tk
from tkinter import filedialog, ttk

# Күдікті сөздер және олардың қауіп ұпайы
suspicious_words = {
    "powershell -enc": 3,
    "keylogger": 3,
    "autorun": 1,
}

# Белгілі вирустар тізімі (саусақ іздері)
here = os.path.dirname(os.path.abspath(__file__))
virus_db = json.load(open(os.path.join(here, "signatures.json")))


def check_file(path):
    """Файлды тексеріп, (нәтиже, түсініктеме) қайтарады."""
    data = open(path, "rb").read()

    # 1-қадам: сигнатуралық талдау
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint in virus_db:
        return "ВИРУС", virus_db[fingerprint]

    # 2-қадам: эвристикалық талдау
    text = data.decode(errors="ignore").lower()
    score = 0
    for word, points in suspicious_words.items():
        if word in text:
            score += points

    if score >= 3:
        return "КҮДІКТІ", "ұпай: " + str(score)
    return "ТАЗА", ""


def scan(folder):
    table.delete(*table.get_children())
    counts = {"ТАЗА": 0, "КҮДІКТІ": 0, "ВИРУС": 0}
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            try:
                status, info = check_file(path)
            except Exception:
                continue  # оқуға болмайтын файлды өткізіп жібереміз
            counts[status] += 1
            table.insert("", "end", values=(path, status, info), tags=(status,))
            window.update()
    summary.config(
        text=f"Таза: {counts['ТАЗА']}   Күдікті: {counts['КҮДІКТІ']}   Вирус: {counts['ВИРУС']}"
    )


def choose_folder():
    folder = filedialog.askdirectory(title="Тексеру үшін папканы таңдаңыз")
    if folder:
        scan(folder)


def scan_test_files():
    scan(os.path.join(here, "test_files"))


# ---------- Терезе ----------
window = tk.Tk()
window.title("Демо-антивирус")
window.geometry("900x480")

tk.Label(window, text="Демо-антивирус", font=("Arial", 20, "bold")).pack(pady=10)

buttons = tk.Frame(window)
buttons.pack()
tk.Button(buttons, text="Папканы таңдап тексеру", font=("Arial", 12), command=choose_folder).pack(side="left", padx=5)
tk.Button(buttons, text="Тест файлдарын тексеру", font=("Arial", 12), command=scan_test_files).pack(side="left", padx=5)

table = ttk.Treeview(window, columns=("file", "status", "info"), show="headings")
table.heading("file", text="Файл")
table.heading("status", text="Нәтиже")
table.heading("info", text="Түсініктеме")
table.column("file", width=520)
table.column("status", width=100)
table.column("info", width=220)
table.tag_configure("ТАЗА", foreground="green")
table.tag_configure("КҮДІКТІ", foreground="orange")
table.tag_configure("ВИРУС", foreground="red")
table.pack(fill="both", expand=True, padx=10, pady=10)

summary = tk.Label(window, text="Папканы таңдаңыз", font=("Arial", 12))
summary.pack(pady=(0, 10))

window.mainloop()
