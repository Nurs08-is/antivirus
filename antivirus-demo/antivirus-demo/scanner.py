"""Оқу мақсатындағы демо-антивирус: сигнатуралық + эвристикалық талдау."""
import hashlib
import json
import sys
from pathlib import Path

# ---------- 1. СИГНАТУРАЛЫҚ ТАЛДАУ ----------
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def signature_scan(path, db):
    """Хэш базада болса, зиянды бағдарламаның атын қайтарады."""
    return db.get(sha256_of(path))

# ---------- 2. ЭВРИСТИКАЛЫҚ ТАЛДАУ ----------
SUSPICIOUS = {
    b"powershell -enc": 3,       # жасырылған команда
    b"createremotethread": 3,    # басқа процеске код енгізу
    b"keylogger": 3,             # пернетақтаны тыңдау
    b"virtualalloc": 2,          # жадыны күдікті бөлу
    b"autorun": 1,               # жүйемен бірге іске қосылу
}
THRESHOLD = 3

def heuristic_scan(path):
    """(ұпай, себептер) қайтарады."""
    data = Path(path).read_bytes().lower()
    score, reasons = 0, []
    for pattern, weight in SUSPICIOUS.items():
        if pattern in data:
            score += weight
            reasons.append(pattern.decode())
    if len(Path(path).suffixes) >= 2 and Path(path).suffix in {".exe", ".bat", ".scr"}:
        score += 2                # мысалы: photo.jpg.exe
        reasons.append("қос кеңейтім")
    return score, reasons

# ---------- 3. НЕГІЗГІ ЦИКЛ ----------
def scan_folder(folder, db):
    for path in Path(folder).rglob("*"):
        if not path.is_file():
            continue
        name = signature_scan(path, db)
        if name:
            print(f"[ЗИЯНДЫ]  {path}  ->  {name} (сигнатура)")
            continue
        score, reasons = heuristic_scan(path)
        if score >= THRESHOLD:
            print(f"[КҮДІКТІ] {path}  ->  ұпай {score}: {', '.join(reasons)}")
        else:
            print(f"[таза]    {path}")

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "test_files"
    db = json.load(open("signatures.json", encoding="utf-8"))
    scan_folder(folder, db)
