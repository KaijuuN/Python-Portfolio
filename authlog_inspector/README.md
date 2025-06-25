# 🔍 AuthLog Inspector

Ein Python-basiertes Tool zur Analyse und Klassifizierung von System-Logdateien – speziell für Authentifizierungs- und sicherheitsrelevante Ereignisse.

---

## ✅ Features

- Erkennt Login-Versuche (erfolgreich / fehlgeschlagen)
- Extrahiert:
  - Zeitstempel
  - Dienst (z. B. `sshd`, `sudo`, `su`)
  - Eventtyp (z. B. `failed_login`, `sudo_usage`)
  - Nutzername
  - IP-Adresse
  - Gültigkeit (`valid` / `invalid` / `neutral` / `system`)
  - Status (`Success` / `Failed` / `Neutral` / `Info`)
- Farbige Konsolenausgabe dank `colorama`
- Leicht erweiterbar über Keyword-Listen

---

## 🛠️ Verwendung

### Start

```bash
python main.py
```

Dann den Pfad zur `.log`-Datei eingeben, z. B.:

```plaintext
/var/log/auth.log
```

---

## 🧪 Testen

Test-Suite: `test_main.py`

```bash
python -m unittest test_main.py
```

---

## 📂 Beispielausgabe

```plaintext
Nr    Timestamp            Service              Eventtype            User                           IP                 Status        Validity
------------------------------------------------------------------------------------------------------------------------------
1     Mar 27 13:06:56      sshd                 success_login        valid_user_basic john          192.168.0.101      Success       valid
2     Mar 27 13:06:56      sshd                 failed_login         invalid_user admin             203.0.113.42       Failed        invalid
3     Mar 27 13:06:56      sudo                 sudo_usage           valid_user_basic john          NONE               Success       valid
```

---

## 📦 Abhängigkeiten

- Python 3.x
- [`colorama`](https://pypi.org/project/colorama/)

Installation:

```bash
pip install colorama
```

---

## 📄 Lizenz

MIT – feel free to use, modify, and share.

---

## ✍️ Autor

Projekt von Ka1juu
