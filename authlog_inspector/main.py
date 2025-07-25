from colorama import Fore, Style
import argparse

status_color = {
    "Success": Fore.GREEN,
    "Failed": Fore.RED,
    "Neutral": Fore.YELLOW,
    "Info": Fore.CYAN,
    "unknown": Fore.LIGHTBLACK_EX,
}


def is_log_file(file_path):
    """
    Checks if the file is a .log file
    """
    return file_path.endswith(".log")


def is_valid_path(file_path):
    """
    Checks if the file path is valid
    """
    import os

    return os.path.isfile(file_path) and os.access(file_path, os.R_OK)


def read_log_file(file_path):
    """
    Reads a .log file
    """
    with open(file_path, "r") as file:
        return file.readlines()


log_services = [
    "sshd",  # SSH-Zugriffe (remote Login)
    "login",  # Lokale Konsolenlogins
    "sudo",  # Root-Rechte über sudo
    "su",  # Benutzerwechsel (su root etc.)
    "gdm-password",  # Grafische Anmeldung (GNOME)
    "lightdm",  # Grafische Anmeldung (Ubuntu/Debian)
    "systemd",  # Sitzungsverwaltung
    "systemd-logind",  # Benutzer-Sessions
    "polkitd",  # Berechtigung über PolicyKit
    "passwd",  # Passwortänderung
    "cron",  # Zeitgesteuerte Aufgaben mit Benutzerbezug
    "atd",  # Einmalige geplante Tasks
    "dbus",  # Desktop-Dienstkommunikation
    "pam_unix",  # PAM-Modul für lokale Passwörter
    "pam_sss",  # PAM über SSSD (LDAP / AD)
    "useradd",  # Benutzer erstellen
    "usermod",  # Benutzer ändern
    "userdel",  # Benutzer löschen
    "groupadd",  # Gruppen erstellen
    "groupdel",  # Gruppen löschen
    "gnome-keyring-daemon",  # Passwortspeicher GNOME
    "sssd",  # Zugriff auf LDAP / AD
    "snapd",  # Snap-Dienst
    "auditd",  # Audit-Dienst
    "cupsd",  # Druckdienste
    "rsyslogd",  # Logging-Dienst selbst
]

event_map = {
    "sudo:": "sudo_usage",
    "su:": "su_switch",
    "Failed password": "failed_login",
    "Accepted password": "success_login",
    "invalid user": "invalid_user",
    "session opened": "session_opened",
    "session closed": "session_closed",
    "authentication failure": "auth_failure",
    "passwd:": "password_change",
}

user_patterns = {
    "for invalid user": "invalid_user",
    "for user": "valid_user_explicit",
    "for": "valid_user_basic",
}

status_keywords = {
    "invalid": {
        "keywords": [
            "Failed password",
            "invalid user",
            "authentication failure",
            "Failed publickey",
            "Connection closed by authenticating user",
            "PAM authentication error",
            "Disconnected from",
            "Too many authentication failures",
            "User not known to the underlying authentication module",
            "User not in sudoers",
        ],
        "status": "Failed",
    },
    "valid": {
        "keywords": [
            "Accepted password",
            "Accepted publickey",
            "session opened",
            "PAM: session opened",
            "login success",
            "authentication succeeded",
            "User logged in",
            "sudo: pam_unix(sudo:session): session opened",
            "su: session opened",
        ],
        "status": "Success",
    },
    "neutral": {
        "keywords": [
            "session closed",
            "sudo:",
            "su:",
            "useradd:",
            "usermod:",
            "userdel:",
            "groupadd:",
            "groupdel:",
            "password changed",
            "gpasswd:",
        ],
        "status": "Neutral",
    },
    "system": {
        "keywords": [
            "Server listening",
            "Listening on",
            "Starting",
            "Started",
            "Stopping",
            "Stopped",
            "Service started",
            "Reloading",
            "Rebooting",
            "Watching system buttons",
            "dbus-daemon:",
            "gnome-keyring-daemon:",
        ],
        "status": "Info",
    },
}


def parse_log_lines_into_dict(log_lines):
    """
    Parses the log lines and extracts relevant information.
    """
    log_dict = {
        "Timestamp": [],
        "Service": [],
        "Eventtype": [],
        "User": [],
        "IP": [],
        "Validity": [],
        "Status": [],
    }
    for line in log_lines:
        # Example parsing logic (this will depend on your log format)
        words = line.split()
        log_dict["Timestamp"].append(words[0:3])

        split_char = ["[", ":", "("]
        service = words[4]
        for char in split_char:
            if char in service:
                service = service.split(char)[0]
                break

        if service in log_services:
            log_dict["Service"].append(service)
        else:
            log_dict["Service"].append("NONE")

        for key, value in event_map.items():
            if key in line:
                log_dict["Eventtype"].append(value)
                break

        for key, value in user_patterns.items():
            if key in line:
                name = line.split(key)[1]
                log_dict["User"].append(value + " " + name.strip().split()[0])
                break

        if "from" in words:
            log_dict["IP"].append(words[words.index("from") + 1])
        else:
            log_dict["IP"].append("NONE")

        validity = "unknown"
        status = "unknown"

        for key, values in status_keywords.items():
            if any(kw in line for kw in values["keywords"]):
                validity = key
                status = values["status"]
                break

        log_dict["Validity"].append(validity)
        log_dict["Status"].append(status)

    return log_dict


CLI_parser = argparse.ArgumentParser(description="CLI argparse for authlog Inspector")
CLI_parser.add_argument(
    "--file", type=str, default=None, required=True, help="Path to the .log file"
)
CLI_parser.add_argument(
    "--limit", type=int, help="Limits the output to given number of lines"
)
CLI_parser.add_argument(
    "--export", type=str, choices=["csv", "json"], help="Export format"
)
CLI_parser.add_argument(
    "--reverse", action="store_true", help="Limits the output to given number of lines"
)
CLI_parser.add_argument(
    "--color",
    type=int,
    choices=[0, 1],
    default=1,
    help="Enable (1) or disable (0) colored output",
)


def main():
    print("Welcome to the AuthLog Inspector!")
    args = CLI_parser.parse_args()
    try:
        if not is_log_file(args.file):
            raise ValueError("File is not a .log file")
        if not is_valid_path(args.file):
            raise ValueError("File path is not valid")

        # Read the log file
        print(f"Reading log file: {args.file}")
        log_lines = read_log_file(args.file)
        print(
            f"Successfully read {len(log_lines)} lines from {args.file} with limit={args.limit}."
        )
        parsed_log = parse_log_lines_into_dict(log_lines)
        print("Log file parsed successfully.")
        print(f"\nShowing first {args.limit} parsed log entries:\n")
        print(
            f"{'Nr':<5} {'Timestamp':<20} {'Service':<20} {'Eventtype':<20} "
            f"{'User':<30} {'IP':<18} {'Status':<13} {'Validity':<10}"
        )
        print("-" * 150)

        limit = args.limit if args.limit is not None else len(parsed_log["Timestamp"])

        if not args.reverse:
            indices = range(min(limit, len(parsed_log["Timestamp"])))
        else:
            start = len(parsed_log) - 1
            stop = len(parsed_log) - limit - 1
            indices = range(start, stop, -1)

        for i in indices:
            timestamp = " ".join(parsed_log["Timestamp"][i])
            service = parsed_log["Service"][i]
            event = parsed_log["Eventtype"][i]
            user = parsed_log["User"][i]
            ip = parsed_log["IP"][i]
            status = parsed_log["Status"][i]
            validity = parsed_log["Validity"][i]

            print(
                f"{i+1:<5} {timestamp:<20} {service:<20} {event:<20} "
                f"{user:<30} {ip:<18} {status_color[status] if args.color == 1 else ''}{status:<13}{Style.RESET_ALL if args.color == 1 else ''} {validity:<10}"
            )

    except Exception as e:
        print(f"Error reading {args.file}: {e}")


if __name__ == "__main__":
    main()
