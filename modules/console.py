"""
modules/console.py - Colored console output utilities
"""

import sys
import os


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"


class Console:
    _no_color = False
    _color_map = {
        "red":     Colors.RED,
        "green":   Colors.GREEN,
        "yellow":  Colors.YELLOW,
        "blue":    Colors.BLUE,
        "magenta": Colors.MAGENTA,
        "cyan":    Colors.CYAN,
        "white":   Colors.WHITE,
        "orange":  Colors.ORANGE,
        "dim":     Colors.DIM,
        "bold":    Colors.BOLD,
    }

    @classmethod
    def setup(cls, no_color=False):
        cls._no_color = no_color or not sys.stdout.isatty()

    @classmethod
    def _c(cls, text, color=None, bold=False):
        if cls._no_color or not color:
            return text
        c = cls._color_map.get(color, "")
        b = Colors.BOLD if bold else ""
        return f"{b}{c}{text}{Colors.RESET}"

    @classmethod
    def print_raw(cls, msg, color=None):
        print(cls._c(msg, color))

    @classmethod
    def info(cls, msg):
        prefix = cls._c("  [*]", "blue", bold=True)
        print(f"{prefix} {msg}")

    @classmethod
    def success(cls, msg):
        prefix = cls._c("  [+]", "green", bold=True)
        print(f"{prefix} {msg}")

    @classmethod
    def warning(cls, msg):
        prefix = cls._c("  [!]", "yellow", bold=True)
        print(f"{prefix} {msg}")

    @classmethod
    def error(cls, msg):
        prefix = cls._c("  [-]", "red", bold=True)
        print(f"{prefix} {msg}")

    @classmethod
    def finding(cls, msg, severity="info"):
        sev_colors = {
            "critical": "red",
            "high":     "orange",
            "medium":   "yellow",
            "low":      "blue",
            "info":     "cyan",
        }
        color = sev_colors.get(severity.lower(), "cyan")
        sev_label = cls._c(f"[{severity.upper():^8}]", color, bold=True)
        print(f"  {sev_label} {msg}")

    @classmethod
    def section(cls, title):
        width = 63
        line = cls._c("─" * width, "cyan")
        title_str = cls._c(f"  ◆ {title}", "cyan", bold=True)
        print(f"\n{title_str}")
        print(f"  {line}")

    @classmethod
    def subsection(cls, title):
        print(f"\n  {cls._c('▸', 'yellow', bold=True)} {cls._c(title, 'white', bold=True)}")

    @classmethod
    def result(cls, key, value, color="white"):
        key_str = cls._c(f"  {key:<20}", "dim")
        val_str = cls._c(str(value), color)
        print(f"{key_str}: {val_str}")

    @classmethod
    def progress(cls, current, total, label=""):
        bar_len = 30
        filled = int(bar_len * current / max(total, 1))
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(100 * current / max(total, 1))
        bar_colored = cls._c(bar, "cyan")
        print(f"\r  [{bar_colored}] {pct:3d}% {label:<40}", end="", flush=True)
        if current >= total:
            print()
