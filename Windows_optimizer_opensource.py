#!/usr/bin/env python3
from __future__ import annotations
import ctypes
import os
import sys
import subprocess
import argparse
import tempfile
import threading
import time
import re
from typing import List, Tuple

# Windows constants for SHEmptyRecycleBinW
_SHERB_NOCONFIRMATION = 0x00000001
_SHERB_NOPROGRESSUI = 0x00000002
_SHERB_NOSOUND = 0x00000004

# track whether interactive mode ran so the __main__ block can pause before closing
launched_interactive = False


def get_temp_dir() -> str:
    return os.path.abspath(os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir())


def empty_recycle_bin(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Permanently empties the Recycle Bin for all drives using SHEmptyRecycleBinW.
    Returns (success, message).
    """
    if dry_run:
        return True, "Dry-run: would call SHEmptyRecycleBinW for all drives."

    try:
        shell32 = ctypes.windll.shell32
        flags = _SHERB_NOCONFIRMATION | _SHERB_NOPROGRESSUI | _SHERB_NOSOUND
        # SHEmptyRecycleBinW(hwnd, pszRootPath, dwFlags)
        hr = shell32.SHEmptyRecycleBinW(None, None, flags)
        if hr == 0:
            return True, "Recycle Bin emptied."
        else:
            return False, f"SHEmptyRecycleBinW returned HRESULT 0x{hr:08X}"
    except Exception as ex:
        return False, f"Exception calling SHEmptyRecycleBinW: {ex}"


def list_network_adapters() -> List[str]:
    """
    Use 'netsh interface show interface' to list adapter names.
    Returns a list of adapter names.
    """
    try:
        proc = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = proc.stdout.splitlines()
        adapters: List[str] = []
        # Skip until we find the header line that contains "Admin State"
        started = False
        for ln in lines:
            if not started:
                if "Admin State" in ln and "State" in ln and "Type" in ln and "Interface Name" in ln:
                    started = True
                continue
            if not ln.strip():
                continue
            # Format columns: Admin State    State    Type    Interface Name
            # Split by whitespace up to 3 times to preserve interface name with spaces
            parts = ln.split(None, 3)
            if len(parts) == 4:
                adapters.append(parts[3].strip())
        return adapters
    except subprocess.CalledProcessError:
        return []


def restart_adapter(adapter_name: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Disable then re-enable a network adapter by name using netsh.
    Returns (success, message).
    """
    if dry_run:
        return True, f"Dry-run: would restart adapter '{adapter_name}'."

    try:
        subprocess.run(
            ["netsh", "interface", "set", "interface", adapter_name, "admin=DISABLED"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["netsh", "interface", "set", "interface", adapter_name, "admin=ENABLED"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True, f"Adapter '{adapter_name}' restarted."
    except subprocess.CalledProcessError as ex:
        return False, f"Command failed for '{adapter_name}': {ex.stderr or ex}"


def apply_tcp_optimizations(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Apply a set of conservative TCP/network optimizations using netsh.
    These are safe, reversible netsh commands. They may require elevated privileges.
    Returns (success, message).
    """
    commands = [
        ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
        ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
        ["netsh", "int", "tcp", "set", "global", "chimney=disabled"],
        ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
        ["netsh", "int", "tcp", "set", "heuristics", "disabled"],
    ]

    if dry_run:
        return True, "Dry-run: would run netsh commands:\n" + "\n".join(" ".join(c) for c in commands)

    out_lines: List[str] = []
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
            out_lines.append(f"OK: {' '.join(cmd)}")
        except subprocess.CalledProcessError as ex:
            out_lines.append(f"FAILED: {' '.join(cmd)} -> {ex.stderr or ex}")
            # Continue running remaining commands but report failure at the end
    return True, "\n".join(out_lines)


def clean_temp_dir(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Removes files and empty directories inside %TEMP% (non-recursive destructive removal).
    This function is intentionally conservative: it only attempts to remove files and then
    empty directories using os.remove and os.rmdir. It will not recursively rmtree unknown
    directories to avoid accidental data loss.
    """
    temp_dir = get_temp_dir()
    if not os.path.exists(temp_dir):
        return False, f"Temp directory '{temp_dir}' does not exist."

    deleted = 0
    failed = 0
    # Walk bottom-up
    for root, dirs, files in os.walk(temp_dir, topdown=False):
        for name in files:
            fp = os.path.join(root, name)
            if dry_run:
                deleted += 1
            else:
                try:
                    os.remove(fp)
                    deleted += 1
                except Exception:
                    failed += 1
        for d in dirs:
            dp = os.path.join(root, d)
            if dry_run:
                deleted += 1
            else:
                try:
                    os.rmdir(dp)
                    deleted += 1
                except Exception:
                    # directory not empty or in use
                    pass
    return True, f"Planned deletions: {deleted}. Failed deletions: {failed}."


# --- New: Wi-Fi profile & password helpers ---------------------------------
def list_wifi_profiles() -> List[str]:
    """
    Return a list of Wi-Fi profile names stored on the system.
    """
    try:
        proc = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True, check=True)
        profiles: List[str] = []
        for ln in proc.stdout.splitlines():
            m = re.search(r"All User Profile\s*:\s*(.+)", ln)
            if m:
                profiles.append(m.group(1).strip())
        return profiles
    except subprocess.CalledProcessError:
        return []


def get_wifi_password(profile: str) -> Tuple[bool, str]:
    """
    Query netsh for the specified profile and extract the Key Content (password).
    Returns (found, password-or-message).
    """
    try:
        proc = subprocess.run(["netsh", "wlan", "show", "profile", profile, "key=clear"],
                              capture_output=True, text=True, check=True)
        m = re.search(r"Key Content\s*:\s*(.+)", proc.stdout)
        if m:
            return True, m.group(1).strip()
        return False, "No password stored (open network or not available)."
    except subprocess.CalledProcessError as ex:
        return False, f"Failed to query profile: {ex}"


def show_wifi_passwords(dry_run: bool = False) -> Tuple[bool, str]:
    if dry_run:
        return True, "Dry-run: would list saved Wi-Fi profiles and their passwords."
    profiles = list_wifi_profiles()
    if not profiles:
        return False, "No Wi-Fi profiles found or failed to query profiles."
    out_lines: List[str] = []
    for p in profiles:
        ok, pw = get_wifi_password(p)
        out_lines.append(f"{p}: {pw}")
    return True, "\n".join(out_lines)
# ---------------------------------------------------------------------------


# --- Progress/Loading spinner helpers --------------------------------------
def _spinner_worker(done_event: threading.Event, prefix: str) -> None:
    frames = ["|", "/", "-", "\\"]
    i = 0
    start = time.time()
    while not done_event.is_set():
        elapsed = int(time.time() - start)
        sys.stdout.write(f"\r{prefix} {frames[i % len(frames)]} Elapsed: {elapsed}s")
        sys.stdout.flush()
        i += 1
        time.sleep(0.12)
    # clear line on finish
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


def run_with_spinner(func, *args, prefix: str = "Working...", **kwargs):
    """
    Run `func(*args, **kwargs)` in a background thread while showing a spinner
    on the main thread. Returns the function's return value.
    """
    done = threading.Event()
    result: dict = {}

    def target():
        try:
            result["value"] = func(*args, **kwargs)
        except Exception as ex:
            result["exc"] = ex
        finally:
            done.set()

    th = threading.Thread(target=target, daemon=True)
    th.start()
    _spinner_worker(done, prefix)
    th.join()
    if "exc" in result:
        raise result["exc"]
    return result.get("value")
# ---------------------------------------------------------------------------


def interactive_menu() -> List[str]:
    choices = []
    print("======================================================")
    print("        Windows optimizer - Interactive Menu")
    print("  Made by Sambota, Cat Eating a chips (AKA MitkoBG)")
    print("======================================================")
    print("Choose actions to perform (comma-separated numbers):")
    print(" 1) Clean %TEMP%")
    print(" 2) Empty Recycle Bin")
    print(" 3) Optimize TCP (apply recommended netsh settings)")
    print(" 4) Restart network adapters (list will be shown)")
    print(" 5) Show saved wifi passwords on PC")
    print(" 6) Run all")
    print(" 7) Create God Mode folder on Desktop")

    raw = input("Selection (e.g. 1,2): ").strip()
    if not raw:
        return choices
    # Map numeric menu entries to action keys
    mapping = {
        "1": "temp",
        "2": "recycle",
        "3": "tcp",
        "4": "restart",
        "5": "wifi",
        "7": "godmode",
    }

    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    # If user chose the "Run all" option, return everything immediately
    if "6" in tokens:
        return ["temp", "recycle", "tcp", "restart", "wifi", "godmode"]

    for token in tokens:
        if token in mapping:
            choices.append(mapping[token])
        # unknown tokens are ignored
    return choices


def ensure_confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        ans = input(prompt + " [y/N]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def create_god_mode(dry_run: bool = False) -> Tuple[bool, str]:
    """Create a God Mode folder on the current user's Desktop."""
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    guid = "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
    path = os.path.join(desktop, guid)
    if dry_run:
        return True, f"Dry-run: would create '{path}'"
    try:
        if not os.path.exists(desktop):
            return False, f"Desktop path not found: {desktop}"
        if not os.path.exists(path):
            os.mkdir(path)
            return True, f"Created God Mode folder: {path}"
        return True, f"God Mode folder already exists: {path}"
    except Exception as ex:
        return False, f"Failed to create God Mode folder: {ex}"


def run_actions(actions: List[str], dry_run: bool = False, assume_yes: bool = False) -> None:
    if not actions:
        print("No actions selected.")
        return

    if "temp" in actions:
        if not ensure_confirm("Proceed to clean %TEMP%?", assume_yes):
            print("Skipped %TEMP% cleanup.")
        else:
            ok, msg = run_with_spinner(clean_temp_dir, dry_run=dry_run, prefix="Cleaning %TEMP%...")
            print("Clean %TEMP% ->", msg)

    if "recycle" in actions:
        if not ensure_confirm("Proceed to empty the Recycle Bin?", assume_yes):
            print("Skipped Recycle Bin empty.")
        else:
            ok, msg = run_with_spinner(empty_recycle_bin, dry_run=dry_run, prefix="Emptying Recycle Bin...")
            print("Empty Recycle Bin ->", msg)

    if "tcp" in actions:
        if not ensure_confirm("Proceed to apply TCP optimizations? (may require admin)", assume_yes):
            print("Skipped TCP optimizations.")
        else:
            ok, msg = run_with_spinner(apply_tcp_optimizations, dry_run=dry_run, prefix="Applying TCP optimizations...")
            print("TCP optimizations ->")
            print(msg)

    if "restart" in actions:
        adapters = list_network_adapters()
        if not adapters:
            print("No adapters found or failed to list adapters.")
        else:
            print("Network adapters:")
            for i, a in enumerate(adapters, start=1):
                print(f" {i}) {a}")
            sel = input("Enter adapter numbers to restart (comma-separated) or 'all': ").strip()
            if not sel:
                print("No adapters selected; skipping restart.")
            else:
                targets: List[str] = []
                if sel.lower() == "all":
                    targets = adapters
                else:
                    for tok in sel.split(","):
                        tok = tok.strip()
                        if not tok:
                            continue
                        try:
                            idx = int(tok) - 1
                            if 0 <= idx < len(adapters):
                                targets.append(adapters[idx])
                        except ValueError:
                            # try to match by name directly
                            if tok in adapters:
                                targets.append(tok)
                for name in targets:
                    if not ensure_confirm(f"Restart adapter '{name}'? This will briefly disconnect network.", assume_yes):
                        print(f"Skipped restarting '{name}'.")
                        continue
                    ok, msg = run_with_spinner(restart_adapter, name, dry_run=dry_run, prefix=f"Restarting '{name}'...")
                    print(f"Restart '{name}' -> {msg}")

    if "wifi" in actions:
        if not ensure_confirm("Proceed to list Wi‑Fi profiles and passwords? (requires appropriate privileges)", assume_yes):
            print("Skipped Wi‑Fi password listing.")
        else:
            ok, msg = run_with_spinner(show_wifi_passwords, dry_run=dry_run, prefix="Gathering Wi‑Fi profiles...")
            print("Wi‑Fi profiles & passwords ->")
            print(msg)

    if "godmode" in actions:
        if not ensure_confirm("Create God Mode folder on Desktop?", assume_yes):
            print("Skipped God Mode creation.")
        else:
            ok, msg = create_god_mode(dry_run=dry_run)
            print(msg)


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows Optimizer: clean temp, empty recycle bin, optimize network adapters.")
    # escape percent signs in help strings to avoid argparse %-formatting errors
    parser.add_argument("--clean-temp", action="store_true", help="Clean %%TEMP%% directory.")
    parser.add_argument("--empty-recycle", action="store_true", help="Empty the Recycle Bin.")
    parser.add_argument("--optimize-tcp", action="store_true", help="Apply conservative TCP/netsh optimizations.")
    parser.add_argument("--restart-adapters", action="store_true", help="Restart selected network adapters.")
    parser.add_argument("--show-wifi", action="store_true", help="Show saved Wi‑Fi profiles and passwords.")
    parser.add_argument("--all", action="store_true", help="Run all actions.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes.")
    parser.add_argument("--yes", action="store_true", help="Assume yes to all confirmations.")
    return parser.parse_args()


def main() -> int:
    global launched_interactive
    args = parse_cli()
    actions: List[str] = []

    # Determine if any CLI flags are present - if so run non-interactively and exit
    cli_flags = any([
        args.clean_temp,
        args.empty_recycle,
        args.optimize_tcp,
        args.restart_adapters,
        args.show_wifi,
        args.all,
    ])

    if args.all:
        actions = ["temp", "recycle", "tcp", "restart", "wifi", "godmode"]
    else:
        if args.clean_temp:
            actions.append("temp")
        if args.empty_recycle:
            actions.append("recycle")
        if args.optimize_tcp:
            actions.append("tcp")
        if args.restart_adapters:
            actions.append("restart")
        if args.show_wifi:
            actions.append("wifi")

    if cli_flags:
        run_actions(actions, dry_run=args.dry_run, assume_yes=args.yes)
        return 0

    # No CLI flags: interactive loop. Keep running until the user chooses to exit.
    launched_interactive = True
    while True:
        actions = interactive_menu()
        if not actions:
            resp = input("No actions selected. Press Enter to exit, or type 'r' to return to the menu: ").strip().lower()
            if resp == 'r':
                continue
            break
        run_actions(actions, dry_run=args.dry_run, assume_yes=args.yes)
        resp = input("Press Enter to return to the menu, or type 'exit' to quit: ").strip().lower()
        if resp == 'exit':
            break

    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        rc = 1
    # If interactive mode ran, pause before closing so double-click launches remain visible
    try:
        if launched_interactive:
            input("Press Enter to close...")
    except EOFError:
        pass
    sys.exit(rc)