#!/usr/bin/env python3
"""Read-only storage analysis for Windows.

The script attributes disk use to installed programs, Microsoft Store app data,
shared program data, user app data, developer tooling, and personal folders.
It never deletes, moves, or changes any files.

Examples
--------
    python storage_analyzer.py
    python storage_analyzer.py --top 50 --min-size 250M
    python storage_analyzer.py --overview --include-system
    python storage_analyzer.py --root "%LOCALAPPDATA%\\Microsoft" --top 40
    python storage_analyzer.py --format json > storage-report.json

The default report deliberately avoids scanning C:\\Windows because it is slow
and not useful for attributing storage to individual applications.  Use
--include-system when that information is wanted as well.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import stat
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


REPARSE_POINT = 0x0400
SYSTEM_FILE_NAMES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")
PERSONAL_FOLDERS = {
    "desktop",
    "documents",
    "downloads",
    "music",
    "pictures",
    "videos",
    "onedrive",
}
DEVELOPER_FOLDERS = {
    ".cache",
    ".cargo",
    ".codex",
    ".conda",
    ".docker",
    ".gradle",
    ".m2",
    ".npm",
    ".nuget",
    ".vscode",
}


@dataclass(frozen=True)
class Candidate:
    """One non-overlapping path within a report section."""

    category: str
    label: str
    path: Path


@dataclass
class ScanResult:
    category: str
    label: str
    path: str
    allocated_bytes: int
    logical_bytes: int
    files: int
    denied: int
    skipped_reparse_points: int


@dataclass
class ScanCounters:
    denied: int = 0
    skipped_reparse_points: int = 0


def windows_path_from_env(name: str, fallback: Path) -> Path:
    """Return a Windows special directory without assuming a specific user name."""

    value = os.environ.get(name)
    return Path(value) if value else fallback


def system_drive_root() -> Path:
    """Return ``C:\\`` rather than the drive-relative Windows path ``C:``."""

    value = os.environ.get("SystemDrive")
    if value and re.fullmatch(r"[A-Za-z]:", value):
        return Path(value + "\\")
    return Path(value) if value else Path("C:\\")


def input_path(value: str) -> Path:
    """Accept home/environment-variable shortcuts supplied at the command line."""

    return Path(os.path.expandvars(os.path.expanduser(value)))


def normal_path_key(path: Path) -> str:
    """A comparison key that does not resolve junctions or require permissions."""

    return os.path.normcase(os.path.abspath(os.fspath(path)))


def is_reparse_point(file_stat: os.stat_result) -> bool:
    return bool(getattr(file_stat, "st_file_attributes", 0) & REPARSE_POINT)


def path_stat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def path_is_reparse_point(path: Path) -> bool:
    file_stat = path_stat(path)
    return bool(file_stat and is_reparse_point(file_stat))


class SizeReader:
    """Reads logical or allocated file sizes without modifying the file system."""

    def __init__(self, allocated: bool) -> None:
        self.allocated = allocated
        self._get_compressed_file_size = None

        if allocated and os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            function = kernel32.GetCompressedFileSizeW
            function.argtypes = (ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong))
            function.restype = ctypes.c_ulong
            self._get_compressed_file_size = function

    def size_for(self, path: str, file_stat: os.stat_result) -> tuple[int, int]:
        """Return (allocated_size, logical_size), falling back safely if needed."""

        logical = file_stat.st_size
        if not self._get_compressed_file_size:
            return logical, logical

        high = ctypes.c_ulong(0)
        ctypes.set_last_error(0)
        low = self._get_compressed_file_size(path, ctypes.byref(high))
        error = ctypes.get_last_error()

        # INVALID_FILE_SIZE can also be a valid low DWORD.  It is an error only
        # if Windows has set a non-zero last-error value.
        if low == 0xFFFFFFFF and error:
            return logical, logical

        allocated = (high.value << 32) | low
        return allocated, logical


class DirectoryScanner:
    """Iterative scanner that skips junctions/symlinks and tolerates denial."""

    def __init__(self, allocated: bool, verbose: bool = False) -> None:
        self.size_reader = SizeReader(allocated)
        self.verbose = verbose

    def scan(self, candidate: Candidate) -> ScanResult:
        counters = ScanCounters()
        allocated_total = 0
        logical_total = 0
        files = 0
        root_stat = path_stat(candidate.path)

        if root_stat is None:
            return ScanResult(
                candidate.category,
                candidate.label,
                str(candidate.path),
                0,
                0,
                0,
                1,
                0,
            )
        if is_reparse_point(root_stat):
            return ScanResult(
                candidate.category,
                candidate.label,
                str(candidate.path),
                0,
                0,
                0,
                0,
                1,
            )

        if stat.S_ISREG(root_stat.st_mode):
            allocated_total, logical_total = self.size_reader.size_for(
                os.fspath(candidate.path), root_stat
            )
            files = 1
        elif stat.S_ISDIR(root_stat.st_mode):
            stack = [os.fspath(candidate.path)]
            while stack:
                current = stack.pop()
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            try:
                                entry_stat = entry.stat(follow_symlinks=False)
                            except OSError:
                                counters.denied += 1
                                continue

                            if is_reparse_point(entry_stat):
                                counters.skipped_reparse_points += 1
                                continue

                            if stat.S_ISDIR(entry_stat.st_mode):
                                stack.append(entry.path)
                            elif stat.S_ISREG(entry_stat.st_mode):
                                allocated, logical = self.size_reader.size_for(
                                    entry.path, entry_stat
                                )
                                allocated_total += allocated
                                logical_total += logical
                                files += 1
                                if self.verbose and files % 20_000 == 0:
                                    print(
                                        f"  {candidate.label}: {files:,} Dateien, "
                                        f"{format_size(allocated_total)} bisher",
                                        file=sys.stderr,
                                    )
                except (OSError, PermissionError):
                    counters.denied += 1

        return ScanResult(
            category=candidate.category,
            label=candidate.label,
            path=str(candidate.path),
            allocated_bytes=allocated_total,
            logical_bytes=logical_total,
            files=files,
            denied=counters.denied,
            skipped_reparse_points=counters.skipped_reparse_points,
        )


def entries_below(
    root: Path,
    category: str,
    *,
    excluded_names: Iterable[str] = (),
    include_files: bool = False,
    label_prefix: str = "",
) -> list[Candidate]:
    """Make candidates for direct children while preventing junction recursion."""

    excluded = {name.casefold() for name in excluded_names}
    candidates: list[Candidate] = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name.casefold() in excluded:
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_reparse_point(entry_stat):
                    continue
                if stat.S_ISDIR(entry_stat.st_mode) or (
                    include_files and stat.S_ISREG(entry_stat.st_mode)
                ):
                    candidates.append(
                        Candidate(category, f"{label_prefix}{entry.name}", Path(entry.path))
                    )
    except (OSError, PermissionError):
        pass
    return candidates


def add_candidate(candidates: list[Candidate], seen: set[str], candidate: Candidate) -> None:
    """Append an existing, non-junction candidate only once."""

    key = normal_path_key(candidate.path)
    if key in seen or path_stat(candidate.path) is None or path_is_reparse_point(candidate.path):
        return
    seen.add(key)
    candidates.append(candidate)


def add_children(
    candidates: list[Candidate],
    seen: set[str],
    root: Path,
    category: str,
    *,
    excluded_names: Iterable[str] = (),
    include_files: bool = False,
    label_prefix: str = "",
) -> None:
    for candidate in entries_below(
        root,
        category,
        excluded_names=excluded_names,
        include_files=include_files,
        label_prefix=label_prefix,
    ):
        add_candidate(candidates, seen, candidate)


def default_candidates(include_system: bool) -> list[Candidate]:
    """Build a non-overlapping program/user-data view of the current PC."""

    user_profile = windows_path_from_env("USERPROFILE", Path.home())
    local_app_data = windows_path_from_env("LOCALAPPDATA", user_profile / "AppData" / "Local")
    roaming_app_data = windows_path_from_env("APPDATA", user_profile / "AppData" / "Roaming")
    program_data = windows_path_from_env("PROGRAMDATA", Path(r"C:\ProgramData"))
    system_drive = system_drive_root()
    program_files = windows_path_from_env("ProgramW6432", Path(r"C:\Program Files"))
    program_files_x86 = windows_path_from_env(
        "ProgramFiles(x86)", Path(r"C:\Program Files (x86)")
    )

    candidates: list[Candidate] = []
    seen: set[str] = set()

    # Program installations, each row representing one top-level vendor/product folder.
    add_children(candidates, seen, program_files, "Installierte Programme (64-bit)")
    add_children(candidates, seen, program_files_x86, "Installierte Programme (32-bit)")

    # AppData is partitioned deliberately so a package is never added twice.
    packages = local_app_data / "Packages"
    programs = local_app_data / "Programs"
    temp = local_app_data / "Temp"
    local_low = user_profile / "AppData" / "LocalLow"
    add_children(candidates, seen, packages, "Microsoft-Store-App-Daten")
    add_children(candidates, seen, programs, "Installierte Benutzerprogramme")
    add_candidate(candidates, seen, Candidate("Temporäre Daten", "AppData\\Local\\Temp", temp))
    add_children(
        candidates,
        seen,
        local_app_data,
        "Lokale App-Daten",
        excluded_names=("Packages", "Programs", "Temp"),
    )
    add_children(candidates, seen, local_low, "App-Daten (LocalLow)")
    add_children(candidates, seen, roaming_app_data, "Roaming-App-Daten")

    # ProgramData contains shared caches, installers, and data used by all users.
    add_children(candidates, seen, program_data, "Gemeinsame Programmdaten")

    # Everything directly in the profile, except AppData (already partitioned above).
    try:
        with os.scandir(user_profile) as entries:
            for entry in entries:
                if entry.name.casefold() == "appdata":
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_reparse_point(entry_stat):
                    continue
                if not (stat.S_ISDIR(entry_stat.st_mode) or stat.S_ISREG(entry_stat.st_mode)):
                    continue

                lowered = entry.name.casefold()
                if lowered in DEVELOPER_FOLDERS or entry.name.startswith("."):
                    category = "Entwicklerdaten"
                elif lowered in PERSONAL_FOLDERS:
                    category = "Eigene Dateien"
                else:
                    category = "Benutzerdaten"
                add_candidate(candidates, seen, Candidate(category, entry.name, Path(entry.path)))
    except (OSError, PermissionError):
        pass

    # Large root-level virtual-memory files are useful context, but do not overlap
    # with the directory rows above.
    for file_name in SYSTEM_FILE_NAMES:
        root_file = system_drive / file_name
        add_candidate(candidates, seen, Candidate("Systemdatei", file_name, root_file))

    if include_system:
        add_candidate(candidates, seen, Candidate("Windows-System", "Windows", system_drive / "Windows"))
        add_candidate(
            candidates,
            seen,
            Candidate("Papierkorb", "$Recycle.Bin", system_drive / "$Recycle.Bin"),
        )
        add_candidate(
            candidates,
            seen,
            Candidate(
                "Geschützter Systembereich",
                "System Volume Information",
                system_drive / "System Volume Information",
            ),
        )

    return candidates


def overview_candidates(root: Path) -> list[Candidate]:
    """Return an intentionally separate, top-level view of one directory/drive."""

    root_stat = path_stat(root)
    if root_stat is None:
        raise FileNotFoundError(f"Pfad existiert nicht oder ist nicht lesbar: {root}")
    if is_reparse_point(root_stat):
        raise ValueError(f"Der Analysepfad ist ein Junction/Symlink: {root}")
    if stat.S_ISREG(root_stat.st_mode):
        return [Candidate("Benutzerdefinierter Pfad", root.name or str(root), root)]

    return entries_below(
        root,
        "Laufwerksübersicht",
        include_files=True,
    )


def parse_size(value: str) -> int:
    """Parse values such as 500M, 1.5GiB, or 0."""

    match = re.fullmatch(r"\s*(\d+(?:[.,]\d+)?)\s*([kmgtpe]?i?b?)?\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError(
            "Ungültige Größe. Beispiele: 0, 500M, 1.5G, 2GiB"
        )
    number = float(match.group(1).replace(",", "."))
    suffix = (match.group(2) or "").casefold().rstrip("b")
    factors = {"": 1, "k": 1024, "ki": 1024, "m": 1024**2, "mi": 1024**2,
               "g": 1024**3, "gi": 1024**3, "t": 1024**4, "ti": 1024**4,
               "p": 1024**5, "pi": 1024**5, "e": 1024**6, "ei": 1024**6}
    return int(number * factors[suffix])


def format_size(number: int) -> str:
    value = float(number)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{number} B"  # Unreachable, but keeps type checkers happy.


def shorten(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    return value[: maximum - 1] + "…"


def results_to_rows(
    results: Sequence[ScanResult],
    minimum: int,
    top: int,
    show_paths: bool,
) -> list[list[str]]:
    selected = [result for result in results if result.allocated_bytes >= minimum]
    selected.sort(key=lambda result: result.allocated_bytes, reverse=True)
    selected = selected[:top]

    rows: list[list[str]] = []
    for result in selected:
        row = [
            shorten(result.category, 29),
            shorten(result.label, 43),
            format_size(result.allocated_bytes),
            f"{result.files:,}",
        ]
        if result.denied or result.skipped_reparse_points:
            row.append(f"{result.denied} / {result.skipped_reparse_points}")
        else:
            row.append("–")
        if show_paths:
            row.append(result.path)
        rows.append(row)
    return rows


def print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    if not rows:
        print("Keine passenden Dateien oder Ordner gefunden.")
        return

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def divider(fill: str = "-") -> str:
        return "+" + "+".join(fill * (width + 2) for width in widths) + "+"

    def rendered(row: Sequence[str]) -> str:
        return "|" + "|".join(
            f" {value.ljust(widths[index])} " for index, value in enumerate(row)
        ) + "|"

    print(divider())
    print(rendered(headers))
    print(divider("="))
    for row in rows:
        print(rendered(row))
    print(divider())


def drive_summary(path: Path) -> str | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    used = usage.total - usage.free
    return (
        f"Laufwerk {path.drive or path}: {format_size(used)} belegt, "
        f"{format_size(usage.free)} frei von {format_size(usage.total)}"
    )


def scan_candidates(
    candidates: Sequence[Candidate], allocated: bool, verbose: bool
) -> list[ScanResult]:
    scanner = DirectoryScanner(allocated=allocated, verbose=verbose)
    results: list[ScanResult] = []
    for index, candidate in enumerate(candidates, start=1):
        if verbose:
            print(
                f"[{index}/{len(candidates)}] Scanne {candidate.path}",
                file=sys.stderr,
            )
        results.append(scanner.scan(candidate))
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rein lesende Windows-Speicheranalyse nach Programmen, App-Daten "
            "und Benutzerordnern. Es werden niemals Dateien verändert."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  python storage_analyzer.py\n"
            "  python storage_analyzer.py --top 50 --min-size 250M\n"
            "  python storage_analyzer.py --overview --include-system\n"
            "  python storage_analyzer.py --root \"%LOCALAPPDATA%\\Microsoft\"\n"
            "  python storage_analyzer.py --format json > storage-report.json\n\n"
            "Hinweis: Junctions/Symlinks werden nicht verfolgt. Geschützte "
            "Systemordner können ohne Administratorrechte unvollständig sein."
        ),
    )
    parser.add_argument(
        "--root",
        type=input_path,
        help=(
            "Analysiert stattdessen nur die direkten Inhalte dieses Ordners. "
            "Praktisch für einen detaillierten zweiten Durchgang."
        ),
    )
    parser.add_argument(
        "--overview",
        action="store_true",
        help=(
            "Ergänzt eine direkte Laufwerksübersicht. Sie überlappt absichtlich "
            "mit der Programmdetailansicht und kann länger dauern."
        ),
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Scannt zusätzlich C:\\Windows und den Papierkorb; das kann länger dauern.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=35,
        help="Maximale Zahl angezeigter Einträge pro Ansicht (Standard: 35).",
    )
    parser.add_argument(
        "--min-size",
        type=parse_size,
        default=0,
        metavar="GRÖSSE",
        help="Kleinste anzuzeigende Größe, z. B. 100M oder 1.5G.",
    )
    parser.add_argument(
        "--logical-size",
        action="store_true",
        help=(
            "Zeigt logische Dateigrößen statt Windows 'Größe auf Datenträger'. "
            "Der Standard ist 'Größe auf Datenträger'."
        ),
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="Zeigt den vollständigen Pfad jeder Zeile.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Ausgabeformat (Standard: table). JSON wird auf stdout geschrieben.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Schreibt den Fortschritt nach stderr.",
    )
    return parser


def print_results(
    title: str,
    results: Sequence[ScanResult],
    args: argparse.Namespace,
    elapsed_seconds: float,
) -> None:
    total = sum(result.allocated_bytes for result in results)
    denied = sum(result.denied for result in results)
    reparse_points = sum(result.skipped_reparse_points for result in results)
    size_name = "Größe auf Datenträger" if not args.logical_size else "Logische Größe"

    if args.format == "json":
        payload = {
            "title": title,
            "size_measure": size_name,
            "elapsed_seconds": round(elapsed_seconds, 2),
            "sum_of_rows_bytes": total,
            "denied_paths": denied,
            "skipped_reparse_points": reparse_points,
            "results": [asdict(result) for result in results],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print(f"\n{title}")
    print(f"Messart: {size_name} | Summe dieser Ansicht: {format_size(total)}")
    headers = ["Kategorie", "Programm / Datenbereich", "Belegt", "Dateien", "Fehler / Links"]
    if args.show_paths:
        headers.append("Pfad")
    print_table(
        headers,
        results_to_rows(results, args.min_size, args.top, args.show_paths),
    )
    print(
        f"Fertig in {elapsed_seconds:.1f} s. Nicht lesbare Pfade: {denied}; "
        f"übersprungene Junctions/Symlinks: {reparse_points}."
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error("--top muss mindestens 1 sein.")

    if args.root and args.overview:
        parser.error("--root und --overview können nicht zusammen verwendet werden.")
    if args.root and args.include_system:
        parser.error("--include-system ist nur ohne --root sinnvoll.")
    if args.overview and args.format == "json":
        parser.error(
            "--overview und --format json können nicht kombiniert werden; "
            "bitte die beiden Ansichten getrennt ausführen."
        )

    allocated = not args.logical_size
    started = time.perf_counter()

    try:
        if args.root:
            candidates = overview_candidates(args.root)
            results = scan_candidates(candidates, allocated, args.verbose)
            print_results(
                f"Benutzerdefinierte Analyse: {args.root}",
                results,
                args,
                time.perf_counter() - started,
            )
            return 0

        system_drive = system_drive_root()
        if args.format == "table":
            summary = drive_summary(system_drive)
            if summary:
                print(summary)
            print(
                "\nProgrammdetailansicht: Die folgenden Zeilen sind bewusst "
                "nicht mit einer optionalen Laufwerksübersicht zu addieren."
            )

        candidates = default_candidates(args.include_system)
        results = scan_candidates(candidates, allocated, args.verbose)
        elapsed = time.perf_counter() - started
        print_results("Programme, App-Daten und Benutzerordner", results, args, elapsed)

        if args.overview:
            if args.format == "table":
                print(
                    "\nLaufwerksübersicht: Diese Ansicht überlappt mit der "
                    "Programmdetailansicht oben und darf nicht dazuaddiert werden."
                )
            overview_started = time.perf_counter()
            overview = scan_candidates(
                overview_candidates(system_drive), allocated, args.verbose
            )
            print_results(
                f"Laufwerksübersicht: {system_drive}",
                overview,
                args,
                time.perf_counter() - overview_started,
            )

    except KeyboardInterrupt:
        print("\nAnalyse abgebrochen; es wurden keine Dateien verändert.", file=sys.stderr)
        return 130
    except (FileNotFoundError, ValueError) as error:
        print(f"Fehler: {error}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
