# Speicheranalyse für Windows

`storage_analyzer.py` ist ein eigenständiges, rein lesendes Analysewerkzeug für Windows. Es zeigt, welche Programme, Store-Apps, App-Daten, Entwicklerwerkzeuge und persönlichen Ordner Speicher belegen. Das Tool löscht, verschiebt oder verändert **keine** Dateien.

## Voraussetzungen

- Windows 10 oder Windows 11
- Python 3.10 oder neuer (`python --version`)
- Keine zusätzlichen Python-Pakete

## Schnellstart

PowerShell im entpackten Ordner öffnen und ausführen:

```powershell
python .\storage_analyzer.py --top 40 --min-size 250M --verbose
```

Die Analyse kann je nach Zahl und Größe der Dateien einige Minuten dauern. Mit `--verbose` erscheint der Fortschritt im Terminal.

## Was wird standardmäßig analysiert?

- Installierte Programme unter `Program Files` und `Program Files (x86)`
- Microsoft-Store-Apps unter `AppData\Local\Packages` (zum Beispiel Clipchamp)
- Lokale, Roaming- und gemeinsame App-Daten (`AppData`, `ProgramData`)
- Entwicklerdaten wie `.vscode`, `.cache`, `.docker`, `.npm` und `.conda`
- Eigene Dateien wie Desktop, Downloads, Dokumente und Videos
- Die großen Systemdateien `pagefile.sys`, `hiberfil.sys` und `swapfile.sys`

`C:\Windows` wird nicht automatisch gescannt, weil es für die Zuordnung zu einzelnen Programmen wenig hilfreich ist und den Lauf deutlich verlängert.

## Nützliche Befehle

### Mehr Ergebnisse anzeigen

```powershell
python .\storage_analyzer.py --top 60 --min-size 100M
```

### Laufwerksübersicht inklusive Windows und Papierkorb

```powershell
python .\storage_analyzer.py --overview --include-system --top 40
```

Die Laufwerksübersicht ist eine zusätzliche Ansicht und überlappt mit der Programmdetailansicht. Beide Tabellen dürfen deshalb nicht addiert werden.

### Einen auffälligen Ordner genauer untersuchen

```powershell
python .\storage_analyzer.py --root "$env:LOCALAPPDATA\Packages" --top 40 --show-paths
```

Weitere sinnvolle Beispiele sind:

```powershell
python .\storage_analyzer.py --root "$env:LOCALAPPDATA\Docker" --top 30
python .\storage_analyzer.py --root "$env:USERPROFILE\.vscode" --top 30
```

### Maschinenlesbaren Bericht erzeugen

```powershell
python .\storage_analyzer.py --format json > storage-report.json
```

### Logische Dateigröße statt „Größe auf Datenträger“ verwenden

```powershell
python .\storage_analyzer.py --logical-size
```

## Optionen

| Option | Bedeutung |
| --- | --- |
| `--top 40` | Begrenzt die Zahl der angezeigten Ergebnisse. |
| `--min-size 250M` | Blendet kleinere Einträge aus. Unterstützt z. B. `100M`, `1.5G` und `2GiB`. |
| `--root PFAD` | Analysiert einen einzelnen Ordner detailliert. |
| `--overview` | Ergänzt eine direkte Übersicht der Inhalte des Systemlaufwerks. |
| `--include-system` | Nimmt zusätzlich `C:\Windows`, Papierkorb und geschützte Systembereiche auf. |
| `--show-paths` | Zeigt vollständige Pfade in der Tabelle. |
| `--format json` | Gibt einen JSON-Bericht auf der Konsole aus. |
| `--logical-size` | Nutzt die logische Dateigröße statt der Windows-Belegung. |
| `--verbose` | Zeigt den Fortschritt auf der Konsole an. |

## Hinweise zur Interpretation

- Standardmäßig zeigt das Tool die Windows-„Größe auf Datenträger“. Das ist bei komprimierten oder sparse Dateien oft aussagekräftiger als die logische Dateigröße.
- Microsoft-Store-Apps erscheinen mit ihrem Paketnamen. Beispielsweise steht `Clipchamp.Clipchamp_...` für Clipchamp.
- `Fehler / Links` zeigt nicht lesbare Pfade und übersprungene Junctions/Symlinks. Junctions werden bewusst nicht verfolgt, damit Ordner nicht doppelt gezählt werden.
- Einige geschützte Systemordner lassen sich ohne Administratorrechte nur teilweise oder gar nicht messen. Das Tool weist darauf hin, statt unzugängliche Bereiche als leer zu behandeln.
- Das Tool liest ausschließlich Metadaten und Dateigrößen. Es nimmt keine Bereinigung vor.

## Hilfe

```powershell
python .\storage_analyzer.py --help
```
