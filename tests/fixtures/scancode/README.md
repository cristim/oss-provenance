# ScanCode public MIT report

`32.4.1-public-mit.json` is the unmodified output of ScanCode Toolkit 32.4.1, using Python 3.12.14 and Click 8.2.1 on macOS ARM64. It scans the existing unmodified SCANOSS reference and its complete MIT grant from `LICENSE-NOTICES/scanoss-winnowing/`, at upstream-relative paths `src/scanoss/winnowing.py` and `LICENSE`.

The command used `--license --info --strip-root --processes 0 --quiet --no-check-version --json REPORT INPUT`. The report contains only public fixture data and temporary paths. Tests require both exact file hashes, the pinned tool version, and empty scan errors. Detection does not admit license applicability or obligations.
