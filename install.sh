#!/bin/sh
# Короткий адрес установщика Diode:
#
#   curl -fsSL https://diode-editor.github.io/install.sh | sh
#   curl -fsSL https://diode-editor.github.io/install.sh | sh -s -- --method=apt
#
# Сам установщик живёт в основном репозитории (diode-editor/diode, файл install.sh
# в корне) и тестируется там. Этот файл — только переадресация на его актуальную
# версию с raw.githubusercontent.com, чтобы адрес на лендинге не менялся и копию
# не нужно было синхронизировать. Аргументы (--method=…, --help) передаются как есть.

set -eu

SRC="https://raw.githubusercontent.com/diode-editor/diode/main/install.sh"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$SRC" | sh -s -- "$@"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O - "$SRC" | sh -s -- "$@"
else
    echo "install.sh: need curl or wget" >&2
    exit 1
fi
