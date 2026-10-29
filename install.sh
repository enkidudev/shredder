#!/bin/sh
set -eu
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
chmod +x "$SOURCE_DIR/shredder.py"
ln -sfn "$SOURCE_DIR/shredder.py" "$INSTALL_DIR/shredder"
echo "Installed. Run shredder --doctor"
