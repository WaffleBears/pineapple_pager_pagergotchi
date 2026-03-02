#!/bin/bash
# Title: Bjorn
# Requires: /root/payloads/user/reconnaissance/pager_bjorn
# Bjorn launcher — runs bjorn_menu.py which handles the menu loop and Bjorn process
# Used for handoff from pagergotchi (or any payload) to Bjorn

BJORN_DIR="/root/payloads/user/reconnaissance/pager_bjorn"

if [ ! -d "$BJORN_DIR" ]; then
    echo "Bjorn not found at $BJORN_DIR"
    exit 1
fi

# Bjorn environment
export PATH="/mmc/usr/bin:$PATH"
export PYTHONPATH="$BJORN_DIR/lib:$BJORN_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$BJORN_DIR/lib:$BJORN_DIR:$LD_LIBRARY_PATH"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

cd "$BJORN_DIR"
python3 bjorn_menu.py
exit $?
