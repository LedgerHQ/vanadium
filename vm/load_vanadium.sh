#!/usr/bin/env bash

set -e  # Exit on any error

# Ensure we are in the directory where the script is located
cd "$(dirname "$0")"

# Create a temporary directory for the virtual environment
TEMP_DIR=$(mktemp -d)

# setup cleanup function on exit, so we don't leave temp files around
cleanup() {
    if type deactivate >/dev/null 2>&1; then
        deactivate
    fi
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

echo "Setting up virtual environment..."
# Create the virtual environment inside it, and activate it
python3 -m venv "$TEMP_DIR/venv"
source "$TEMP_DIR/venv/bin/activate"

echo "Installing dependencies (this might take a moment)..."
# Install required python libraries
# We redirect stdout to /dev/null to keep it clean, but let stderr through in case of errors
pip install --upgrade pip setuptools wheel > /dev/null
pip install ledgerblue > /dev/null

echo "Detecting device..."
# try to detect the target_id of the connected device
# The APDU 0xE001000000 is GET TARGET ID
if ! target_id=$(python3 -c "from ledgerblue.comm import getDongle; dongle = getDongle(False); print(dongle.exchange(bytearray([0xE0, 0x01, 0x00, 0x00, 0x00]))[:4].hex())"); then
    echo "Error: Failed to communicate with the device. Please ensure the device is connected and unlocked."
    exit 1
fi

case $target_id in
    "33000004")
        echo "Sideloading is not supported on Ledger Nano X."
        exit 1
        ;;
    "33100004")
        model=nanosplus
        model_full="Nano S Plus"
        ;;
    "33200004")
        model=stax
        model_full="Stax"
        ;;
    "33300004")
        model=flex
        model_full="Flex"
        ;;
    "33400004")
        model=apex_p
        model_full="Nano Gen5"
        ;;
    *)
        echo "Unknown or unsupported device (target_id: $target_id)"
        exit 1
        ;;
esac

# check that the .apdu file exists
apdu_file="target/$model/release/app-vanadium.apdu"
if [ ! -f "$apdu_file" ]; then
    echo "Error: Vanadium binary not found at $apdu_file."
    echo "Please run ./download_vanadium.sh, or build the app yourself."
    exit 1
fi

echo "Loading Vanadium onto your Ledger $model_full."
echo "Please follow the instructions on your device."

# sideload the app
if ! python3 -m ledgerblue.runScript --targetId "0x$target_id" --fileName "$apdu_file" --apdu --scp > /dev/null; then
    echo "Error: Failed to load the application onto the device. Is the device firmware up to date?"
    exit 1
fi

echo "Vanadium app successfully loaded onto the device."
