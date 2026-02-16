#!/bin/bash
# Flash BeskarCore to VisionFive 2 SD card
# Usage: ./flash_visionfive2.sh /dev/sdX

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <SD_CARD_DEVICE>"
  echo "Example: $0 /dev/sdX  (Linux) or //wsl$/Ubuntu/dev/sdX (Windows WSL2)"
  exit 1
fi

DEVICE=$1

echo "[+] Building BeskarCore for VisionFive 2..."
cd ../beskarcore || exit 1
make jh7110_visionfive2

echo "[+] Unmounting SD card..."
sudo umount ${DEVICE}* 2>/dev/null

echo "[+] Writing image to $DEVICE..."
sudo dd if=images/beskarcore.img of=$DEVICE bs=1M status=progress conv=fsync

echo "[+] Syncing..."
sync

echo "[✓] Done. Insert SD card into VisionFive 2 and boot."
echo "[!] Connect serial console (115200 8N1) to see: 'BeskarCore v1.0 — Shield Active'"
