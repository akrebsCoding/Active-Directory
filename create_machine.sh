#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: ./create_machine.sh <machine-name>"
  exit 1
fi

MACHINE="$1"
mkdir -p "$MACHINE"/{01_Recon/nmap,02_Enumeration,03_Exploitation,04_PrivEsc,05_Post-Exploitation,Loot,Screenshots,Shells}
touch "$MACHINE/notes.md"
touch "$MACHINE/Loot/Creds.md"
touch "$MACHINE/report.md"

echo "✅ Struktur für $MACHINE erstellt!"
echo "   → cd $MACHINE && ls"
