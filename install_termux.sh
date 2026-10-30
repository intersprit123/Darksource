#!/data/data/com.termux/files/usr/bin/bash
set -eu
pkg update
pkg install -y python git curl
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
chmod +x darksource.py
echo "DarkSource UE installed."
echo "Try: python darksource.py https://example.com"
echo "Phone metadata: python darksource.py --phone +14155552671"
