#!/bin/sh
# Adds mindyourownbytes to your applications menu, for your account only.
#
# Run it from the folder you unpacked, and again if you move that folder. It writes only
# below your home folder, and needs no administrator rights. To take the entry out again,
# delete ~/.local/share/applications/mindyourownbytes.desktop.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
data="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$data/applications" "$data/icons/hicolor/256x256/apps"
cp "$here/mindyourownbytes.png" "$data/icons/hicolor/256x256/apps/mindyourownbytes.png"

cat > "$data/applications/mindyourownbytes.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=mindyourownbytes
Comment=Encrypt your files before any cloud sees them
Exec="$here/mindyourownbytes" %F
Icon=mindyourownbytes
Terminal=false
Categories=Utility;Security;
ENTRY

echo "mindyourownbytes is now in your applications menu."
