#!/usr/bin/env bash
# install-desktop.sh — add HYEONGI to the application menu: the desktop app
# ("HYEONGI") and the terminal launcher ("HYEONGI (terminal)", Kali style).
#
# Installs for the CURRENT user only (no root needed):
#   ~/.local/share/applications/hyeongi.desktop
#   ~/.local/share/icons/hicolor/scalable/apps/hyeongi.svg
#   ~/.local/share/icons/hicolor/256x256/apps/hyeongi.png   (if available)
#
# Run it from anywhere:  bash packaging/install-desktop.sh
# Uninstall:             bash packaging/install-desktop.sh --uninstall

set -euo pipefail

# repo root = parent of this script's directory
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

APPS="$HOME/.local/share/applications"
ICON_SVG_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
ICON_PNG_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
DESKTOP="$APPS/hyeongi.desktop"
DESKTOP_TERM="$APPS/hyeongi-terminal.desktop"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$DESKTOP" "$DESKTOP_TERM" "$ICON_SVG_DIR/hyeongi.svg" "$ICON_PNG_DIR/hyeongi.png"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
  echo "HYEONGI desktop entry removed."
  exit 0
fi

mkdir -p "$APPS" "$ICON_SVG_DIR" "$ICON_PNG_DIR"

# make sure the launcher is executable
chmod +x "$ROOT/bin/hyeongi" "$ROOT/bin/hyeongid" 2>/dev/null || true

# install icons
install -m 0644 "$ROOT/assets/hyeongi.svg" "$ICON_SVG_DIR/hyeongi.svg"
if [[ -f "$ROOT/assets/hyeongi-256.png" ]]; then
  install -m 0644 "$ROOT/assets/hyeongi-256.png" "$ICON_PNG_DIR/hyeongi.png"
fi

# write the .desktop with absolute paths substituted in
for pair in "hyeongi.desktop:$DESKTOP" "hyeongi-terminal.desktop:$DESKTOP_TERM"; do
  sed -e "s|__HYEONGI_DIR__|$ROOT|g" -e "s|__HYEONGI_ICON__|hyeongi|g" \
      "$ROOT/packaging/${pair%%:*}" > "${pair#*:}"
  chmod 0644 "${pair#*:}"
done

# refresh the desktop + icon caches (best effort)
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "Installed:"
echo "  $DESKTOP  (app)"
echo "  $DESKTOP_TERM  (terminal)"
echo "  $ICON_SVG_DIR/hyeongi.svg"
[[ -f "$ICON_PNG_DIR/hyeongi.png" ]] && echo "  $ICON_PNG_DIR/hyeongi.png"
echo
echo "HYEONGI should now appear in your application menu under Security/Network."
echo "If it doesn't show immediately, log out/in or run:  update-desktop-database $APPS"
if ! python3 -c "import PySide6" 2>/dev/null; then
  echo
  echo "The app needs PySide6 for your user:  python3 -m pip install --user PySide6-Essentials"
fi
if ! command -v pkexec >/dev/null 2>&1; then
  echo "The app asks for root through pkexec (polkit), which is not installed."
fi
