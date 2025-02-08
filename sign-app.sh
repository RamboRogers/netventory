#!/bin/bash
set -e

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="${PROJECT_ROOT}/netventory.app"

echo "Signing NetVentory.app..."
echo "Signing app bundle with hardened runtime and entitlements..."

# Sign with your Developer ID and enable hardened runtime
codesign --force --deep --options runtime \
  --entitlements "${PROJECT_ROOT}/NetVentory.entitlements" \
  --sign "Developer ID Application" "${APP_PATH}"

echo "Verifying signature..."
codesign --verify --deep --strict --verbose=4 "${APP_PATH}"

echo "Signing complete!"
echo
echo "Next steps:"
echo "1. Submit the app for notarization using: xcrun notarytool submit \"${APP_PATH}\""
echo "2. Once notarized, staple the ticket using: xcrun stapler staple \"${APP_PATH}\""