#!/bin/bash

# Create bins directory if it doesn't exist
mkdir -p bins

# Build function
build() {
    local GOOS=$1
    local GOARCH=$2
    local EXTENSION=""

    # Add .exe extension for Windows
    if [ "$GOOS" = "windows" ]; then
        EXTENSION=".exe"
    fi

    # Build name format: netventory-os-arch
    local BINARY="netventory-${GOOS}-${GOARCH}${EXTENSION}"

    echo "Building $BINARY..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "bins/$BINARY" -ldflags="-s -w" netventory.go

    # Create checksum
    if [ "$GOOS" = "windows" ]; then
        (cd bins && sha256sum "$BINARY" > "${BINARY}.sha256")
    else
        (cd bins && shasum -a 256 "$BINARY" > "${BINARY}.sha256")
    fi
}

echo "🔨 Building NetVentory..."
echo "================================"

# Build for various platforms
build "linux" "amd64"
build "linux" "arm64"
build "darwin" "amd64"
build "darwin" "arm64"
build "windows" "amd64"

echo "================================"
echo "✅ Build complete! Binaries in ./bins:"
ls -lh bins/

cd bins
rm -f netventory.zip
zip netventory.zip netventory-windows-amd64.exe
