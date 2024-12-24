#!/bin/bash

# Configuration
VERSION="0.2.0n"
GITHUB_REPO="ramborogers/netventory"
PLATFORMS=("darwin/amd64" "darwin/arm64" "linux/amd64" "linux/arm64" "windows/amd64")

# Ensure gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh) is not installed. Please install it first."
    exit 1
fi

# Ensure gh is authenticated
if ! gh auth status &> /dev/null; then
    echo "GitHub CLI is not authenticated. Please run 'gh auth login' first."
    exit 1
fi

# Create bins directory if it doesn't exist
mkdir -p bins

# Build for all platforms
for platform in "${PLATFORMS[@]}"; do
    OS="${platform%/*}"
    ARCH="${platform#*/}"

    echo "Building for $OS/$ARCH..."

    # Set output name based on platform
    if [ "$OS" = "windows" ]; then
        output_name="netventory-$OS-$ARCH.exe"
    else
        output_name="netventory-$OS-$ARCH"
    fi

    # Build the binary
    GOOS=$OS GOARCH=$ARCH go build -o "bins/$output_name"

    # Generate SHA256 hash
    if [ -f "bins/$output_name" ]; then
        if [ "$OS" = "windows" ]; then
            sha256sum "bins/$output_name" | cut -d ' ' -f 1 > "bins/$output_name.sha256"
            # Create netventory.zip for Windows
            echo "Creating netventory.zip for Windows..."
            cd bins
            rm -f netventory.zip
            zip netventory.zip "$output_name"
            cd ..
        else
            shasum -a 256 "bins/$output_name" > "bins/$output_name.sha256"
        fi
    fi
done

# Update Homebrew formula
echo "Updating Homebrew formula..."
DARWIN_AMD64_SHA=$(cat bins/netventory-darwin-amd64.sha256 | cut -d ' ' -f 1)
DARWIN_ARM64_SHA=$(cat bins/netventory-darwin-arm64.sha256 | cut -d ' ' -f 1)

# Update the formula file
sed -i '' "s/version \".*\"/version \"$VERSION\"/" homebrew-netventory/Formula/netventory.rb
sed -i '' "s/sha256 \".*\" # amd64/sha256 \"$DARWIN_AMD64_SHA\" # amd64/" homebrew-netventory/Formula/netventory.rb
sed -i '' "s/sha256 \".*\" # arm64/sha256 \"$DARWIN_ARM64_SHA\" # arm64/" homebrew-netventory/Formula/netventory.rb

# Ask about GitHub release
read -p "Create GitHub Release? (y/N): " do_release
if [[ $do_release =~ ^[Yy]$ ]]; then
    echo "Creating GitHub release..."
    gh release create "v$VERSION" \
        --title "v$VERSION" \
        --notes "Release v$VERSION" \
        bins/netventory-* bins/netventory.zip
    echo "GitHub release created!"
else
    echo "Skipping GitHub release."
fi

echo "Build process complete!"
