#!/bin/bash

# Configuration
VERSION="0.4.0n"
GITHUB_REPO="ramborogers/netventory"
PLATFORMS=("darwin/amd64" "darwin/arm64" "linux/amd64" "linux/arm64" "windows/amd64")

# Check if private.txt exists, if not create a template
if [ ! -f "private.txt" ]; then
    echo "Creating template private.txt..."
    cat <<EOL > private.txt
# Private configuration template
# Add your telemetry server and token below

TELEMETRY_SERVER=
TELEMETRY_TOKEN=
EOL
fi


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

# Get SHA256 values
DARWIN_AMD64_SHA=$(cat bins/netventory-darwin-amd64.sha256 | cut -d ' ' -f 1)
DARWIN_ARM64_SHA=$(cat bins/netventory-darwin-arm64.sha256 | cut -d ' ' -f 1)

# Create Homebrew formula content
cat > homebrew-netventory/Formula/netventory.rb << EOL
class Netventory < Formula
  desc "Network inventory and discovery tool"
  homepage "https://github.com/ramborogers/netventory"
  version "$VERSION"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ramborogers/netventory/releases/download/$VERSION/netventory-darwin-amd64"
      sha256 "$DARWIN_AMD64_SHA" # amd64
    else
      url "https://github.com/ramborogers/netventory/releases/download/$VERSION/netventory-darwin-arm64"
      sha256 "$DARWIN_ARM64_SHA" # arm64
    end
  end

  def install
    if Hardware::CPU.intel?
      bin.install "netventory-darwin-amd64" => "netventory"
    else
      bin.install "netventory-darwin-arm64" => "netventory"
    end
    # Remove quarantine attribute
    system "xattr", "-d", "com.apple.quarantine", "#{bin}/netventory"
  rescue
    # Ignore if xattr fails (in case attribute doesn't exist)
    nil
  end

  test do
    system "#{bin}/netventory", "--version"
  end
end
EOL

# Ask about GitHub release
read -p "Create GitHub Release? (y/N): " do_release
if [[ $do_release =~ ^[Yy]$ ]]; then
    echo "Creating GitHub release..."
    gh release create "$VERSION" \
        --title "$VERSION" \
        --notes "Release $VERSION" \
        bins/netventory-* bins/netventory.zip
    echo "GitHub release created!"
else
    echo "Skipping GitHub release."
fi

echo "Build process complete!"
