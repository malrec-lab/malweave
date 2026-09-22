#!/usr/bin/env bash
set -euo pipefail

# Bootstrap external tools for a Ghidra extraction worker. Python packages remain locked in uv.

echo "=== MalWeave Ghidra Worker Setup ==="
echo ""

# Configuration - customize these before running
GHIDRA_VERSION="${GHIDRA_VERSION:-11.2.1_PUBLIC}"
GHIDRA_DATE="${GHIDRA_DATE:-20241105}"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION%_*}_build/ghidra_${GHIDRA_VERSION}_${GHIDRA_DATE}.zip"
JAVA_VERSION="${JAVA_VERSION:-21}"
UV_VERSION="0.11.9"
PYTHON_VERSION="3.12.12"
GHIDRA_SHA256="${GHIDRA_SHA256:-}"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

if [[ "$EUID" -eq 0 ]]; then
    PRIVILEGED=()
elif command -v sudo &>/dev/null; then
    PRIVILEGED=(sudo)
else
    echo "Root access or sudo is required to install Linux system packages." >&2
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install system dependencies
echo "Installing system dependencies..."
if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &>/dev/null; then
        "${PRIVILEGED[@]}" apt-get update -qq
        "${PRIVILEGED[@]}" apt-get install -y -qq curl unzip openjdk-${JAVA_VERSION}-jdk
    elif command -v yum &>/dev/null; then
        "${PRIVILEGED[@]}" yum install -y -q curl unzip java-${JAVA_VERSION}-openjdk
    else
        echo "No supported package manager found (apt-get or yum)"
        exit 1
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not found. Please install it first: https://brew.sh"
        exit 1
    fi
    brew install "openjdk@${JAVA_VERSION}"
    export JAVA_HOME="$(brew --prefix "openjdk@${JAVA_VERSION}")/libexec/openjdk.jdk/Contents/Home"
    export PATH="$JAVA_HOME/bin:$PATH"
fi

# Verify Java
echo "Verifying Java installation..."
java -version 2>&1 | head -n 1

# Install uv
echo ""
echo "Installing uv ${UV_VERSION}..."
UV_BIN="${UV_BIN:-$(command -v uv || true)}"
if [[ -z "$UV_BIN" ]]; then
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh
    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [[ -x "$candidate" ]]; then
            UV_BIN="$candidate"
            break
        fi
    done
fi
if [[ -z "$UV_BIN" ]] || [[ ! -x "$UV_BIN" ]]; then
    echo "uv was installed but could not be located; set UV_BIN and rerun." >&2
    exit 1
fi
export PATH="$(dirname "$UV_BIN"):$PATH"
"$UV_BIN" --version
if ! "$UV_BIN" --version | grep -q "${UV_VERSION}"; then
    echo "Error: expected uv ${UV_VERSION}; set UV_BIN to the required version." >&2
    exit 1
fi

# Clone or update repository
echo ""
REPO_DIR="${MALWEAVE_REPO_DIR:-$HOME/malweave}"
if [[ -d "$REPO_DIR" ]]; then
    echo "Repository already exists at $REPO_DIR"
    echo "To update, run: cd $REPO_DIR && git pull"
else
    echo "Please clone the repository manually to $REPO_DIR"
    echo "Example: git clone <repository-url> $REPO_DIR"
    exit 1
fi

cd "$REPO_DIR"

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
"$UV_BIN" python install "$PYTHON_VERSION"
"$UV_BIN" sync --locked

# Download and setup Ghidra
echo ""
GHIDRA_DIR="${GHIDRA_DIR:-$HOME/ghidra}"
GHIDRA_INSTALL="$GHIDRA_DIR/ghidra_${GHIDRA_VERSION}"

if [[ -d "$GHIDRA_INSTALL" ]]; then
    echo "Ghidra already installed at $GHIDRA_INSTALL"
else
    echo "Downloading Ghidra ${GHIDRA_VERSION}..."
    mkdir -p "$GHIDRA_DIR"
    cd "$GHIDRA_DIR"

    GHIDRA_ARCHIVE="ghidra_${GHIDRA_VERSION}_${GHIDRA_DATE}.zip"
    if [[ ! -f "$GHIDRA_ARCHIVE" ]]; then
        curl --fail --location --retry 3 "$GHIDRA_URL" --output "$GHIDRA_ARCHIVE"
    fi

    if [[ -n "$GHIDRA_SHA256" ]]; then
        if command -v sha256sum &>/dev/null; then
            printf '%s  %s\n' "$GHIDRA_SHA256" "$GHIDRA_ARCHIVE" | sha256sum --check --status
        else
            [[ "$(shasum -a 256 "$GHIDRA_ARCHIVE" | awk '{print $1}')" == "$GHIDRA_SHA256" ]]
        fi
    else
        echo "Warning: GHIDRA_SHA256 is unset; record the downloaded archive checksum privately." >&2
    fi

    echo "Extracting Ghidra..."
    unzip -q "$GHIDRA_ARCHIVE"

    cd "$REPO_DIR"
fi

export GHIDRA_ROOT="$GHIDRA_INSTALL"

# Verify Ghidra
echo ""
echo "Verifying Ghidra installation..."
if [[ "$OS" == "linux" ]]; then
    ANALYZE_HEADLESS="$GHIDRA_ROOT/support/analyzeHeadless"
else
    ANALYZE_HEADLESS="$GHIDRA_ROOT/support/analyzeHeadless"
fi

if [[ ! -x "$ANALYZE_HEADLESS" ]]; then
    echo "Error: analyzeHeadless not found or not executable at $ANALYZE_HEADLESS"
    exit 1
fi

HELP_OUTPUT="$("$ANALYZE_HEADLESS" -help 2>&1 || true)"
if [[ "$HELP_OUTPUT" != *"analyzeHeadless"* ]] && [[ "$HELP_OUTPUT" != *"Usage"* ]]; then
    echo "Error: analyzeHeadless did not return its help text: $ANALYZE_HEADLESS" >&2
    exit 1
fi

# Create the usable local environment file without overwriting an existing configuration.
echo ""
echo "Creating local environment configuration..."
if [[ -e "$REPO_DIR/.env" ]]; then
    echo "Keeping existing $REPO_DIR/.env"
else
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    echo "Created $REPO_DIR/.env from .env.example"
fi

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "Next steps:"
echo "1. The default $REPO_DIR/.env is ready for this checkout's data/ layout and ~/ghidra."
echo "   Edit it only if this worker uses different mounted paths: nano .env"
echo ""
echo "2. Ensure RanDS corpus is available (network mount or local copy)"
echo ""
echo "3. The section runner creates output, state, and work directories as needed."
echo ""
echo "4. Verify installation:"
echo "   $UV_BIN run --locked malweave data inspect --dataset rands"
echo "   \$GHIDRA_ROOT/support/analyzeHeadless -help"
echo ""
echo "Environment variables set in this session:"
echo "  GHIDRA_ROOT=$GHIDRA_ROOT"
echo "  JAVA_HOME=${JAVA_HOME:-<system default>}"
