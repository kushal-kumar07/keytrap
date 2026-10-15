#!/bin/bash

###############################################################################
# KeyTrap Quick Runner
# Loads environment and runs keytrap with proper configuration
###############################################################################

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found"
    echo "Please run: cp .env.example .env"
    exit 1
fi

# Load environment
export $(cat .env | grep -v '^#' | xargs)

# macOS: Set library path for WeasyPrint
if [[ "$OSTYPE" == "darwin"* ]]; then
    export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib
fi

# Run keytrap with all arguments passed through
exec keytrap "$@"
