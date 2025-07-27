#!/bin/bash
# lint.sh - Helper script for running Ruff linting and formatting

set -e

echo "🔍 Running Ruff linter..."
ruff check .

echo ""
echo "🎨 Running Ruff formatter..."
ruff format .

echo ""
echo "✅ Linting and formatting complete!"
