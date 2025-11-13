#!/usr/bin/env fish
# Load environment and run oscap-service commands

# Check if .env file exists
if not test -f .env
    echo "❌ Error: .env file not found"
    echo "💡 Tip: Copy .env.example to .env and configure it"
    exit 1
end

# Read and export each variable from .env
echo "📝 Loading environment variables from .env..."
for line in (cat .env | grep -v '^$' | grep -v '^#')
    set -gx (string split '=' -- $line)
end

echo "✓ Environment loaded"
echo ""

# Check if command argument provided
if test (count $argv) -eq 0
    echo "Usage: ./start.fish <command>"
    echo ""
    echo "Available commands:"
    echo "  status      - Show service status"
    echo "  scan        - Run compliance scan"
    echo "  remediate   - Interactive remediation"
    echo "  rollback    - Restore to checkpoint"
    echo "  reports     - Manage reports"
    echo ""
    echo "Example: ./start.fish status"
    exit 1
end

# Run the oscap-service with provided command
echo "🚀 Running: oscap-service $argv"
echo ""
exec ./oscap-service $argv
