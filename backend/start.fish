#!/usr/bin/env fish
# Build and start compliance-monitor with environment variables loaded

# Check if .env file exists
if not test -f .env
    echo "Error: .env file not found"
    exit 1
end

# Build the binary
echo "🔨 Building compliance-monitor..."
go build -o compliance-monitor main.go

if test $status -ne 0
    echo "❌ Build failed"
    exit 1
end

echo "✓ Build successful"

# Read and export each variable
for line in (cat .env | grep -v '^$' | grep -v '^#')
    set -gx (string split '=' -- $line)
end

echo "✓ Environment variables loaded from .env"
echo "🚀 Starting compliance-monitor..."
echo ""

# Run the server with inherited environment
exec ./compliance-monitor
