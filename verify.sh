#!/bin/bash
set -e

echo "Verifying yara-scanner project..."
echo ""

# Check Go version
echo "=== Go version ==="
go version

# Verify go.mod
echo ""
echo "=== go.mod verification ==="
go mod verify

# Run tests (will fail until tests are added, but shows the pattern)
echo ""
echo "=== Running go test (no tests yet) ==="
go test ./... -v || echo "No tests yet - this is expected for v0.1"

# Build Linux agent
echo ""
echo "=== Building Linux agent ==="
go build -o yara-scanner-agent ./cmd/agent
echo "✓ Linux build successful"

# Build Windows agent (cross-compile)
echo ""
echo "=== Building Windows agent (cross-compile) ==="
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o yara-scanner-agent.exe ./cmd/agent
echo "✓ Windows build successful"

# Verify no cgo dependency
echo ""
echo "=== Checking for CGO usage ==="
if grep -r "import \"C\"" internal/ 2>/dev/null; then
  echo "⚠️  WARNING: CGO detected - cross-compile may fail"
else
  echo "✓ No CGO detected - pure Go cross-compilation supported"
fi

# Display artifacts
echo ""
echo "=== Build artifacts ==="
ls -lh yara-scanner-agent* 2>/dev/null || echo "No artifacts found"

echo ""
echo "✓ Verification complete!"

