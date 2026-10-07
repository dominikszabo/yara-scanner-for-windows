# YARA Scanner Documentation

## Overview

YARA Scanner is a Go-based endpoint security tool that uses YARA rules for malware detection and suspicious activity identification. It supports scanning of files, processes, and memory on Windows endpoints.

## Architecture

### Core Components

1. **Engine** (`internal/engine`)
   - YARA engine interface
   - Command-line wrapper for yara.exe
   - Rule compilation and caching

2. **Scanner** (`internal/scanner`)
   - Filesystem scanning
   - Process scanning (Windows)
   - Memory scanning (Windows)
   - Result deduplication

3. **Agent** (`internal/agent`)
   - Agent service management
   - Configuration handling
   - Result persistence

4. **CLI** (`cmd/`)
   - Agent CLI commands
   - Server CLI commands

### Data Flow

```
┌─────────────────┐
│    CLI/Agent    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Engine       │
│  (yara.exe)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Scanner       │
│  (walk, dedup)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Output       │
│   (JSON)        │
└─────────────────┘
```

## Building

### Prerequisites
- Go 1.27.1 or later
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/dominikszabo/yara-scanner.git
cd yara-scanner

# Download dependencies
go mod tidy

# Build for current platform
go build -o yara-scanner-agent ./cmd/agent

# Build for Windows (cross-compile)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o yara-scanner-agent.exe ./cmd/agent
```

## Usage

### CLI Commands

```bash
# Scan a file
./yara-scanner-agent.exe scan /path/to/file

# Scan a directory
./yara-scanner-agent.exe scan /path/to/directory

# Scan processes
./yara-scanner-agent.exe scan-processes

# Scan memory
./yara-scanner-agent.exe scan-memory

# List loaded rules
./yara-scanner-agent.exe list-rules

# Compile rules
./yara-scanner-agent.exe compile-rules

# Help
./yara-scanner-agent.exe help
```

### Output Format

Results are output in JSON format:

```json
{
  "target": "/path/to/file.exe",
  "timestamp": "2025-01-01T12:00:00Z",
  "results": [
    {
      "rule": "Malware_Suspicious",
      "namespace": "default",
      "tags": ["malware", "suspicious"],
      "matches": true,
      "meta": {
        "file_path": "/path/to/file.exe",
        "file_size": "12345",
        "file_hash": "abc123..."
      },
      "strings": []
    }
  ]
}
```

## YARA Rules

### Rule Files Location

Rules are loaded from the `rules/` directory. All `.yar` and `.yara` files are loaded automatically.

### Rule Syntax

YARA rules follow the standard YARA syntax:

```yara
rule RuleName {
    meta:
        description = "Rule description"
        author = "Author Name"
        severity = "high"
    
    strings:
        $string1 = "malware string"
        $string2 = { 01 02 03 04 }
    
    condition:
        $string1 or $string2
}
```

### Rule Categories

- **malware.yar**: Known malware signatures
- **suspicious.yar**: Suspicious activity patterns
- **custom.yar**: Organization-specific rules

## Configuration

### Environment Variables

```bash
# YARA executable path
YARA_PATH=/path/to/yara.exe

# Number of worker threads
SCAN_THREADS=4

# Log level
LOG_LEVEL=info

# Output directory
OUTPUT_DIR=output
```

### Configuration File

Create a `config.json` file:

```json
{
  "rules_path": "rules",
  "scan_paths": ["/path/to/scan"],
  "workers": 4,
  "timeout": 300,
  "threads": 4,
  "output_dir": "output",
  "log_level": "info"
}
```

## Windows Process Scanning

Windows process scanning requires:
1. Running as administrator
2. Windows-specific YARA features
3. Proper permissions to read process memory

### Example

```powershell
# Run as administrator
.\yara-scanner-agent.exe scan-processes
```

## Memory Scanning

Memory scanning is supported for:
- Running processes
- Process memory dumps
- System memory regions

## Development

### Project Structure

```
yara-scanner/
├── cmd/               # CLI commands
│   ├── agent/        # Agent CLI
│   └── server/       # Server CLI
├── internal/         # Internal packages
│   ├── engine/       # YARA engine wrapper
│   ├── scanner/      # Scanning logic
│   └── agent/        # Agent service
├── rules/            # YARA rule files
├── deploy/           # Deployment scripts
├── docs/             # Documentation
└── .github/          # CI/CD workflows
```

### Adding New Features

1. Add code to appropriate `internal/` package
2. Update CLI commands in `cmd/`
3. Update documentation
4. Add tests

## Testing

```bash
# Run all tests
go test ./...

# Run specific test
go test ./internal/engine -v

# Test with coverage
go test ./... -coverprofile=coverage.out
```

## Troubleshooting

### Common Issues

1. **yara.exe not found**
   - Ensure yara.exe is in PATH or specify YARA_PATH
   
2. **Permission denied**
   - Run as administrator on Windows
   
3. **Rule compilation failed**
   - Check YARA rule syntax
   
4. **Slow scanning**
   - Increase worker threads
   - Use -w flag for faster scanning

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT - See LICENSE for details.

## Acknowledgments

- YARA by Victor M. Alvarez (@plusvic, @vmalvarez)
- Go language team
