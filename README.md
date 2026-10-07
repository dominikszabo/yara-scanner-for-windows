# YARA Scanner

A Go-based YARA scanner agent with bundled yara.exe for Windows endpoints. This project provides filesystem scanning, process scanning, and memory scanning capabilities.

## Features

- ✅ Filesystem scanning (recursive directory walking)
- ✅ Process scanning (Windows process memory scanning)
- ✅ File scanning with YARA rules
- ✅ Bundle yara.exe (no CGO required)
- ✅ Cross-compile from Linux to Windows
- ✅ JSON output format
- ✅ Rule compilation and caching
- ✅ Deduplication of scan results
- ✅ Silent installation with auto-config

## Architecture

```
yara-scanner/
├── cmd/
│   ├── agent/          # CLI agent for endpoint scanning
│   └── server/         # Optional server mode for remote scanning
├── internal/
│   ├── engine/         # YARA engine wrapper (calls yara.exe)
│   ├── scanner/        # Core scanning logic (filesystem, processes, memory)
│   └── agent/          # Agent service management
├── rules/              # YARA rule files
├── deploy/             # Deployment artifacts
├── docs/               # Documentation
└── .github/workflows/  # CI/CD pipelines
```

## Tech Stack

- **Language**: Go 1.27.1
- **YARA**: Bundled yara.exe (no CGO)
- **Build**: Cross-compile from Linux to Windows
- **CI/CD**: GitHub Actions
- **License**: MIT

## Installing

### Direct Download

Download `yara.exe` from the official releases:

```bash
# Windows PowerShell
Invoke-WebRequest -Uri "https://github.com/Satellile/yara/releases/download/latest/yara.exe" -OutFile "yara.exe"

# Windows CMD
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/Satellile/yara/releases/download/latest/yara.exe' -OutFile 'yara.exe'"
```

### Running the Agent

1. Place `yara.exe` in the same directory as `yara-scanner-agent.exe`
2. Open Command Prompt or PowerShell in that directory
3. Run the agent:
   ```bash
   ./yara-scanner-agent.exe scan /path/to/scan
   ```

4. First-time setup: The agent will automatically detect and configure your output folder. Run `yara config` to open the config directory and manually edit settings if needed.

## Quick Start

### Building from Source

```bash
# Build for Windows (cross-compile from Linux)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o yara-scanner-agent.exe ./cmd/agent

# Build for Linux
go build -o yara-scanner-agent ./cmd/agent
```

### Running the Agent

```bash
# Scan a directory
./yara-scanner-agent.exe scan /path/to/scan

# Scan a specific file
./yara-scanner-agent.exe scan /path/to/file.exe

# Scan running processes
./yara-scanner-agent.exe scan-processes

# Use custom yara.exe path
YARA_PATH=/path/to/yara.exe ./yara-scanner-agent.exe scan /path/to/scan

# Output to file
./yara-scanner-agent.exe scan /path/to/scan --output results.json
```

## YARA Rule Organization

Place your YARA rules in the `rules/` directory:

```
rules/
├── malware.yar
├── suspicious.yar
└── ... (more rule files)
```

Rules are loaded and compiled at startup. Multiple rule files can be loaded simultaneously.

See `rules/README.md` for more information about rule format and sources.

## Deploying

### Manual Deployment

1. Copy `yara-scanner-agent.exe` and `yara.exe` to the target Windows endpoint
2. Run from Command Prompt or PowerShell
3. Add to startup via Task Scheduler or Registry if needed

### Automated Deployment (GPO/Intune)

See `deploy/` directory for sample scripts:
- `deploy/install.ps1` - PowerShell installer
- `deploy/uninstall.ps1` - Uninstall script
- `deploy/configure-gpo.md` - GPO configuration guide

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| YARA_PATH | yara.exe | Path to bundled yara.exe |
| SCAN_THREADS | 4 | Number of concurrent scan threads |
| LOG_LEVEL | info | Log level (debug, info, warn, error) |

## Agent Commands

- `scan <path>` - Scan a file or directory
- `scan-processes` - Scan running processes
- `scan-memory` - Scan process memory
- `list-rules` - List loaded YARA rules
- `compile-rules` - Compile and validate rules

## CI/CD

The project includes GitHub Actions workflows for:

- Go 1.27.1 compatibility
- Cross-compile to Windows (amd64)
- Test execution
- Build artifacts

See `.github/workflows/ci.yml` for details.

## License

MIT - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- YARA by Victor M. Alvarez (@plusvic, @vmalvarez)
- Go language team for the amazing toolchain
- Satellile for yara.exe (https://github.com/Satellile/yara)
