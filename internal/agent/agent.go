package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dominikszabo/yara-scanner/internal/engine"
	"github.com/dominikszabo/yara-scanner/internal/scanner"
)

// Agent represents the YARA scanner agent
type Agent struct {
	scannerObj   *scanner.Scanner
	rulesDir     string
	config       Config
	shutdownChan chan struct{}
}

// Config holds agent configuration
type Config struct {
	RulesPath    string   `json:"rules_path"`
	ScanPaths    []string `json:"scan_paths"`
	Workers      int      `json:"workers"`
	Timeout      int      `json:"timeout"`
	Threads      int      `json:"threads"`
	OutputDir    string   `json:"output_dir"`
	LogLevel     string   `json:"log_level"`
	YaraPath     string   `json:"yara_path"`
}

// DefaultConfig returns default agent configuration
func DefaultConfig() Config {
	return Config{
		RulesPath:  "rules",
		Workers:    4,
		Timeout:    300,
		Threads:    4,
		OutputDir:  "output",
		LogLevel:   "info",
		YaraPath:   "", // will default to yara.exe
	}
}

// NewAgent creates a new agent instance
func NewAgent(config Config) (*Agent, error) {
	// Validate and set defaults
	if config.RulesPath == "" {
		config.RulesPath = "rules"
	}
	if config.Workers == 0 {
		config.Workers = 4
	}
	if config.Timeout == 0 {
		config.Timeout = 300
	}
	if config.OutputDir == "" {
		config.OutputDir = "output"
	}
	
	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// Create scanner
	s, err := scanner.NewScanner(scanner.ScannerConfig{
		RulesPath: config.RulesPath,
		Workers:   config.Workers,
		Timeout:   config.Timeout,
		Threads:   config.Threads,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}
	
	return &Agent{
		scannerObj:   s,
		rulesDir:     config.RulesPath,
		config:       config,
		shutdownChan: make(chan struct{}),
	}, nil
}

// Start starts the agent
func (a *Agent) Start(ctx context.Context) error {
	fmt.Printf("Starting YARA Scanner Agent...\n")
	fmt.Printf("Rules directory: %s\n", a.rulesDir)
	fmt.Printf("Workers: %d\n", a.config.Workers)
	
	// Load rules
	if err := a.loadRules(ctx); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}
	
	// Start scan loop
	go a.scanLoop(ctx)
	
	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	select {
	case <-sigChan:
		fmt.Println("\nShutting down...")
	case <-ctx.Done():
		fmt.Println("\nContext cancelled")
	case <-a.shutdownChan:
		fmt.Println("\nShutdown requested")
	}
	
	return nil
}

// loadRules loads YARA rules from the rules directory
func (a *Agent) loadRules(ctx context.Context) error {
	rulesPath := a.rulesDir
	
	// Check if rules directory exists
	info, err := os.Stat(rulesPath)
	if err != nil {
		return fmt.Errorf("rules directory not found: %w", err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("rules path is not a directory")
	}
	
	// Find all .yar files
	var ruleFiles []string
	err = filepath.WalkDir(rulesPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(path) == ".yar" || filepath.Ext(path) == ".yara") {
			ruleFiles = append(ruleFiles, path)
		}
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}
	
	if len(ruleFiles) == 0 {
		return fmt.Errorf("no YARA rule files found in %s", rulesPath)
	}
	
	fmt.Printf("Loaded %d rule file(s)\n", len(ruleFiles))
	return nil
}

// scanLoop performs periodic scanning
func (a *Agent) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.performScans(ctx)
		}
	}
}

// performScans performs all configured scans
func (a *Agent) performScans(ctx context.Context) {
	fmt.Println("Performing scheduled scan...")
	
	for _, path := range a.config.ScanPaths {
		result, err := a.scannerObj.RunScan(ctx, path)
		if err != nil {
			fmt.Printf("Scan error for %s: %v\n", path, err)
			continue
		}
		
		// Save results to file
		a.saveResults(result)
		
		// Print summary
		fmt.Printf("Scanned %s: %d matches\n", path, len(result.Results))
	}
}

// scanPath scans a specific path and saves results
func (a *Agent) scanPath(ctx context.Context, path string) error {
	result, err := a.scannerObj.RunScan(ctx, path)
	if err != nil {
		return err
	}
	
	a.saveResults(result)
	return nil
}

// saveResults saves scan results to a file
func (a *Agent) saveResults(result *scanner.ScanResult) {
	if result == nil {
		return
	}
	
	// Generate filename with timestamp
	timestamp := result.Timestamp.Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s.json", timestamp)
	
	// Build output path
	outputPath := filepath.Join(a.config.OutputDir, filename)
	
	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal results: %v\n", err)
		return
	}
	
	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		fmt.Printf("Failed to save results: %v\n", err)
		return
	}
	
	fmt.Printf("Results saved to: %s\n", outputPath)
}

// ScanDirectory scans a directory
func (a *Agent) ScanDirectory(ctx context.Context, path string) error {
	result, err := a.scannerObj.RunScan(ctx, path)
	if err != nil {
		return err
	}
	
	a.saveResults(result)
	
	// Print results
	for _, r := range result.Results {
		if r.Matches {
			fmt.Printf("Match found: %s in %s\n", r.Rule, result.Path)
		}
	}
	
	return nil
}

// ScanFile scans a single file
func (a *Agent) ScanFile(ctx context.Context, path string) error {
	return a.ScanDirectory(ctx, path)
}

// ScanProcess scans a process by PID
func (a *Agent) ScanProcess(ctx context.Context, pid int) error {
	// Process scanning requires Windows-specific implementation
	// For now, return error
	return fmt.Errorf("process scanning requires Windows-specific implementation")
}

// GetEngine returns the YARA engine
func (a *Agent) GetEngine() engine.Engine {
	return a.scannerObj.GetEngine()
}

// GetResults returns all scan results
func (a *Agent) GetResults() []engine.Result {
	return a.scannerObj.GetResults()
}

// ClearResults clears all scan results
func (a *Agent) ClearResults() {
	a.scannerObj.ClearResults()
}
