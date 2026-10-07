package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dominikszabo/yara-scanner/internal/engine"
)

// Scanner represents the core scanning functionality
type Scanner struct {
	engine      engine.Engine
	rulesPath   string
	results     []engine.Result
	resultsMu   sync.Mutex
	processed   map[string]bool
	processedMu sync.Mutex
	workers     int
}

// ScannerConfig holds configuration for the scanner
type ScannerConfig struct {
	RulesPath string
	Workers   int
	Timeout   int
	Threads   int
}

// NewScanner creates a new scanner instance
func NewScanner(config ScannerConfig) (*Scanner, error) {
	// Validate config
	if config.RulesPath == "" {
		config.RulesPath = "rules"
	}
	if config.Workers == 0 {
		config.Workers = 4
	}
	if config.Timeout == 0 {
		config.Timeout = 300 // 5 minutes default timeout
	}
	
	// Create engine
	yaraPath := os.Getenv("YARA_PATH")
	if yaraPath == "" {
		yaraPath = "yara.exe"
	}
	
	eng := engine.NewCLIEngine(yaraPath)
	eng.SetTimeout(config.Timeout)
	eng.SetThreads(config.Threads)
	
	return &Scanner{
		engine:    eng,
		rulesPath: config.RulesPath,
		workers:   config.Workers,
		processed: make(map[string]bool),
	}, nil
}

// ScanPath scans a file or directory path
func (s *Scanner) ScanPath(ctx context.Context, path string) ([]engine.Result, error) {
	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not found: %w", err)
	}
	
	// Check if it's a file or directory
	if info.IsDir() {
		return s.scanDirectory(ctx, path)
	}
	
	return s.scanFile(ctx, path)
}

// scanDirectory recursively scans a directory
func (s *Scanner) scanDirectory(ctx context.Context, dir string) ([]engine.Result, error) {
	var allResults []engine.Result
	var wg sync.WaitGroup
	errChan := make(chan error, s.workers)
	
	// Walk the directory tree (errors handled in callback)
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories
		if d.IsDir() {
			return nil
		}
		
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Check file extension
		ext := filepath.Ext(path)
		if ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == "" {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				results, err := s.scanFile(ctx, p)
				if err != nil {
					errChan <- fmt.Errorf("failed to scan %s: %w", p, err)
					return
				}
				
				s.resultsMu.Lock()
				s.results = append(s.results, results...)
				s.resultsMu.Unlock()
			}(path)
		}
		
		return nil
	})
	
	wg.Wait()
	close(errChan)
	
	// Collect errors
	for range errChan {
		allResults = append(allResults, engine.Result{
			Rule:    "filesystem_error",
			Matches: false,
		})
	}
	
	return s.deduplicateResults(allResults), nil
}

// scanFile scans a single file
func (s *Scanner) scanFile(ctx context.Context, path string) ([]engine.Result, error) {
	// Check for duplicates
	if s.isProcessed(path) {
		return nil, nil
	}
	s.markProcessed(path)
	
	// Perform scan
	results, err := s.engine.Scan(ctx, path, s.rulesPath)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	
	// Add file metadata to results
	for i := range results {
		results[i].Meta["file_path"] = path
		results[i].Meta["file_size"] = fmt.Sprintf("%d", getFileSize(path))
		results[i].Meta["file_hash"] = getFileHash(path)
	}
	
	return results, nil
}

// ScanProcess scans a Windows process by PID
func (s *Scanner) ScanProcess(ctx context.Context, pid int) ([]engine.Result, error) {
	// On Windows, process scanning requires special handling
	// We'll use a placeholder implementation here
	// The actual implementation would use Windows APIs via go-ole or syscall
	
	// For now, return an error indicating this needs Windows-specific implementation
	return nil, fmt.Errorf("process scanning requires Windows-specific implementation")
}

// ScanMemory scans process memory
func (s *Scanner) ScanMemory(ctx context.Context, processID int) ([]engine.Result, error) {
	// Memory scanning implementation
	return nil, fmt.Errorf("memory scanning requires Windows-specific implementation")
}

// scanProcess scans a single process
func (s *Scanner) scanProcess(ctx context.Context, processID int) error {
	// Process scanning placeholder
	// Would need Windows-specific implementation using:
	// - OpenProcess()
	// - ReadProcessMemory()
	// - YARA scanning of memory buffer
	
	return nil
}

// deduplicateResults removes duplicate scan results
func (s *Scanner) deduplicateResults(results []engine.Result) []engine.Result {
	seen := make(map[string]bool)
	var deduped []engine.Result
	
	for _, result := range results {
		key := generateResultKey(result)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, result)
		}
	}
	
	return deduped
}

// isProcessed checks if a path has already been processed
func (s *Scanner) isProcessed(path string) bool {
	s.processedMu.Lock()
	defer s.processedMu.Unlock()
	return s.processed[path]
}

// markProcessed marks a path as processed
func (s *Scanner) markProcessed(path string) {
	s.processedMu.Lock()
	defer s.processedMu.Unlock()
	s.processed[path] = true
}

// getFileSize returns the size of a file
func getFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// getFileHash returns the SHA256 hash of a file
func getFileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// generateResultKey generates a unique key for a result
func generateResultKey(result engine.Result) string {
	return fmt.Sprintf("%s:%s", result.Rule, result.Namespace)
}

// GetResults returns all scan results
func (s *Scanner) GetResults() []engine.Result {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	return s.results
}

// ClearResults clears all scan results
func (s *Scanner) ClearResults() {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	s.results = nil
}

// GetProcessedCount returns the number of processed items
func (s *Scanner) GetProcessedCount() int {
	s.processedMu.Lock()
	defer s.processedMu.Unlock()
	return len(s.processed)
}

// GetEngine returns the YARA engine
func (s *Scanner) GetEngine() engine.Engine {
	return s.engine
}

// ScanResult represents a single scan operation result
type ScanResult struct {
	Path      string          `json:"path"`
	Results   []engine.Result `json:"results"`
	Timestamp time.Time       `json:"timestamp"`
	Error     string          `json:"error,omitempty"`
}

// RunScan runs a complete scan operation
func (s *Scanner) RunScan(ctx context.Context, path string) (*ScanResult, error) {
	// start := time.Now() // could track duration if needed
	
	results, err := s.ScanPath(ctx, path)
	if err != nil {
		return &ScanResult{
			Path:      path,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, err
	}
	
	return &ScanResult{
		Path:      path,
		Results:   results,
		Timestamp: time.Now(),
	}, nil
}
