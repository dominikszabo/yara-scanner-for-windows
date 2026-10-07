package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Result represents a single YARA scan result
type Result struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Tags      []string          `json:"tags"`
	Matches   bool              `json:"matches"`
	Meta      map[string]string `json:"meta"`
	Strings   []StringMatch     `json:"strings,omitempty"`
}

// StringMatch represents a matched string in YARA
type StringMatch struct {
	Offset int64  `json:"offset"`
	Data   string `json:"data"`
	Name   string `json:"name"`
}

// Engine interface defines the YARA scanning engine operations
type Engine interface {
	// Scan performs YARA scanning on the specified target
	Scan(ctx context.Context, target string, rulesPath string) ([]Result, error)
	
	// ScanBytes performs YARA scanning on byte data
	ScanBytes(ctx context.Context, data []byte, rulesPath string) ([]Result, error)
	
	// CompileRule compiles YARA rules from a file
	CompileRule(ctx context.Context, rulesPath string) error
	
	// SetTimeout sets the scan timeout in seconds
	SetTimeout(seconds int)
	
	// SetThreads sets the number of threads for scanning
	SetThreads(threads int)
	
	// GetVersion returns the YARA version
	GetVersion() (string, error)
	
	// SetExtraOptions sets additional YARA options
	SetExtraOptions(options ...string)
}

// CLIEngine implements Engine using command-line yara.exe
type CLIEngine struct {
	yaraPath   string
	timeout    int
	threads    int
	extraOpts  []string
}

// NewCLIEngine creates a new CLI-based YARA engine
func NewCLIEngine(yaraPath string) *CLIEngine {
	if yaraPath == "" {
		yaraPath = "yara.exe"
	}
	return &CLIEngine{
		yaraPath:  yaraPath,
		timeout:   0, // no timeout by default
		threads:   4,
		extraOpts: []string{},
	}
}

// Scan performs YARA scanning on the specified target
func (e *CLIEngine) Scan(ctx context.Context, target string, rulesPath string) ([]Result, error) {
	args := []string{"-w"} // -w: fast scanning mode
	
	if e.timeout > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", e.timeout))
	}
	
	if e.threads > 0 {
		args = append(args, "-j", fmt.Sprintf("%d", e.threads))
	}
	
	args = append(args, e.extraOpts...)
	args = append(args, rulesPath, target)
	
	cmd := exec.CommandContext(ctx, e.yaraPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("yara scan failed: %w", err)
	}
	
	return parseYaraOutput(string(output))
}

// ScanBytes performs YARA scanning on byte data
func (e *CLIEngine) ScanBytes(ctx context.Context, data []byte, rulesPath string) ([]Result, error) {
	// Write data to temp file for scanning
	tmpFile, err := os.CreateTemp("", "yara-scan-*.dat")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	
	if _, err := tmpFile.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	
	return e.Scan(ctx, tmpFile.Name(), rulesPath)
}

// CompileRule compiles YARA rules from a file
func (e *CLIEngine) CompileRule(ctx context.Context, rulesPath string) error {
	// Use yarac to compile rules to a binary file
	args := []string{"-w", rulesPath, rulesPath + ".compiled"}
	cmd := exec.CommandContext(ctx, e.yaraPath, args...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("yara compile failed: %w", err)
	}
	
	return nil
}

// SetTimeout sets the scan timeout in seconds
func (e *CLIEngine) SetTimeout(seconds int) {
	e.timeout = seconds
}

// SetThreads sets the number of threads for scanning
func (e *CLIEngine) SetThreads(threads int) {
	e.threads = threads
}

// GetVersion returns the YARA version
func (e *CLIEngine) GetVersion() (string, error) {
	cmd := exec.Command(e.yaraPath, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// SetExtraOptions sets additional YARA options
func (e *CLIEngine) SetExtraOptions(options ...string) {
	e.extraOpts = options
}

// parseYaraOutput parses the YARA CLI output
func parseYaraOutput(output string) ([]Result, error) {
	var results []Result
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse line format: "RuleName /path/to/file"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		
		ruleName := strings.TrimSpace(parts[0])
		// target := strings.TrimSpace(parts[1]) // unused for now - could store in metadata
		
		result := Result{
			Rule:    ruleName,
			Matches: true,
			Meta:    make(map[string]string),
		}
		
		results = append(results, result)
	}
	
	return results, nil
}

// JSONResult represents the final scan result in JSON format
type JSONResult struct {
	Target    string    `json:"target"`
	Timestamp string    `json:"timestamp"`
	Results   []Result  `json:"results"`
	Error     string    `json:"error,omitempty"`
}

// MarshalJSON converts the scan result to JSON
func (r JSONResult) MarshalJSON() ([]byte, error) {
	type Alias JSONResult
	return json.Marshal(Alias(r))
}

// UnmarshalJSON parses JSON into a JSONResult
func (r *JSONResult) UnmarshalJSON(data []byte) error {
	type Alias JSONResult
	aux := &Alias{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	*r = JSONResult(*aux)
	return nil
}
