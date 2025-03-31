package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/gofrs/flock"
	"gopkg.in/yaml.v3"
)

// Version of the scanner.
const Version = "1.0.0"

// Global flags.
var (
	jsonMode  bool
	configDir string
	logPath   string
)

// outWriter is the global writer for all output.
var outWriter io.Writer = os.Stdout

// Helper logging functions.
func logInfo(format string, a ...interface{}) {
	if !jsonMode {
		fmt.Fprintf(outWriter, "[INFO] "+format+"\n", a...)
	}
}
func logDebug(format string, a ...interface{}) {
	if !jsonMode {
		fmt.Fprintf(outWriter, "[DEBUG] "+format+"\n", a...)
	}
}
func logError(format string, a ...interface{}) {
	if !jsonMode {
		fmt.Fprintf(outWriter, "[ERROR] "+format+"\n", a...)
	}
}

// PolicyInfo holds top-level policy information.
type PolicyInfo struct {
	ID          string `yaml:"id"`
	File        string `yaml:"file"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	RegexType   string `yaml:"regex_type"`
}

// Policy represents the overall YAML configuration.
type Policy struct {
	PolicyInfo   PolicyInfo        `yaml:"policy"`
	Requirements interface{}         `yaml:"requirements"`
	Variables    map[string]string `yaml:"variables"`
	Checks       []Check           `yaml:"checks"`
}

// Check holds individual check details.
type Check struct {
	ID          int                   `yaml:"id"`
	Title       string                `yaml:"title"`
	Description string                `yaml:"description"`
	Rationale   string                `yaml:"rationale"`
	Remediation string                `yaml:"remediation"`
	Compliance  []map[string][]string `yaml:"compliance"`
	Condition   string                `yaml:"condition"`
	Rules       []string              `yaml:"rules"`
}

// ScanRule stores the compiled regex along with its originating check info.
type ScanRule struct {
	CheckID    int
	CheckTitle string
	Regex      *regexp2.Regexp
	Directory  string // resolved directory for this rule
	RuleText   string // the raw rule text (optional)
}

// CheckResult is the JSON output structure for a check.
type CheckResult struct {
	Type     string      `json:"type"`      // e.g., "check"
	ID       int         `json:"id"`        // unique id for the check result
	Policy   string      `json:"policy"`    // from PolicyInfo.Name
	PolicyID string      `json:"policy_id"` // from PolicyInfo.ID
	Check    CheckOutput `json:"check"`
}

// CheckOutput holds details about the check.
type CheckOutput struct {
	ID          int               `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Rationale   string            `json:"rationale"`
	Remediation string            `json:"remediation"`
	Compliance  map[string]string `json:"compliance"`
	Rules       []string          `json:"rules"`
	Condition   string            `json:"condition"`
	Directory   string            `json:"directory"`
	Result      string            `json:"result"` // "failed" if any match was found
	Files       []string          `json:"files"`  // list of files that triggered the check
}

// Global map for accumulating check results (for JSON output).
var checkResults = make(map[int]*CheckResult)



func loadYAMLConfig(filePath string) (*Policy, error) {
	logInfo("Loading YAML configuration from %s", filePath)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var policy Policy
	err = yaml.Unmarshal(data, &policy)
	if err != nil {
		return nil, err
	}
	logInfo("YAML loaded successfully from %s", filePath)
	return &policy, nil
}

func debugVariables(variables map[string]string) {
	logDebug("Extracted Variables:")
	for key, value := range variables {
		logDebug("    %s -> %s", key, value)
	}
}

func resolveDirectory(path string, variables map[string]string) string {
	if strings.HasPrefix(path, "d:$") {
		varName := "$" + path[3:]
		logDebug("Attempting to resolve: %s", varName)
		if value, exists := variables[varName]; exists {
			logDebug("Replacing %s with %s", path, value)
			return value
		}
		logError("No matching variable found for %s in YAML variables", varName)
		return ""
	}
	return path
}

func scanDirectory(dir string, allowedExts []string, scanRules []ScanRule) {
	logInfo("Scanning directory: %s", dir)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		logError("Directory %s does not exist or is not accessible!", dir)
		return
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logError("Error accessing file %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			logInfo("Entering directory: %s", path)
			return nil
		}
		fileExt := filepath.Ext(path)
		matches := false
		for _, ext := range allowedExts {
			if fileExt == ext {
				matches = true
				break
			}
		}
		if !matches {
			return nil
		}
		logInfo("Checking file: %s", path)
		checkFile(path, scanRules)
		return nil
	})
	if err != nil {
		logError("Error scanning directory %s: %v", dir, err)
	}
}

func matchWithTimeout(r *regexp2.Regexp, content string, timeout time.Duration) (bool, error) {
	type result struct {
		match bool
		err   error
	}
	resultCh := make(chan result, 1)
	
	// Run the regex matching in a goroutine.
	go func() {
		m, err := r.MatchString(content)
		resultCh <- result{m, err}
	}()
	
	select {
	case res := <-resultCh:
		return res.match, res.err
	case <-time.After(timeout):
		return false, fmt.Errorf("regex matching timed out after %s", timeout)
	}
}

func checkFile(filePath string, scanRules []ScanRule) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		logError("Could not read file %s: %v", filePath, err)
		return
	}
	content := string(data)
	for _, rule := range scanRules {
		// Use the custom timeout wrapper.
		match, err := matchWithTimeout(rule.Regex, content, 5*time.Second)
		if err != nil {
			logError("Regex matching error on file %s: %v", filePath, err)
			continue
		}
		if match {
			if jsonMode {
				if res, exists := checkResults[rule.CheckID]; exists {
					if !contains(res.Check.Files, filePath) {
						res.Check.Files = append(res.Check.Files, filePath)
						res.Check.Result = "failed"
					}
				}
			} else {
				fmt.Fprintf(outWriter, "[ALERT] Sensitive data found in: %s (Policy ID: %d, Title: %s)\n",
					filePath, rule.CheckID, rule.CheckTitle)
			}
			break
		}
	}
}


func parseRules(policy *Policy) (map[string][]string, []ScanRule) {
	logInfo("Extracting scan rules from YAML...")
	debugVariables(policy.Variables)
	dirMap := make(map[string][]string)
	var scanRules []ScanRule

	for _, check := range policy.Checks {
		logInfo("Processing check: %s", check.Title)
		for _, rule := range check.Rules {
			parts := bytes.Split([]byte(rule), []byte("->"))
			if len(parts) < 3 {
				logError("Rule does not have 3 parts, skipping: %s", rule)
				continue
			}
			dirKey := string(bytes.TrimSpace(parts[0]))
			fileExtsRaw := string(bytes.TrimSpace(parts[1]))
			regexRaw := string(bytes.TrimSpace(parts[2]))

			dirPath := resolveDirectory(dirKey, policy.Variables)
			logDebug("Resolved directory: %s -> %s", dirKey, dirPath)
			if dirPath == "" {
				logError("Directory variable %s did not resolve! Skipping...", dirKey)
				continue
			}

			extTokens := strings.Split(fileExtsRaw, "|")
			var exts []string
			for _, token := range extTokens {
				token = strings.TrimSpace(token)
				token = strings.TrimSuffix(token, "$")
				if token != "" {
					exts = append(exts, token)
				}
			}
			if len(exts) == 0 {
				logError("No file extensions found in rule: %s", fileExtsRaw)
				continue
			}

			reMatch := regexp.MustCompile(`r:(.*)`).FindStringSubmatch(regexRaw)
			if len(reMatch) > 1 {
				rePattern := reMatch[1]
				logInfo("Compiling regex: %s", rePattern)
				compiledRegex := regexp2.MustCompile(rePattern, regexp2.RE2)
				scanRules = append(scanRules, ScanRule{
					CheckID:    check.ID,
					CheckTitle: check.Title,
					Regex:      compiledRegex,
					Directory:  dirPath,
					RuleText:   rule,
				})
			} else {
				logError("No regex found in rule: %s", regexRaw)
			}

			dirMap[dirPath] = exts
			logInfo("Successfully added directory: %s -> Extensions: %v", dirPath, exts)
		}
	}
	logInfo("Rule extraction complete.")
	return dirMap, scanRules
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	flag.BoolVar(&jsonMode, "json", false, "Output results in JSON format")
	flag.StringVar(&configDir, "configdir", "", "Directory containing ruleset YAML files (files ending with .yml) (required)")
	flag.StringVar(&logPath, "log", "", "Output logfile path")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Atomicorp Compliance scanner, v(%s)\n", Version)
		fmt.Fprintf(os.Stderr, "Copyright Atomicorp, 2025\n\n")
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if configDir == "" {
		flag.Usage()
		log.Fatalf("Missing required flag: --configdir")
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer f.Close()
		outWriter = f
	}

	// Locking to prevent multiple instances
	lockFilePath := filepath.Join(os.TempDir(), "compliance-scanner.lock")
	fileLock := flock.New(lockFilePath)
	locked, err := fileLock.TryLock()
	if err != nil {
		log.Fatalf("Failed to acquire lock: %v", err)
	}
	if !locked {
		log.Fatalf("Another instance is already running. Exiting.")
	}
	defer func() {
		err := fileLock.Unlock()
		if err != nil {
			logError("Failed to release lock: %v", err)
		}
	}()

	globPattern := filepath.Join(configDir, "*.yml")
	files, err := filepath.Glob(globPattern)
	if err != nil {
		log.Fatalf("Error globbing configdir: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("No YAML files found in configdir: %s", configDir)
	}
	aggregated := Policy{
		Variables: make(map[string]string),
	}
	for _, file := range files {
		p, err := loadYAMLConfig(file)
		if err != nil {
			logError("Invalid YAML file %s: %v", file, err)
			continue
		}
		for k, v := range p.Variables {
			aggregated.Variables[k] = v
		}
		aggregated.Checks = append(aggregated.Checks, p.Checks...)
	}
	if len(aggregated.Checks) == 0 {
		log.Fatalf("No valid YAML configuration found in configdir: %s", configDir)
	}
	policy := &aggregated
	for _, c := range policy.Checks {
		if jsonMode {
			comp := make(map[string]string)
			for _, compMap := range c.Compliance {
				for k, arr := range compMap {
					comp[k] = strings.Join(arr, ",")
				}
			}
			dir := ""
			checkResults[c.ID] = &CheckResult{
				Type:     "check",
				ID:       c.ID,
				Policy:   policy.PolicyInfo.Name,
				PolicyID: policy.PolicyInfo.ID,
				Check: CheckOutput{
					ID:          c.ID,
					Title:       c.Title,
					Description: c.Description,
					Rationale:   c.Rationale,
					Remediation: c.Remediation,
					Compliance:  comp,
					Rules:       c.Rules,
					Condition:   c.Condition,
					Directory:   dir,
					Result:      "passed",
					Files:       []string{},
				},
			}
		}
	}
	dirMap, scanRules := parseRules(policy)
	logInfo("Extracted directories for scanning:")
	if len(dirMap) == 0 {
		logError("No directories were resolved! Please check your YAML file.")
	} else {
		for dir, exts := range dirMap {
			logInfo("    [DIR] %s -> Extensions: %v", dir, exts)
		}
	}
	for dir, exts := range dirMap {
		logInfo("Scanning resolved directory: %s", dir)
		scanDirectory(dir, exts, scanRules)
	}
	if jsonMode {
		for _, res := range checkResults {
			if res.Check.Result == "failed" {
				jsonOut, err := json.Marshal(res)
				if err != nil {
					log.Fatalf("Failed to marshal JSON: %v", err)
				}
				fmt.Fprintln(outWriter, string(jsonOut))
			}
		}
	} else {
		logInfo("Scan completed.")
	}
}