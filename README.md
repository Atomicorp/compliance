# Atomicorp Compliance Scanner

Atomicorp Compliance Scanner is a Go-based tool that scans user directories for sensitive credentials according to configurable YAML rulesets. It is designed to integrate with security monitoring systems such as OSSEC, and supports both plain-text and JSON output modes.

## Features

- **Configurable Rules:** Load rulesets from YAML files (using globbing) from a specified configuration directory.
- **Output Modes:** Display results as plain text or JSON (one JSON object per check) using the `--json` flag.
- **Logging:** Option to write output to a log file using the `--log` flag (appends output).
- **Cross-Platform Build:** Easily cross-compile for Linux, macOS, and Windows.

## Prerequisites

- **Go:** Ensure you have Go installed (version 1.17 or later is recommended).

## Building the Scanner

make

this will create binaries for linux, mac, and windows


## Usage

The Atomicorp Compliance Scanner is run from the command line. It requires you to specify a directory containing YAML ruleset files using the `--configdir` flag. You can also choose to output results in JSON format and/or direct the output to a log file.

### Command-Line Flags

- **`--configdir <path>` (Required):**  
  Specifies the directory containing the YAML ruleset files. The scanner will search for all files ending with `.yml` in this directory.

- **`--json`:**  
  Outputs the results in JSON format. In this mode, log messages are suppressed and each check result is printed as a single JSON line.

- **`--log <path>`:**  
  Writes all output (plain-text or JSON) to the specified log file. The output is appended to the file rather than overwriting it.

### Examples

#### Plain-Text Mode

Run the scanner using a configuration directory located at `/etc/compliance-configs`:

```bash
./compliance-scanner --configdir /etc/compliance-configs
