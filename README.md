# AWS Credential Scanner

An advanced security tool for detecting exposed AWS credentials in web applications, websites, and configuration files.

## Features

- **Advanced Credential Detection**: Uses multiple pattern recognition techniques to identify AWS keys.
- **Smart Contextual Analysis**: Reduces false positives through semantic context analysis.
- **Comprehensive Content Exploration**: Recursively crawls websites, explores hidden endpoints, and analyzes multiple content types.
- **Multi-Format Support**: Detects credentials in HTML, JavaScript, JSON, YAML, Base64-encoded content, and URL-encoded strings.
- **Security Scoring**: Provides confidence scores for each finding based on context analysis.
- **Telegram Integration**: Optional real-time notifications for discovered credentials.
- **Detailed Reporting**: Comprehensive output in both human-readable text and machine-parseable JSON formats.

## Requirements

- Python 3.7+
- Required Python packages:
  - `aiohttp`: For asynchronous HTTP requests
  - `beautifulsoup4`: For HTML parsing
  - `pyyaml`: For YAML parsing
  - `telebot`: For Telegram notifications (optional)
  - `boto3`: For AWS key validation (optional)

## Installation

1. Clone this repository or download the script
2. Install required dependencies:

```bash
pip install aiohttp beautifulsoup4 pyyaml pyTelegramBotAPI boto3
```

## Usage

### Basic Usage

```bash
python aws_scanner.py -f targets.txt
```

### Command Line Arguments

- `-f, --file`: File containing targets (one per line)
- `-t, --timeout`: Request timeout in seconds
- `-d, --depth`: Maximum scan depth per target
- `-o, --output`: Output file path
- `--format`: Output format (text or json)
- `-v, --verbose`: Enable verbose logging
- `--config`: Configure Telegram notifications

### Interactive Mode

If you run the script without specifying a targets file, it will enter interactive mode:

```bash
python aws_scanner.py
```

## Target File Format

Create a text file with one target per line. Targets can be:
- URLs (e.g., `https://example.com`)
- Domain names (e.g., `example.com`)
- IP addresses (e.g., `192.168.1.1`)

Comments can be added using `#`:

```
# Production servers
example.com
https://api.example.com

# Development
dev.example.com
```

## Configuration

Run the script with the `--config` flag to set up Telegram notifications and other options:

```bash
python aws_scanner.py --config
```

Configuration is saved in `~/.aws_scanner/config.json`.

## Security Considerations

This tool is intended for security professionals to audit their own systems or systems they have permission to test. Unauthorized scanning of systems may violate laws and terms of service.

## Responsible Disclosure

If you discover AWS credentials using this tool:

1. Do not use or attempt to use the credentials
2. Immediately notify the affected organization through their security contact or responsible disclosure program
3. Securely delete any discovered credentials after reporting

## License

This project is licensed under the MIT License - see the LICENSE file for details.