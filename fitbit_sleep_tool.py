#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sleep Data Tool

Python 3.10+

FEATURES:
- GUI with ttkbootstrap
- Theme support
- Secure OAuth2 flow with PKCE
- Multi-account encrypted token storage with OS keychain
- Fetches sleep data and exports to CSV
- Thread-safe operations with progress indicators
- Rate limiting with retry logic
- Input validation

Expected .env keys:
FITBIT_CLIENT_ID=your_fitbit_client_id
FITBIT_REDIRECT_URI=http://localhost:8080/

This tool is not affiliated with Fitbit. Use at your own risk. Fitbit is a trademark of Fitbit, Inc. 
This tool is provided "as is" without warranty of any kind. This tool is licensed under the agpl-3.0 license. 
In terms of privacy, this tool only stores OAuth tokens locally in encrypted form and does not transmit any personal data to third parties.
"""

import os
import json
import logging
import datetime
import threading
import webbrowser
import time
import secrets
import hashlib
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from typing import Any, Callable, Dict, List, Optional

import requests
import pandas as pd
from pydantic import BaseModel, HttpUrl, ValidationError
from requests_oauthlib import OAuth2Session

try:
    import ttkbootstrap as ttk
    from ttkbootstrap.constants import *
    from ttkbootstrap.dialogs import Messagebox
    from ttkbootstrap.widgets import ToastNotification
except ImportError:
    raise ImportError("Please install ttkbootstrap: pip install ttkbootstrap")

from tkinter import filedialog

import sys
from tkinter import messagebox as tk_messagebox

# Patch ttkbootstrap Messagebox on macOS
if sys.platform == "darwin":
    class FixedMessagebox:
        @staticmethod
        def show_info(message, title="Info", parent=None):
            return tk_messagebox.showinfo(title, message, parent=parent)

        @staticmethod
        def show_error(message, title="Error", parent=None):
            return tk_messagebox.showerror(title, message, parent=parent)

        @staticmethod
        def show_warning(message, title="Warning", parent=None):
            return tk_messagebox.showwarning(title, message, parent=parent)

        @staticmethod
        def ok(message, title="Info", parent=None):
            return tk_messagebox.showinfo(title, message, parent=parent)

    Messagebox = FixedMessagebox


try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    raise ImportError("Please install cryptography: pip install cryptography")

try:
    import keyring
    from keyring.errors import KeyringError
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    KeyringError = Exception

# ═══════════════════════════════════════════════════════════
# Logging and Environment
# ═══════════════════════════════════════════════════════════

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

try:
    from dotenv import load_dotenv
    load_dotenv()
    logging.info("Loaded configuration from .env file")
except ImportError:
    logging.warning("python-dotenv not installed. Install with: pip install python-dotenv")
    logging.info("Falling back to system environment variables")

# ═══════════════════════════════════════════════════════════
# Constants and Config
# ═══════════════════════════════════════════════════════════

# OAuth Configuration
DEVELOPER_CLIENT_ID = os.getenv("FITBIT_CLIENT_ID", "")
DEVELOPER_REDIRECT_URI = os.getenv("FITBIT_REDIRECT_URI", "http://localhost:8080/")

# Network Timeouts (seconds)
OAUTH_PORT = 8080
OAUTH_TIMEOUT = 120
TOKEN_REQUEST_TIMEOUT = 30
API_REQUEST_TIMEOUT = 20
SERVER_SHUTDOWN_TIMEOUT = 1.0

# Fitbit API Endpoints
FITBIT_AUTH_URL = "https://www.fitbit.com/oauth2/authorize"
FITBIT_TOKEN_URL = "https://api.fitbit.com/oauth2/token"
FITBIT_PROFILE_URL = "https://api.fitbit.com/1/user/-/profile.json"
FITBIT_SLEEP_URL = "https://api.fitbit.com/1.2/user/-/sleep/date/{date}.json"

# Storage
TOKEN_DIR = "fitbit_tokens"
ENCRYPTION_KEY_FILE = "fitbit_key.key"
KEYRING_SERVICE_NAME = "FitbitSleepTool"
KEYRING_KEY_USERNAME = "encryption_key"

# Rate Limiting
EXP_SKEW_SECONDS = 300
MAX_RATE_LIMIT_RETRIES = 3
DEFAULT_RETRY_AFTER = 60

# Keychain status logging
if KEYRING_AVAILABLE:
    try:
        keyring_backend = keyring.get_keyring()
        logging.info(f"✓ OS Keychain available: {keyring_backend.__class__.__name__}")
    except Exception as e:
        logging.warning(f"Keyring library available but backend failed: {e}")
        KEYRING_AVAILABLE = False
else:
    logging.warning("⚠️  Keyring library not installed. Using file-based key storage.")
    logging.info("For better security, install: pip install keyring")

'''
logging.warning(
    "SECURITY: This is a PUBLIC CLIENT. Do not use client_secret in production. "
    "Register as 'Public Client' in Fitbit Developer Console."
)
'''

# ═══════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════

class FitbitConfig(BaseModel):
    """Configuration for Fitbit OAuth (PUBLIC CLIENT - no secret)"""
    client_id: str
    redirect_uri: HttpUrl

class Token(BaseModel):
    """OAuth token with automatic expiration checking"""
    access_token: str
    refresh_token: str
    expires_at: float
    token_type: str = "Bearer"

    def is_expired(self) -> bool:
        """Check if token is expired with safety buffer"""
        return datetime.datetime.now().timestamp() >= self.expires_at

    def copy(self) -> "Token":
        """Create a deep copy of the token"""
        return Token.model_validate(self.model_dump())

class SleepRecord(BaseModel):
    """Sleep data record from Fitbit API"""
    account: str
    date: str
    startTime: str
    endTime: str
    REM: int
    Light: int
    Deep: int
    SOL: int
    MinutesAwake: int
    WASO: float
    TIB: int
    sleepType: str
    sourceNote: str

# ═══════════════════════════════════════════════════════════
# Secure Token Storage with OS Keychain
# ═══════════════════════════════════════════════════════════

class SecureStorage:
    """Handles encrypted token storage with OS-level keychain support."""

    def __init__(self, key_path: str = ENCRYPTION_KEY_FILE, use_keyring: bool = True):
        self.key_path = key_path
        self.use_keyring = use_keyring and KEYRING_AVAILABLE
        self.service_name = KEYRING_SERVICE_NAME
        self.key_username = KEYRING_KEY_USERNAME
        
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)
        
        if self.use_keyring:
            logging.info("✓ Using OS keychain for encryption key storage")
        else:
            logging.warning("⚠️  Using file-based encryption key storage (less secure)")

    def _load_or_create_key(self) -> bytes:
        """Load existing encryption key or create new one, preferring OS keychain"""
        if self.use_keyring:
            key = self._load_from_keyring()
            if key:
                logging.info("Loaded encryption key from OS keychain")
                if os.path.exists(self.key_path):
                    self._migrate_key_to_keyring()
                return key
        
        if os.path.exists(self.key_path):
            key = self._load_from_file()
            if key:
                if self.use_keyring:
                    if self._save_to_keyring(key):
                        logging.info("✓ Migrated encryption key from file to OS keychain")
                        try:
                            os.remove(self.key_path)
                            logging.info("Removed old key file after migration")
                        except Exception as e:
                            logging.warning(f"Could not remove old key file: {e}")
                return key
        
        return self._create_new_key()

    def _load_from_keyring(self) -> Optional[bytes]:
        """Load encryption key from OS keychain"""
        if not self.use_keyring:
            return None
        try:
            key_str = keyring.get_password(self.service_name, self.key_username)
            if key_str:
                return key_str.encode('utf-8')
            return None
        except KeyringError as e:
            logging.error(f"Failed to load key from keychain: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error loading from keychain: {e}")
            return None

    def _save_to_keyring(self, key: bytes) -> bool:
        """Save encryption key to OS keychain"""
        if not self.use_keyring:
            return False
        try:
            keyring.set_password(self.service_name, self.key_username, key.decode('utf-8'))
            logging.debug("Encryption key saved to OS keychain")
            return True
        except KeyringError as e:
            logging.error(f"Failed to save key to keychain: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error saving to keychain: {e}")
            return False

    def _load_from_file(self) -> Optional[bytes]:
        """Load encryption key from file"""
        try:
            with open(self.key_path, "rb") as f:
                key = f.read()
            logging.debug("Loaded encryption key from file")
            return key
        except Exception as e:
            logging.error(f"Failed to load key from file: {e}")
            return None

    def _save_to_file(self, key: bytes) -> bool:
        """Save encryption key to file with secure permissions"""
        try:
            with open(self.key_path, "wb") as f:
                f.write(key)
            try:
                os.chmod(self.key_path, 0o600)
                logging.debug("Encryption key saved to file with 0o600 permissions")
            except Exception as e:
                logging.warning(f"Could not set file permissions: {e}")
            return True
        except Exception as e:
            logging.error(f"Failed to save key to file: {e}")
            return False

    def _create_new_key(self) -> bytes:
        """Create new encryption key and save it"""
        key = Fernet.generate_key()
        if self.use_keyring:
            if self._save_to_keyring(key):
                logging.info("✓ New encryption key generated and saved to OS keychain")
                return key
            else:
                logging.warning("Failed to save to keychain, falling back to file")
        if self._save_to_file(key):
            logging.warning("⚠️  New encryption key generated and saved to FILE (less secure)")
        else:
            logging.error("Failed to save encryption key!")
        return key

    def _migrate_key_to_keyring(self):
        """Migrate existing file-based key to OS keychain"""
        if not self.use_keyring or not os.path.exists(self.key_path):
            return
        try:
            with open(self.key_path, "rb") as f:
                key = f.read()
            if self._save_to_keyring(key):
                loaded = self._load_from_keyring()
                if loaded and loaded == key:
                    try:
                        os.remove(self.key_path)
                        logging.info("✓ Successfully migrated key from file to OS keychain")
                    except Exception as e:
                        logging.warning(f"Migration successful but could not remove file: {e}")
                else:
                    logging.warning("Keychain save verification failed, keeping file backup")
        except Exception as e:
            logging.error(f"Key migration failed: {e}")

    def save_encrypted(self, path: str, data: str) -> None:
        """Encrypt and save data to file"""
        enc = self.fernet.encrypt(data.encode("utf-8"))
        with open(path, "wb") as f:
            f.write(enc)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        logging.info("Token encrypted and saved: %s", path)

    def load_encrypted(self, path: str) -> Optional[str]:
        """Load and decrypt data from file"""
        try:
            with open(path, "rb") as f:
                enc = f.read()
            return self.fernet.decrypt(enc).decode("utf-8")
        except InvalidToken:
            logging.error("Invalid encryption token for %s - file may be corrupted", path)
            return None
        except FileNotFoundError:
            logging.error("Token file not found: %s", path)
            return None
        except Exception as e:
            logging.error("Unexpected error loading %s: %s", path, e)
            return None

    @staticmethod
    def hash_account_name(name: str) -> str:
        """Create a hashed filename for security"""
        return hashlib.sha256(name.encode()).hexdigest()[:16]

    def get_storage_info(self) -> Dict[str, Any]:
        """Get information about current storage method"""
        return {
            "keyring_available": KEYRING_AVAILABLE,
            "using_keyring": self.use_keyring,
            "keyring_backend": keyring.get_keyring().__class__.__name__ if KEYRING_AVAILABLE else None,
            "file_exists": os.path.exists(self.key_path),
            "storage_method": "OS Keychain" if self.use_keyring else "File-based"
        }

# ═══════════════════════════════════════════════════════════
# OAuth Callback Server (PKCE)
# ═══════════════════════════════════════════════════════════

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles OAuth callback from Fitbit"""

    def log_message(self, format, *args):
        """Suppress default HTTP logging"""
        pass

    def do_GET(self):
        """Handle GET request from OAuth callback"""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if "state" in params:
            received_state = params["state"][0]
            if received_state != self.server.expected_state:
                self._send_html(
                    "<h2>Security Error</h2><p>State mismatch detected. Possible CSRF attack.</p>", 
                    400
                )
                self.server.auth_success = False
                self.server.auth_error = "State mismatch - possible CSRF attack"
                logging.error("CSRF attack detected: state mismatch")
                return
        
        if "code" in params:
            self.server.auth_code = params["code"][0]
            self.server.auth_success = True
            self._send_html(
                "<h2>✓ Authorization Successful!</h2>"
                "<p>You may close this window and return to the application.</p>"
            )
            logging.info("OAuth authorization successful")
        elif "error" in params:
            err = params.get("error_description", ["Unknown error"])[0]
            self.server.auth_error = err
            self._send_html(f"<h2>Authorization Error</h2><p>{err}</p>", 400)
            logging.error(f"OAuth error: {err}")

    def _send_html(self, content: str, code: int = 200):
        """Send HTML response"""
        self.send_response(code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = f"""
        <html>
        <head>
            <title>Fitbit OAuth</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                h2 {{ color: #333; }}
            </style>
        </head>
        <body>{content}</body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

class OAuthCallbackServer:
    """Temporary HTTP server to handle OAuth callback"""

    def __init__(self, port: int = OAUTH_PORT):
        self.port = port
        self.server = None
        self.thread = None

    def start(self, expected_state: str):
        """Start the callback server"""
        self.server = HTTPServer(("localhost", self.port), OAuthCallbackHandler)
        self.server.auth_code = None
        self.server.auth_success = False
        self.server.auth_error = None
        self.server.expected_state = expected_state
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logging.info(f"OAuth callback server started on port {self.port}")

    def _run(self):
        """Run server until callback received"""
        while not self.server.auth_success and self.server.auth_error is None:
            self.server.handle_request()

    def wait_for_code(self, timeout: int = OAUTH_TIMEOUT) -> str:
        """Wait for OAuth code with timeout"""
        start = time.time()
        while time.time() - start < timeout:
            if self.server.auth_success:
                return self.server.auth_code
            if self.server.auth_error:
                raise ValueError(self.server.auth_error)
            time.sleep(0.1)
        raise TimeoutError(f"Timeout waiting for OAuth callback after {timeout}s")

    def stop(self):
        """Stop and cleanup the server"""
        if self.server:
            try:
                self.server.server_close()
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=SERVER_SHUTDOWN_TIMEOUT)
                logging.info("OAuth callback server stopped")
            except Exception as e:
                logging.warning(f"Error stopping server: {e}")

# ═══════════════════════════════════════════════════════════
# Fitbit API Client
# ═══════════════════════════════════════════════════════════

def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE verifier and challenge for OAuth"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode("utf-8").rstrip("=")
    logging.debug("PKCE pair generated")
    return verifier, challenge

def token_dict_to_model(token_dict: Dict[str, Any]) -> Token:
    """Convert token dictionary from API to Token model"""
    now = datetime.datetime.now().timestamp()
    
    if "expires_at" in token_dict:
        ea = float(token_dict["expires_at"])
    elif "expires_in" in token_dict:
        ea = now + float(token_dict["expires_in"]) - EXP_SKEW_SECONDS
    else:
        ea = now + 6 * 3600 - EXP_SKEW_SECONDS

    return Token(
        access_token=token_dict["access_token"],
        refresh_token=token_dict["refresh_token"],
        expires_at=ea,
        token_type=token_dict.get("token_type", "Bearer"),
    )

def validate_date_format(date_str: str) -> bool:
    """Validate date is in YYYY-MM-DD format"""
    try:
        datetime.datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False

class FitbitClient:
    """Client for interacting with Fitbit API (PUBLIC CLIENT)"""

    def __init__(
        self, 
        config: FitbitConfig, 
        token: Token, 
        save_cb: Optional[Callable[[Token], None]] = None
    ):
        self.config = config
        self.token = token
        self.save_cb = save_cb
        self._refresh_lock = threading.Lock()

    def _headers(self) -> Dict[str, str]:
        """Get authorization headers"""
        return {"Authorization": f"Bearer {self.token.access_token}"}

    def refresh_token(self) -> Optional[Token]:
        """Refresh access token using refresh token (PUBLIC CLIENT - no secret)"""
        with self._refresh_lock:
            if not self.token.is_expired():
                logging.debug("Token still valid after lock acquisition")
                return self.token
            
            logging.info("Refreshing access token...")
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self.token.refresh_token,
                "client_id": self.config.client_id,
            }
            
            try:
                resp = requests.post(
                    FITBIT_TOKEN_URL, 
                    headers=headers, 
                    data=data, 
                    timeout=TOKEN_REQUEST_TIMEOUT
                )
                resp.raise_for_status()
                
                new_tok = token_dict_to_model(resp.json())
                self.token = new_tok
                
                if self.save_cb:
                    self.save_cb(new_tok)
                
                logging.info("Token refreshed successfully")
                return new_tok
                
            except requests.exceptions.HTTPError as e:
                logging.error(f"HTTP error during token refresh: {e.response.status_code} - {e.response.text}")
                return None
            except requests.exceptions.RequestException as e:
                logging.error(f"Network error during token refresh: {e}")
                return None
            except Exception as e:
                logging.error(f"Unexpected error during token refresh: {e}")
                return None

    def ensure_valid(self) -> Token:
        """Ensure token is valid, refresh if needed"""
        if self.token.is_expired():
            refreshed = self.refresh_token()
            if not refreshed:
                raise RuntimeError("Failed to refresh expired token")
        return self.token

    def get_profile_name(self) -> str:
        """Get user profile display name"""
        try:
            self.ensure_valid()
        except RuntimeError as e:
            logging.error(f"Token validation failed: {e}")
            return "Unknown"
        
        try:
            resp = requests.get(
                FITBIT_PROFILE_URL, 
                headers=self._headers(), 
                timeout=API_REQUEST_TIMEOUT
            )
            
            if resp.status_code == 429:
                retry_after = resp.headers.get('Retry-After', DEFAULT_RETRY_AFTER)
                logging.warning(f"Rate limited on profile fetch. Retry after {retry_after} seconds")
                return "Unknown"
            
            resp.raise_for_status()
            return resp.json().get("user", {}).get("displayName", "Unknown")
            
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error fetching profile: {e.response.status_code}")
            return "Unknown"
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error fetching profile: {e}")
            return "Unknown"
        except (KeyError, ValueError) as e:
            logging.error(f"Error parsing profile data: {e}")
            return "Unknown"

    def get_sleep_data(self, date: str, retry_count: int = 0) -> Optional[SleepRecord]:
        """Fetch sleep data for a specific date with rate limit retry logic"""
        if not validate_date_format(date):
            logging.error(f"Invalid date format: {date}. Expected YYYY-MM-DD")
            return None
        
        try:
            self.ensure_valid()
        except RuntimeError as e:
            logging.error(f"Token validation failed: {e}")
            return None
        
        try:
            resp = requests.get(
                FITBIT_SLEEP_URL.format(date=date), 
                headers=self._headers(), 
                timeout=API_REQUEST_TIMEOUT
            )
            
            if resp.status_code == 429:
                if retry_count < MAX_RATE_LIMIT_RETRIES:
                    retry_after = int(resp.headers.get('Retry-After', DEFAULT_RETRY_AFTER))
                    logging.warning(
                        f"Rate limited. Waiting {retry_after}s before retry "
                        f"(attempt {retry_count + 1}/{MAX_RATE_LIMIT_RETRIES})"
                    )
                    time.sleep(retry_after)
                    return self.get_sleep_data(date, retry_count + 1)
                else:
                    logging.error("Max rate limit retries exceeded")
                    return None
            
            if not resp.ok:
                logging.error(f"Sleep data error ({resp.status_code}): {resp.text}")
                return None
            
            json_data = resp.json()
            
            if "meta" in json_data and json_data.get("meta", {}).get("state") == "pending":
                retry_duration = json_data.get("meta", {}).get("retryDuration", 3000) / 1000
                logging.info(f"Sleep log pending, suggested retry in {retry_duration}s")
                return None
            
            data = json_data.get("sleep", [])
            if not data:
                logging.info(f"No sleep data found for {date}")
                return None
            
            s = max(data, key=lambda x: x.get("duration", 0))
            levels = s.get("levels", {})
            summary = levels.get("summary", {})
            sleep_type = s.get("type", "stages")
            
            if sleep_type == "stages":
                REM = int(summary.get("rem", {}).get("minutes", 0))
                Light = int(summary.get("light", {}).get("minutes", 0))
                Deep = int(summary.get("deep", {}).get("minutes", 0))
            else:
                REM = 0
                Light = int(summary.get("asleep", {}).get("minutes", 0))
                Deep = 0
            
            waso = sum(
                i.get("seconds", 0) / 60.0
                for i in levels.get("data", []) 
                if i.get("level") == "wake"
            )
            
            return SleepRecord(
                account="",
                date=s["endTime"][:10],
                startTime=s["startTime"],
                endTime=s["endTime"],
                REM=REM,
                Light=Light,
                Deep=Deep,
                SOL=int(s.get("minutesToFallAsleep", 0)),
                MinutesAwake=int(s.get("minutesAwake", 0)),
                WASO=round(waso, 1),
                TIB=int(s.get("timeInBed", 0)),
                sleepType=sleep_type,
                sourceNote="main sleep",
            )
            
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error fetching sleep data: {e.response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error fetching sleep data: {e}")
            return None
        except (KeyError, ValueError, TypeError) as e:
            logging.error(f"Error parsing sleep data: {e}")
            return None

# ═══════════════════════════════════════════════════════════
# Modern GUI Application with ttkbootstrap
# ═══════════════════════════════════════════════════════════

class FitbitApp:
    """Main GUI application with modern ttkbootstrap interface"""

    def __init__(self, master: ttk.Window):
        self.master = master
        master.title("🌙 Sleep Data Tool")
        master.geometry("1000x750")
        
        # Set app icon if available
        try:
            master.iconbitmap("icon.ico")
        except:
            pass
        
        self.storage = SecureStorage()
        self.accounts: Dict[str, Token] = {}
        self.sleep_data: Dict[str, List[SleepRecord]] = {}
        
        # Thread-safety locks
        self._data_lock = threading.Lock()
        self._accounts_lock = threading.Lock()
        
        # Progress tracking
        self.is_fetching = False
        
        os.makedirs(TOKEN_DIR, exist_ok=True)
        self._build_ui()
        self._load_saved_accounts()

    def _build_ui(self):
        """Build the modern user interface"""
        # Configure style
        style = ttk.Style()
        
        # Main container with padding
        main_container = ttk.Frame(self.master, padding=20)
        main_container.pack(fill=BOTH, expand=YES)
        
        # ────────────────────────────────────────────────────────────
        # HEADER SECTION
        # ────────────────────────────────────────────────────────────
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=X, pady=(0, 20))
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="🌙 Fitbit Sleep Data Tool",
            font=("Helvetica", 20, "bold"),
            bootstyle="inverse-primary"
        )
        title_label.pack(side=LEFT)
        
        # Security status indicator
        storage_info = self.storage.get_storage_info()
        if storage_info["using_keyring"]:
            security_text = f"🔒 Secure: {storage_info['keyring_backend']}"
            security_style = "success"
        else:
            security_text = "⚠️  File-based storage"
            security_style = "warning"
        
        security_label = ttk.Label(
            header_frame,
            text=security_text,
            font=("Helvetica", 9),
            bootstyle=security_style
        )
        security_label.pack(side=RIGHT, padx=(10, 0))
        
        # Info button
        info_btn = ttk.Button(
            header_frame,
            text="ℹ️",
            command=self.show_storage_info,
            bootstyle="info-link",
            width=3
        )
        info_btn.pack(side=RIGHT)
        
        # Subtitle
        subtitle_label = ttk.Label(
            header_frame,
            text="OAuth 2.0 with PKCE • Multi-Account • Encrypted Storage",
            font=("Helvetica", 9),
            bootstyle="secondary"
        )
        subtitle_label.pack(side=LEFT, padx=(15, 0))
        
        # ────────────────────────────────────────────────────────────
        # ACCOUNT SECTION
        # ────────────────────────────────────────────────────────────
        account_frame = ttk.Labelframe(
            main_container,
            text="👤 Account Management",
            padding=15,
            bootstyle="primary"
        )
        account_frame.pack(fill=X, pady=(0, 15))
        
        # Account selection row
        account_select_frame = ttk.Frame(account_frame)
        account_select_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(
            account_select_frame,
            text="Select Account:",
            font=("Helvetica", 10, "bold")
        ).pack(side=LEFT, padx=(0, 10))
        
        self.account_box = ttk.Combobox(
            account_select_frame,
            state="readonly",
            width=40,
            font=("Helvetica", 10)
        )
        self.account_box.pack(side=LEFT, fill=X, expand=YES)
        
        # Action buttons row
        action_btn_frame = ttk.Frame(account_frame)
        action_btn_frame.pack(fill=X)
        
        add_btn = ttk.Button(
            action_btn_frame,
            text="➕ Add Account",
            command=self.add_account,
            bootstyle="success-outline",
            width=18
        )
        add_btn.pack(side=LEFT, padx=(0, 5))
        
        load_btn = ttk.Button(
            action_btn_frame,
            text="🔄 Load Account",
            command=self.load_account,
            bootstyle="info-outline",
            width=18
        )
        load_btn.pack(side=LEFT, padx=5)
        
        # ────────────────────────────────────────────────────────────
        # DATA FETCH SECTION
        # ────────────────────────────────────────────────────────────
        fetch_frame = ttk.Labelframe(
            main_container,
            text="📊 Fetch Sleep Data",
            padding=15,
            bootstyle="info"
        )
        fetch_frame.pack(fill=X, pady=(0, 15))
        
        # Date input row
        date_frame = ttk.Frame(fetch_frame)
        date_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(
            date_frame,
            text="📅 Date (YYYY-MM-DD):",
            font=("Helvetica", 10, "bold")
        ).pack(side=LEFT, padx=(0, 10))
        
        self.date_entry = ttk.Entry(
            date_frame,
            font=("Helvetica", 10),
            width=20
        )
        default_date = str(datetime.date.today() - datetime.timedelta(days=1))
        self.date_entry.insert(0, default_date)
        self.date_entry.pack(side=LEFT)
        
        ttk.Label(
            date_frame,
            text="(Yesterday's sleep)",
            font=("Helvetica", 9),
            bootstyle="secondary"
        ).pack(side=LEFT, padx=(10, 0))
        
        # Fetch button with progress bar
        fetch_btn_frame = ttk.Frame(fetch_frame)
        fetch_btn_frame.pack(fill=X)
        
        self.fetch_btn = ttk.Button(
            fetch_btn_frame,
            text="📊 Fetch Sleep Data",
            command=self.fetch_data,
            bootstyle="primary",
            width=25
        )
        self.fetch_btn.pack(side=LEFT)
        
        self.progress_bar = ttk.Progressbar(
            fetch_btn_frame,
            mode="indeterminate",
            bootstyle="primary-striped"
        )
        self.progress_bar.pack(side=LEFT, fill=X, expand=YES, padx=(10, 0))
        
        # ────────────────────────────────────────────────────────────
        # DATA TABLE SECTION
        # ────────────────────────────────────────────────────────────
        table_frame = ttk.Labelframe(
            main_container,
            text="💤 Sleep Data Records",
            padding=15,
            bootstyle="secondary"
        )
        table_frame.pack(fill=BOTH, expand=YES, pady=(0, 15))
        
        # Create Treeview with modern styling
        cols = [
            "account", "date", "startTime", "endTime", "REM", "Light",
            "Deep", "SOL", "MinutesAwake", "WASO", "TIB", "sleepType"
        ]
        
        tree_container = ttk.Frame(table_frame)
        tree_container.pack(fill=BOTH, expand=YES)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical")
        vsb.pack(side=RIGHT, fill=Y)
        
        hsb = ttk.Scrollbar(tree_container, orient="horizontal")
        hsb.pack(side=BOTTOM, fill=X)
        
        self.tree = ttk.Treeview(
            tree_container,
            columns=cols,
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            bootstyle="primary"
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Configure columns
        column_widths = {
            "account": 100,
            "date": 90,
            "startTime": 130,
            "endTime": 130,
            "REM": 60,
            "Light": 60,
            "Deep": 60,
            "SOL": 50,
            "MinutesAwake": 90,
            "WASO": 60,
            "TIB": 60,
            "sleepType": 80
        }
        
        for col in cols:
            self.tree.heading(col, text=col, anchor=CENTER)
            self.tree.column(
                col,
                anchor=CENTER,
                width=column_widths.get(col, 80),
                minwidth=50
            )
        
        self.tree.pack(fill=BOTH, expand=YES)
        
        # ────────────────────────────────────────────────────────────
        # EXPORT SECTION
        # ────────────────────────────────────────────────────────────
        export_frame = ttk.Frame(main_container)
        export_frame.pack(fill=X)
        
        export_btn = ttk.Button(
            export_frame,
            text="💾 Export to CSV",
            command=self.export_csv,
            bootstyle="success",
            width=20
        )
        export_btn.pack(side=LEFT)
        
        # Status label
        self.status_label = ttk.Label(
            export_frame,
            text="Ready",
            font=("Helvetica", 10),
            bootstyle="secondary"
        )
        self.status_label.pack(side=LEFT, padx=(15, 0))

    def set_status(self, msg: str, style: str = "secondary"):
        """Update status label with color (thread-safe)"""
        def update():
            self.status_label.config(text=msg, bootstyle=style)
        self.master.after(0, update)

    def show_toast(self, title: str, message: str, duration: int = 3000, bootstyle: str = "info"):
        """Show a modern toast notification"""
        try:
            toast = ToastNotification(
                title=title,
                message=message,
                duration=duration,
                bootstyle=bootstyle
            )
            toast.show_toast()
        except Exception as e:
            logging.debug(f"Toast notification failed: {e}")

    # ────────────────────────────────────────────────────────────
    # Account Management
    # ────────────────────────────────────────────────────────────

    def _get_config(self) -> Optional[FitbitConfig]:
        """Get Fitbit configuration from environment (PUBLIC CLIENT)"""
        if not (DEVELOPER_CLIENT_ID and DEVELOPER_REDIRECT_URI):
            Messagebox.show_error(
                "Please configure your .env file with:\n"
                "FITBIT_CLIENT_ID\n"
                "FITBIT_REDIRECT_URI\n\n"
                "Note: CLIENT_SECRET is NOT needed for public clients.",
                title="Missing Configuration",
                parent=self.master
            )
            return None
        
        try:
            return FitbitConfig(
                client_id=DEVELOPER_CLIENT_ID,
                redirect_uri=DEVELOPER_REDIRECT_URI,
            )
        except ValidationError as e:
            Messagebox.show_error(
                f"Invalid configuration:\n{e}",
                title="Configuration Error",
                parent=self.master
            )
            return None

    def _load_saved_accounts(self):
        """Load saved account names from metadata into dropdown on startup"""
        if not os.path.exists(TOKEN_DIR):
            return

        display_names = []
        name_map = {}

        for file in os.listdir(TOKEN_DIR):
            if file.endswith("_meta.json"):
                try:
                    meta_path = os.path.join(TOKEN_DIR, file)
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    display_name = meta.get("display_name")
                    hashed_name = meta.get("hashed_filename")

                    if display_name and hashed_name:
                        display_names.append(display_name)
                        name_map[display_name] = hashed_name
                except Exception as e:
                    logging.warning(f"Failed to load metadata {file}: {e}")

        if not display_names:
            # fallback: show raw .json filenames if no metadata found
            files = [f.replace(".json", "") for f in os.listdir(TOKEN_DIR)
                    if f.endswith(".json") and not f.endswith("_meta.json")]
            display_names = files

        self.account_box["values"] = display_names
        if display_names:
            self.account_box.current(0)
            try:
                self.load_account()
            except AttributeError:
                logging.warning("Auto-select handler not found (on_account_selected)")

            logging.info(f"Found {len(display_names)} saved account(s)")
            self.set_status(f"Found {len(display_names)} saved account(s)", "success")
            self.show_toast("Accounts Loaded", f"Found {len(display_names)} account(s)", bootstyle="success")

        # Store mapping for lookups later
        self._account_name_map = name_map



    def show_storage_info(self):
        """Display detailed storage information"""
        info = self.storage.get_storage_info()
        
        details = f"""Storage Information:

Keyring Library: {'Installed ✓' if info['keyring_available'] else 'Not installed ✗'}
Storage Method: {info['storage_method']}
{'Backend: ' + info['keyring_backend'] if info['keyring_backend'] else ''}
Legacy Key File: {'Exists' if info['file_exists'] else 'Not found'}

"""
        if not info['using_keyring']:
            details += """⚠️ Recommendation:
Install keyring for better security:
pip install keyring

Supported platforms:
• Windows: Credential Manager
• macOS: Keychain
• Linux: Secret Service API"""
        else:
            details += "✓ Your encryption keys are stored securely in the OS keychain!"
        
        Messagebox.show_info(details, title="Storage Information", parent=self.master)

    def add_account(self):
        """Add new Fitbit account via OAuth (PUBLIC CLIENT)"""
        cfg = self._get_config()
        if not cfg:
            return
        
        self.set_status("Starting OAuth flow...", "info")
        self.show_toast("OAuth", "Opening browser for authorization...", bootstyle="info")
        
        # Generate PKCE parameters
        verifier, challenge = generate_pkce_pair()
        scope = ["sleep", "profile"]
        
        oauth = OAuth2Session(cfg.client_id, redirect_uri=str(cfg.redirect_uri), scope=scope)
        auth_url, state = oauth.authorization_url(
            FITBIT_AUTH_URL,
            code_challenge=challenge,
            code_challenge_method="S256"
        )
        
        server = OAuthCallbackServer(OAUTH_PORT)
        
        try:
            server.start(state)
            webbrowser.open(auth_url)
            self.set_status("⏳ Waiting for browser authorization...", "warning")
            logging.info("Browser opened for OAuth authorization")
            
            code = server.wait_for_code()
            
            self.set_status("⏳ Exchanging authorization code...", "warning")
            raw_token = oauth.fetch_token(
                FITBIT_TOKEN_URL,
                code=code,
                code_verifier=verifier,
                include_client_id=True,
            )
            
            token = token_dict_to_model(raw_token)
            client = FitbitClient(cfg, token)
            name = client.get_profile_name()
            
            # Save token
            hashed_name = SecureStorage.hash_account_name(name)
            acc_file = os.path.join(TOKEN_DIR, f"{hashed_name}.json")
            
            metadata = {"display_name": name, "hashed_filename": hashed_name}
            metadata_file = os.path.join(TOKEN_DIR, f"{hashed_name}_meta.json")
            with open(metadata_file, "w") as f:
                json.dump(metadata, f)
            
            self.storage.save_encrypted(acc_file, token.model_dump_json(indent=2))
            
            with self._accounts_lock:
                self.accounts[name] = token
            
            # Update UI
            current_accounts = list(self.account_box["values"])
            if name not in current_accounts:
                current_accounts.append(name)
            self.account_box["values"] = current_accounts
            self.account_box.set(name)
            
            self.set_status(f"✓ Account '{name}' added successfully!", "success")
            self.show_toast("Success", f"Account '{name}' added!", bootstyle="success")
            Messagebox.ok(f"Account '{name}' added successfully!", title="Success", parent=self.master)
            logging.info(f"Account '{name}' added and saved")
            
        except TimeoutError as e:
            logging.error(f"OAuth timeout: {e}")
            Messagebox.show_error(f"Authorization timeout:\n{str(e)}", title="Timeout")
            self.set_status("Authorization timeout", "danger")
        except ValueError as e:
            logging.error(f"OAuth error: {e}")
            Messagebox.show_error(f"Authorization failed:\n{str(e)}", title="OAuth Error", parent=self.master)
            self.set_status("Authorization failed", "danger")
        except Exception as e:
            logging.error(f"Unexpected error adding account: {e}", exc_info=True)
            Messagebox.show_error(f"Failed to add account:\n{str(e)}", title="Error", parent=self.master)
            self.set_status("Error adding account", "danger")
        finally:
            server.stop()

    def load_account(self):
        """Load existing account token from storage"""
        name = self.account_box.get()
        if not name:
            Messagebox.show_info("Please select an account from the dropdown.", title="Select Account")
            return

        # Use hashed filename if metadata is available
        hashed_name = getattr(self, "_account_name_map", {}).get(name)
        if not hashed_name:
            hashed_name = SecureStorage.hash_account_name(name)

        path = os.path.join(TOKEN_DIR, f"{hashed_name}.json")
        if not os.path.exists(path):
            path = os.path.join(TOKEN_DIR, f"{name}.json")

        data = self.storage.load_encrypted(path)
        
        if not data:
            Messagebox.show_error(
                f"Cannot load token file for '{name}'.",
                title="Error",
                parent=self.master
            )
            return
        
        try:
            token = Token.model_validate_json(data)
            
            with self._accounts_lock:
                self.accounts[name] = token
            
            self.set_status(f"✓ Loaded account '{name}'", "success")
            self.show_toast("Account Loaded", f"'{name}' ready to use", bootstyle="success")
            logging.info(f"Loaded account: {name}")
            
        except ValidationError as e:
            Messagebox.show_error(f"Invalid token format:\n{e}", title="Error", parent=self.master)
            logging.error(f"Token validation error for {name}: {e}")

    # ────────────────────────────────────────────────────────────
    # Data Fetch
    # ────────────────────────────────────────────────────────────

    def fetch_data(self):
        """Fetch sleep data (runs in background thread)"""

        # Ensure an account is loaded before fetching data
        if not getattr(self, "active_account", None):
            selected = self.account_box.get()
            if selected:
                try:
                    self.load_account()
                    logging.info(f"Automatically loaded account: {selected}")
                except AttributeError:
                    logging.warning("Account load handler (on_account_selected) not found")

        if self.is_fetching:
            Messagebox.show_warning(
                "Already fetching data. Please wait...",
                title="In Progress",
                parent=self.master
            )
            return
        
        threading.Thread(target=self._fetch_worker, daemon=True).start()

    def _fetch_worker(self):
        """Background worker to fetch sleep data"""
        self.is_fetching = True
        self._ui(lambda: self.progress_bar.start(10))
        self._ui(lambda: self.fetch_btn.configure(state="disabled"))
        
        name = self.account_box.get()
        
        with self._accounts_lock:
            if not name or name not in self.accounts:
                self._ui(lambda: Messagebox.show_info(
                    "Please load or add an account first.",
                    title="Account Required",
                    parent=self.master
                ))
                self._cleanup_fetch()
                return
            token = self.accounts[name].copy()
        
        date = self.date_entry.get().strip()
        
        if not validate_date_format(date):
            self._ui(lambda: Messagebox.show_error(
                "Please use YYYY-MM-DD format (e.g., 2024-10-30)",
                title="Invalid Date",
                parent=self.master
            ))
            self._cleanup_fetch()
            return
        
        cfg = self._get_config()
        if not cfg:
            self._cleanup_fetch()
            return
        
        self._ui(lambda: self.set_status(f"⏳ Fetching data for {name}...", "info"))
        
        try:
            client = FitbitClient(cfg, token, save_cb=lambda t: self._save_token(name, t))
            record = client.get_sleep_data(date)
            
            if not record:
                self._ui(lambda: Messagebox.show_info(
                    f"No sleep data found for {date}.\n"
                    f"Check that you have sleep data logged for this date.",
                    title="No Data",
                    parent=self.master
                ))
                self._ui(lambda: self.set_status("No data found", "warning"))
                self._cleanup_fetch()
                return
            
            record.account = name
            
            with self._accounts_lock:
                if name in self.accounts:
                    self.accounts[name] = client.token
            
            with self._data_lock:
                records = self.sleep_data.setdefault(name, [])
                records[:] = [r for r in records if r.date != record.date]
                records.append(record)
            
            self._ui(lambda: self._insert_record(record))
            self._ui(lambda: self.set_status(f"✓ Data for {name} loaded successfully!", "success"))
            self._ui(lambda: self.show_toast("Success", f"Sleep data for {date} loaded", bootstyle="success"))
            logging.info(f"Sleep data fetched successfully for {name} on {date}")
            
        except RuntimeError as e:
            logging.error(f"Token error: {e}")
            self._ui(lambda: Messagebox.show_error(
                f"Failed to refresh token. Please re-authenticate:\n{str(e)}",
                title="Token Error",
                parent=self.master
            ))
            self._ui(lambda: self.set_status("Token error - re-authentication needed", "danger"))
        except Exception as e:
            logging.error(f"Error fetching data: {e}", exc_info=True)
            self._ui(lambda: Messagebox.show_error(f"Failed to fetch data:\n{str(e)}", title="Error", parent=self.master))
            self._ui(lambda: self.set_status("Error fetching data", "danger"))
        finally:
            self._cleanup_fetch()

    def _cleanup_fetch(self):
        """Cleanup after fetch operation"""
        self.is_fetching = False
        self._ui(lambda: self.progress_bar.stop())
        self._ui(lambda: self.fetch_btn.configure(state="normal"))

    def _ui(self, fn: Callable):
        """Execute function on UI thread"""
        self.master.after(0, fn)

    def _insert_record(self, rec: SleepRecord):
        """Insert sleep record into table"""
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if values[0] == rec.account and values[1] == rec.date:
                self.tree.delete(item)
        
        self.tree.insert("", "end", values=list(rec.model_dump().values()))

    def _save_token(self, name: str, t: Token):
        """Save token to encrypted storage"""
        hashed_name = SecureStorage.hash_account_name(name)
        path = os.path.join(TOKEN_DIR, f"{hashed_name}.json")
        
        if not os.path.exists(path):
            path = os.path.join(TOKEN_DIR, f"{name}.json")
        
        self.storage.save_encrypted(path, t.model_dump_json(indent=2))
        logging.debug(f"Token saved for {name}")

    # ────────────────────────────────────────────────────────────
    # Export
    # ────────────────────────────────────────────────────────────

    def export_csv(self):
        """Export sleep data to CSV file"""
        with self._data_lock:
            if not self.sleep_data:
                Messagebox.show_info(
                    "No data to export. Fetch some sleep data first.",
                    title="No Data"
                )
                return
            
            all_records = [
                r.model_dump()
                for lst in self.sleep_data.values()
                for r in lst
            ]
        
        if not all_records:
            Messagebox.show_info("No data to export.", title="No Data")
            return
        
        df = pd.DataFrame(all_records)
        df = df.sort_values(["account", "date"])
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"fitbit_sleep_data_{datetime.date.today()}.csv"
        )
        
        if filepath:
            try:
                df.to_csv(filepath, index=False)
                Messagebox.ok(
                    f"✓ CSV exported successfully!\n\n"
                    f"File: {filepath}\n"
                    f"Records: {len(all_records)}",
                    title="Success",
                    parent=self.master
                )
                self.set_status(f"✓ Exported {len(all_records)} records", "success")
                self.show_toast("Export Complete", f"{len(all_records)} records exported", bootstyle="success")
                logging.info(f"Exported {len(all_records)} records to {filepath}")
            except Exception as e:
                Messagebox.show_error(f"Failed to export CSV:\n{str(e)}", title="Export Error", parent=self.master)
                logging.error(f"Export error: {e}", exc_info=True)

# ═══════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════

def main():
    """Main application entry point"""
    try:
        # Create window with modern theme
        root = ttk.Window(
            title="🌙 Sleep Data Tool",
            themename="flatly",  # Options: darkly, flatly, litera, minty, pulse, superhero, etc.
            size=(1000, 750)
        )
        
        app = FitbitApp(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application error: {e}", exc_info=True)
        try:
            Messagebox.show_error(f"Application failed to start:\n{str(e)}", title="Fatal Error", parent=root)
        except:
            print(f"Fatal error: {e}")

if __name__ == "__main__":
    main()