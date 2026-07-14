import traceback
import re
import warnings
import winreg
from pathlib import Path
import ssl
import socket
import select
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from http.server import HTTPServer, BaseHTTPRequestHandler
import certifi
import subprocess
import sys
import platform
from datetime import datetime, timedelta, timezone
import dearpygui.dearpygui as dpg
import win32gui
import win32con
import keyboard
import time
import json
import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import shutil
import glob
from tkinter import Tk, filedialog
import pyperclip
import urllib3
from collections import defaultdict
import ctypes
import ctypes.wintypes

# Requires: pip install pyopenssl pydivert

try:
    import pydivert
    from pydivert import WinDivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WinDivertInterceptor:
    """Kernel-level packet interceptor using WinDivert for process-based traffic capture"""
    
    def __init__(self, proxy_port=8443):
        self.proxy_port = proxy_port
        self.running = False
        self.filter_by_pid = True
        self.process_names = ["RobloxPlayerBeta.exe"]
        self.own_pid = os.getpid()
        self.connection_table = {}  # src_port → (orig_dst_addr, orig_dst_port)
        self.pid_map = {}  # (src_addr, src_port, dst_addr, dst_port) → process_name
        self.pid_cache = {}  # pid (int) → process_name (str)
        self._network_handle = None
        self._socket_thread = None
        self._network_thread = None
        self._lock = threading.Lock()
        self._cleanup_timer = None
        self._error_message = ""
    
    def start(self):
        """Start WinDivert interceptor"""
        if not PYDIVERT_AVAILABLE:
            return False, "pydivert is not installed. Run: pip install pydivert"
        if self.running:
            return False, "Interceptor already running"
        
        self._error_message = ""
        
        try:
            self.running = True
            self._socket_thread = threading.Thread(target=self._run_socket_monitor, daemon=True)
            self._network_thread = threading.Thread(target=self._run_network_interceptor, daemon=True)
            self._socket_thread.start()
            time.sleep(0.3)  # Let socket monitor start first to build PID map
            self._network_thread.start()
            self._start_cleanup_timer()
            return True, "Network Capture started"
        except Exception as e:
            self.running = False
            msg = f"WinDivert failed to start: {str(e)}. Make sure the app is running as Administrator and your antivirus is not blocking WinDivert."
            self._error_message = msg
            return False, msg
    
    def stop(self):
        """Stop WinDivert interceptor"""
        self.running = False
        if self._cleanup_timer:
            self._cleanup_timer.cancel()
            self._cleanup_timer = None
        # Close WinDivert network handle to unblock recv loop
        try:
            if self._network_handle:
                self._network_handle.close()
                self._network_handle = None
        except:
            pass
        with self._lock:
            self.connection_table.clear()
            self.pid_map.clear()
        return True, "Network Capture stopped"
    
    def get_original_dest(self, client_port):
        """Look up original destination for a redirected connection"""
        with self._lock:
            return self.connection_table.get(client_port)
    
    def _get_process_name(self, pid):
        """Get process name from PID with caching"""
        if pid in self.pid_cache:
            return self.pid_cache[pid]
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if handle:
                buf = ctypes.create_unicode_buffer(260)
                size = ctypes.wintypes.DWORD(260)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(
                    handle, 0, buf, ctypes.byref(size)
                ):
                    name = os.path.basename(buf.value)
                    self.pid_cache[pid] = name
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return name
                ctypes.windll.kernel32.CloseHandle(handle)
        except:
            pass
        self.pid_cache[pid] = ""
        return ""
    
    def _should_intercept(self, process_name):
        """Check if traffic from this process should be intercepted"""
        if not self.filter_by_pid:
            return True  # Capture all when PID filter disabled
        if not process_name:
            return False
        return process_name.lower() in [p.strip().lower() for p in self.process_names]
    
    @staticmethod
    def _addr_to_str(addr):
        """Convert WinDivert uint32[4] address to IP string"""
        import struct
        # IPv4 is stored in the first element only (mapped IPv4)
        raw = struct.pack(">I", addr[0])
        return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"
    
    def _lookup_pid_by_port(self, src_port):
        """Real-time PID lookup by source port using Windows TCP table"""
        try:
            import ctypes
            from ctypes import wintypes
            
            iphlpapi = ctypes.windll.iphlpapi
            TCP_TABLE_OWNER_PID_ALL = 5
            AF_INET = 2
            
            class ROW(ctypes.Structure):
                _fields_ = [
                    ("dwState", wintypes.DWORD),
                    ("dwLocalAddr", wintypes.DWORD),
                    ("dwLocalPort", wintypes.DWORD),
                    ("dwRemoteAddr", wintypes.DWORD),
                    ("dwRemotePort", wintypes.DWORD),
                    ("dwOwningPid", wintypes.DWORD),
                ]
            
            class TABLE(ctypes.Structure):
                _fields_ = [
                    ("dwNumEntries", wintypes.DWORD),
                    ("table", ROW * 1),
                ]
            
            size = wintypes.DWORD(0)
            iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            buf = (ctypes.c_byte * size.value)()
            ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            
            if ret == 0:
                table = ctypes.cast(buf, ctypes.POINTER(TABLE)).contents
                rows = ctypes.cast(ctypes.byref(table.table), ctypes.POINTER(ROW * table.dwNumEntries)).contents
                for row in rows:
                    local_port = ((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF)
                    if local_port == src_port:
                        pid = row.dwOwningPid
                        if pid != self.own_pid:
                            return self._get_process_name(pid)
        except:
            pass
        return ""
    
    def _run_socket_monitor(self):
        """Monitor TCP connections to map connections to process IDs using Windows TCP table API"""
        try:
            # Use GetExtendedTcpTable (iphlpapi) for PID mapping
            # This replaces WinDivert SOCKET layer which requires WinDivert 2.0+
            import ctypes
            from ctypes import wintypes
            
            iphlpapi = ctypes.windll.iphlpapi
            
            # MIB_TCP_STATE constants
            TCP_TABLE_OWNER_PID_ALL = 5
            AF_INET = 2
            
            class MIB_TCPROW_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("dwState", wintypes.DWORD),
                    ("dwLocalAddr", wintypes.DWORD),
                    ("dwLocalPort", wintypes.DWORD),
                    ("dwRemoteAddr", wintypes.DWORD),
                    ("dwRemotePort", wintypes.DWORD),
                    ("dwOwningPid", wintypes.DWORD),
                ]
            
            class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("dwNumEntries", wintypes.DWORD),
                    ("table", MIB_TCPROW_OWNER_PID * 1),
                ]
            
            def _ip_int_to_str(ip_int):
                """Convert network-byte-order DWORD to IP string"""
                return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
            
            def _port_int_to_host(port_int):
                """Convert network-byte-order port to host order"""
                return ((port_int & 0xFF) << 8) | ((port_int >> 8) & 0xFF)
            
            while self.running:
                try:
                    # Get required buffer size
                    size = wintypes.DWORD(0)
                    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
                    
                    buf = (ctypes.c_byte * size.value)()
                    ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
                    
                    if ret == 0:  # NO_ERROR
                        table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
                        num = table.dwNumEntries
                        
                        # Access rows via pointer arithmetic
                        row_array = ctypes.cast(
                            ctypes.byref(table.table),
                            ctypes.POINTER(MIB_TCPROW_OWNER_PID * num)
                        ).contents
                        
                        for row in row_array:
                            remote_port = _port_int_to_host(row.dwRemotePort)
                            if remote_port != 443:
                                continue
                            
                            pid = row.dwOwningPid
                            if pid == self.own_pid:
                                continue
                            
                            process_name = self._get_process_name(pid)
                            local_ip = _ip_int_to_str(row.dwLocalAddr)
                            local_port = _port_int_to_host(row.dwLocalPort)
                            remote_ip = _ip_int_to_str(row.dwRemoteAddr)
                            
                            key = (local_ip, local_port, remote_ip, remote_port)
                            with self._lock:
                                self.pid_map[key] = process_name
                    
                    time.sleep(0.5)  # Poll every 500ms
                except Exception:
                    if not self.running:
                        break
                    time.sleep(1.0)
        except Exception as e:
            if self.running:
                self._error_message = f"Socket monitor error: {e}"
                print(f"Socket monitor error: {e}")
    
    def _run_network_interceptor(self):
        """Intercept network packets and redirect matching traffic to local proxy"""
        try:
            # Capture outbound to port 443 AND inbound from our proxy port
            # We need both directions for proper NAT: redirect outbound, restore inbound
            self._network_handle = WinDivert(
                "(outbound and tcp.DstPort == 443 and !loopback) or "
                f"(inbound and tcp.SrcPort == {self.proxy_port} and ip.SrcAddr == 127.0.0.1)"
            )
            self._network_handle.open()
            print("[WinDivert] Network interceptor opened successfully")
            while self.running:
                try:
                    packet = self._network_handle.recv()
                    if not packet:
                        continue
                    
                    if packet.is_outbound:
                        # OUTBOUND: redirect Roblox traffic to our proxy
                        key = (packet.src_addr, packet.src_port,
                               packet.dst_addr, packet.dst_port)
                        with self._lock:
                            process_name = self.pid_map.get(key, "")
                        
                        # Fallback: if PID map miss, try direct lookup by source port
                        if not process_name:
                            process_name = self._lookup_pid_by_port(packet.src_port)
                            if process_name:
                                with self._lock:
                                    self.pid_map[key] = process_name
                        
                        if self._should_intercept(process_name):
                            print(f"[WinDivert] REDIRECT {process_name}: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port} => 127.0.0.1:{self.proxy_port}")
                            # Save original destination before redirecting
                            with self._lock:
                                self.connection_table[packet.src_port] = (
                                    packet.dst_addr, packet.dst_port
                                )
                            # Redirect to local proxy
                            packet.dst_addr = "127.0.0.1"
                            packet.dst_port = self.proxy_port
                    else:
                        # INBOUND: response from our proxy - restore original source
                        with self._lock:
                            orig = self.connection_table.get(packet.dst_port)
                        if orig:
                            orig_addr, orig_port = orig
                            print(f"[WinDivert] RESTORE inbound: 127.0.0.1:{self.proxy_port} => {orig_addr}:{orig_port}")
                            packet.src_addr = orig_addr
                            packet.src_port = orig_port
                    
                    # Re-inject packet (modified or not)
                    self._network_handle.send(packet)
                except Exception as exc:
                    if not self.running:
                        break
                    print(f"[WinDivert] Packet error: {exc}")
        except Exception as e:
            if self.running:
                self._error_message = f"Network interceptor error: {e}"
                print(f"Network interceptor error: {e}")
    
    def _start_cleanup_timer(self):
        """Periodically clean stale entries from connection table and PID cache"""
        if not self.running:
            return
        with self._lock:
            # Cap connection table at 1000 entries
            if len(self.connection_table) > 1000:
                keys = list(self.connection_table.keys())
                for k in keys[:500]:
                    del self.connection_table[k]
            # Cap PID map at 5000 entries
            if len(self.pid_map) > 5000:
                self.pid_map.clear()
                self.pid_cache.clear()
        self._cleanup_timer = threading.Timer(60.0, self._start_cleanup_timer)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()


# ---------------------------------------------------------------------------
# Constants for Roblox directory scanning
# ---------------------------------------------------------------------------

_ROBLOX_PROCESS = 'RobloxPlayerBeta.exe'
_ROBLOX_STUDIO_PROCESS = 'RobloxStudioBeta.exe'

_PEM_CERT_BLOCK_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----\s*\n.*?\n\s*-----END CERTIFICATE-----',
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Roblox directory scanner for CA injection
# ---------------------------------------------------------------------------

def _extract_exe_from_command(command):
    """Extract an executable path from a registry shell/open command string."""
    if not command:
        return None
    cmd = command.replace('\x00', '').strip()
    if not cmd:
        return None
    if cmd.startswith('"'):
        end_quote = cmd.find('"', 1)
        if end_quote <= 1:
            return None
        exe_str = cmd[1:end_quote]
    else:
        exe_str = cmd.split()[0] if cmd.split() else cmd
    p = Path(exe_str)
    if p.suffix.lower() in ('.exe', '.com', '.bat', '.cmd') and p.exists():
        return p
    return None


def _find_roblox_dirs():
    """Locate every RobloxPlayerBeta.exe and RobloxStudioBeta.exe installation.
    Scans Windows registry to find all Roblox-compatible launchers including
    Froststrap, Fishstrap, Bloxstrap, and standard Roblox."""
    found = []
    seen = set()

    def _add(path):
        key = str(path)
        if key not in seen:
            found.append(path)
            seen.add(key)
            return True
        return False

    def _scan_for_exe(root, max_depth):
        results = []
        def _has_roblox_exe(path):
            return (
                os.path.isfile(os.path.join(path, _ROBLOX_PROCESS))
                or os.path.isfile(os.path.join(path, _ROBLOX_STUDIO_PROCESS))
            )
        if root.is_dir() and _has_roblox_exe(root):
            results.append(root)
        def _recurse(path, depth):
            try:
                for entry in os.scandir(path):
                    if not entry.is_dir():
                        continue
                    entry_path = Path(entry.path)
                    if _has_roblox_exe(entry_path):
                        results.append(entry_path)
                    if depth < max_depth:
                        _recurse(entry_path, depth + 1)
            except OSError:
                pass
        if root.is_dir():
            _recurse(root, 1)
        return results

    def _check_player_path_key(key):
        for value_name, process_name in (('PlayerPath', _ROBLOX_PROCESS), ('StudioPath', _ROBLOX_STUDIO_PROCESS)):
            try:
                val, rtype = winreg.QueryValueEx(key, value_name)
            except OSError:
                continue
            if rtype != winreg.REG_SZ or not val:
                continue
            val = val.replace('\x00', '').strip()
            if not val:
                continue
            p = Path(val)
            if p.name.lower() == process_name.lower():
                p = p.parent
            if os.path.isfile(os.path.join(str(p), process_name)):
                _add(p)
            else:
                for d in _scan_for_exe(p, 1):
                    _add(d)

    # 1. Main Registry Search (finds Froststrap, Fishstrap, Bloxstrap, etc.)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software') as hkey:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(hkey, i); i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(hkey, name) as sk:
                        _check_player_path_key(sk)
                        j = 0
                        while True:
                            try:
                                sub = winreg.EnumKey(sk, j); j += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(sk, sub) as ssk:
                                    _check_player_path_key(ssk)
                            except (OSError, ValueError):
                                pass
                except OSError:
                    pass
    except OSError:
        pass

    # 2. MS Store Version
    for d in _scan_for_exe(Path(r'C:\XboxGames\Roblox'), 2):
        _add(d)

    # 3. Active Roblox Player (registry shell command)
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'SOFTWARE\Classes\roblox-player\shell\open\command',
        ) as key:
            try:
                cmd, rtype = winreg.QueryValueEx(key, '')
                if rtype == winreg.REG_SZ and cmd:
                    exe_path = _extract_exe_from_command(cmd)
                    if exe_path is not None:
                        for d in _scan_for_exe(exe_path.parent, 2):
                            _add(d)
            except (OSError, ValueError):
                pass
    except OSError:
        pass

    # 4. Program Files (x86) Roblox
    for d in _scan_for_exe(Path(r'C:\Program Files (x86)\Roblox\Versions'), 2):
        _add(d)

    # 5. Regular Roblox (%LocalAppData%\Roblox\Versions)
    local_appdata = Path(os.environ.get('LOCALAPPDATA', ''))
    if local_appdata.exists():
        for d in _scan_for_exe(local_appdata / 'Roblox' / 'Versions', 1):
            _add(d)

    # 6. Active Studio (registry shell command)
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'SOFTWARE\Classes\roblox-studio\shell\open\command',
        ) as key:
            try:
                cmd, rtype = winreg.QueryValueEx(key, '')
                if rtype == winreg.REG_SZ and cmd:
                    exe_path = _extract_exe_from_command(cmd)
                    if exe_path is not None:
                        for d in _scan_for_exe(exe_path.parent, 2):
                            _add(d)
            except (OSError, ValueError):
                pass
    except OSError:
        pass

    return found


# ---------------------------------------------------------------------------
# CA injection into Roblox cacert.pem
# ---------------------------------------------------------------------------

def _normalize_newlines(text):
    return text.replace('\r\n', '\n').replace('\r', '\n')

def _normalize_pem_block(pem_block):
    return f"{_normalize_newlines(pem_block).strip()}\n"

def _is_diversion_ca_cert_block(pem_block):
    """Return True if pem_block is a Diversion/FlagBrowser self-signed CA cert."""
    try:
        from cryptography.utils import CryptographyDeprecationWarning
        with warnings.catch_warnings():
            warnings.filterwarnings(
                'ignore',
                category=CryptographyDeprecationWarning,
                message=r"Parsed a serial number which wasn't positive.*",
            )
            cert = x509.load_pem_x509_certificate(pem_block.encode('utf-8'))
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        cn = cn_attrs[0].value if cn_attrs else ''
        org = org_attrs[0].value if org_attrs else ''
        return (
            cert.subject == cert.issuer
            and (
                cn == 'Diversion Root CA'
                or 'lumyna.cc' in org
                or 'FlagBrowser' in org
                or 'Diversion' in cn
            )
        )
    except Exception:
        return False


def _upsert_diversion_ca_in_cacert(ca_file, ca_pem):
    """Ensure exactly one current Diversion CA exists in ca_file.
    Returns (changed, diversion_count_before, current_count_before).
    """
    existing = ca_file.read_text(encoding='utf-8', errors='replace') if ca_file.exists() else ''
    normalized_existing = _normalize_newlines(existing)
    normalized_current = _normalize_pem_block(ca_pem)

    # Strip all Diversion CA blocks
    parts = []
    last_end = 0
    diversion_count = 0
    current_count = 0

    for match in _PEM_CERT_BLOCK_RE.finditer(normalized_existing if existing else ''):
        parts.append((_normalize_newlines(existing) if existing else '')[last_end:match.start()])
        block = match.group(0)
        if _is_diversion_ca_cert_block(block):
            diversion_count += 1
            if _normalize_pem_block(block) == normalized_current:
                current_count += 1
        else:
            parts.append(block)
        last_end = match.end()
    parts.append((_normalize_newlines(existing) if existing else '')[last_end:])

    cleaned = ''.join(parts).rstrip('\n')
    updated = f'{cleaned}\n{normalized_current}' if cleaned else normalized_current

    changed = updated != normalized_existing
    if changed:
        ca_file.write_text(updated, encoding='utf-8')

    return changed, diversion_count, current_count


def _install_ca_into_roblox(ca_pem):
    """Ensure each Roblox ssl/cacert.pem has exactly one current Diversion CA cert.
    Scans all Roblox installations found via registry."""
    dirs = _find_roblox_dirs()
    if not dirs:
        return

    for d in dirs:
        ssl_dir = d / 'ssl'
        ssl_dir.mkdir(exist_ok=True)
        ca_file = ssl_dir / 'cacert.pem'
        try:
            changed, diversion_count, current_count = _upsert_diversion_ca_in_cacert(ca_file, ca_pem)
        except (PermissionError, OSError, UnicodeDecodeError):
            pass


class ProxySettings:
    """Lightweight HTTPS proxy for intercepting Roblox settings requests"""
    
    def __init__(self):
        self.port = 8443
        self.running = False
        self.stop_requested = False
        self.intercepted_count = 0
        self.passthrough_count = 0
        self.logs = []
        self.max_logs = 200
        self.log_mutex = threading.Lock()
        # Collapse identical retry storms so they cannot flood the UI.
        self._last_log_entry = None
        self._last_log_at = 0.0
        self.server_thread = None
        self.server_socket = None
        self.ca_cert_path = ""
        self.ca_key_path = ""
        self.json_path = ""
        self.connections = []
        self.thread_pool = None
        self.interceptor = WinDivertInterceptor(self.port)
        self._real_server_ip = None  # Cached real IP resolved before hosts redirect
        self.on_client_version_callback = None  # Called when /client-version/ is seen
        
    def generate_ca_cert(self, cert_path, key_path):
        """Generate a self-signed CA certificate and key pair using cryptography lib"""
        try:
            # Generate RSA key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
            
            # Build subject/issuer (self-signed, so same)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "lumyna.cc"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Diversion Root CA"),
            ])
            
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(int(time.time() * 1000))
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=5 * 365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False, key_encipherment=False,
                        content_commitment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=False, decipher_only=False,
                    ), critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            
            # Save certificate
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Save key
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            return True, "CA certificate generated successfully!"
        except Exception as e:
            return False, f"Failed to generate CA certificate: {str(e)}"
    
    def install_ca_cert_windows(self, cert_path):
        """Install CA certificate into Windows Local Machine trusted root store"""
        if platform.system() != "Windows":
            return False, "Certificate installation is only supported on Windows"
        
        if not os.path.exists(cert_path):
            return False, f"Certificate file not found: {cert_path}"
        
        try:
            # Install to Local Machine Root store (not current user)
            result = subprocess.run(
                ['certutil', '-addstore', '-f', 'Root', cert_path],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0 or "succeeded" in result.stdout.lower():
                return True, "Certificate installed to Machine Root store successfully!"
            else:
                error_msg = result.stderr or result.stdout or "Unknown error"
                if "Access is denied" in error_msg or "access denied" in error_msg.lower():
                    return False, "Access denied. Please run the application as Administrator and try again."
                else:
                    return False, f"Installation failed: {error_msg}"
                    
        except Exception as e:
            return False, f"Error installing certificate: {str(e)}"
    
    
    def add_log(self, entry):
        """Add a log entry without letting identical retry storms flood the UI."""
        now = time.monotonic()
        with self.log_mutex:
            if entry == self._last_log_entry and (now - self._last_log_at) < 1.0:
                return
            self._last_log_entry = entry
            self._last_log_at = now
            if len(self.logs) >= self.max_logs:
                self.logs.pop(0)
            self.logs.append(entry)

    def get_logs(self):
        """Get all log entries (thread-safe)"""
        with self.log_mutex:
            return self.logs.copy()
    
    def clear_logs(self):
        """Clear all log entries (thread-safe)"""
        with self.log_mutex:
            self.logs.clear()
    
    # Roblox domains we redirect via hosts file
    INTERCEPT_DOMAINS = [
        "clientsettingscdn.roblox.com",
    ]
    HOSTS_MARKER = "# Anti Flag Proxy"
    HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    
    def _add_hosts_entries(self):
        """Add DNS redirect entries to Windows hosts file"""
        try:
            # Read current hosts file
            with open(self.HOSTS_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove any existing entries
            lines = [l for l in content.splitlines() if self.HOSTS_MARKER not in l]
            
            # Add our entries
            for domain in self.INTERCEPT_DOMAINS:
                lines.append(f"127.0.0.1 {domain} {self.HOSTS_MARKER}")
            
            with open(self.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            
            # Flush DNS cache (double flush for reliability)
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['netsh', 'interface', 'ip', 'delete', 'dnscache'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(0.1)  # Give OS time to propagate
            return True
        except Exception as e:
            print(f"Error modifying hosts file: {e}")
            return False
    
    def _remove_hosts_entries(self):
        """Remove our DNS redirect entries from hosts file"""
        try:
            with open(self.HOSTS_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = [l for l in content.splitlines() if self.HOSTS_MARKER not in l]
            
            with open(self.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            print(f"Error restoring hosts file: {e}")
    
    def start(self, port, json_path, ca_cert_path, ca_key_path, fallback_dns="1.1.1.1"):
        """Start the proxy server using hosts-file DNS redirect"""
        if self.running:
            return False, "Network Capture is already active"
        
        self.port = 443  # Must be 443 - hosts file can only redirect IP, not port
        self.json_path = json_path
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.stop_requested = False
        self.intercepted_count = 0
        self.passthrough_count = 0
        
        if not ca_cert_path or not ca_key_path or not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            return False, "CA certificate and key are required. Generate them first."
        
        # Generate leaf cert for Roblox domains
        cert_pem, key_pem = self._generate_leaf_cert("clientsettingscdn.roblox.com",
                                                       extra_sans=self.INTERCEPT_DOMAINS)
        if not cert_pem or not key_pem:
            return False, "Failed to generate leaf certificate"
        
        # Save leaf cert/key for TLS server
        import tempfile
        try:
            self._leaf_cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb')
            self._leaf_cert_file.write(cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode())
            self._leaf_cert_file.close()
            
            self._leaf_key_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb')
            self._leaf_key_file.write(key_pem if isinstance(key_pem, bytes) else key_pem.encode())
            self._leaf_key_file.close()
        except Exception as e:
            return False, f"Failed to create temp cert files: {e}"
        
        # A previous crash can leave the hosts redirect behind. Clear it before
        # resolving the upstream address, otherwise DNS returns 127.0.0.1.
        self._remove_hosts_entries()
        time.sleep(0.25)

        # Resolve the upstream address before enabling a new redirect.
        self._real_server_ip = self._resolve_real_server_ip(fallback_dns)
        if self._real_server_ip:
            self.add_log(f"[SYSTEM] Resolved real server IP: {self._real_server_ip}")
        else:
            # Do not enter capture mode if passthrough traffic cannot be forwarded.
            self.add_log("[ERROR] Capture was not started: real server IP could not be resolved")
            for attr in ('_leaf_cert_file', '_leaf_key_file'):
                try:
                    f = getattr(self, attr, None)
                    if f and os.path.exists(f.name):
                        os.unlink(f.name)
                except Exception:
                    pass
            return False, (
                "Could not resolve the real clientsettingscdn.roblox.com IP. "
                "Capture was not started to avoid forwarding failures."
            )

        # Start TLS proxy server FIRST (bind before DNS redirect to eliminate race window)
        self._server_ready = threading.Event()
        self.server_thread = threading.Thread(target=self._run_proxy, daemon=True)
        self.server_thread.start()
        
        # Wait for server to bind
        if not self._server_ready.wait(timeout=5.0):
            self.stop_requested = True
            return False, "Failed to start TLS server (bind timeout)"
        
        # NOW add hosts file entries (server is already listening)
        if not self._add_hosts_entries():
            self.stop_requested = True
            return False, "Failed to modify hosts file. Make sure the app is running as Administrator."
        
        self.add_log("[SYSTEM] Network Capture started - hosts file redirect active")
        return True, "Network Capture: Active"
    
    def _resolve_real_server_ip(self, fallback_dns="1.1.1.1"):
        """Resolve the real Roblox server IP, with fallback DNS if hosts file is already redirected"""
        try:
            real_ip = socket.getaddrinfo("clientsettingscdn.roblox.com", 443, socket.AF_INET)[0][4][0]
            if real_ip != "127.0.0.1":
                return real_ip
        except:
            pass
        
        # Hosts file already redirected or DNS failed - try fallback DNS via direct UDP query
        try:
            import struct
            # Build DNS query for clientsettingscdn.roblox.com
            domain = "clientsettingscdn.roblox.com"
            parts = domain.split('.')
            query = b'\xaa\xbb'  # Transaction ID
            query += b'\x01\x00'  # Flags: standard query, recursion desired
            query += b'\x00\x01'  # Questions: 1
            query += b'\x00\x00'  # Answers: 0
            query += b'\x00\x00'  # Authority: 0
            query += b'\x00\x00'  # Additional: 0
            for part in parts:
                query += bytes([len(part)]) + part.encode()
            query += b'\x00'      # End of name
            query += b'\x00\x01'  # Type: A
            query += b'\x00\x01'  # Class: IN
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(query, (fallback_dns, 53))
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response - skip header (12 bytes) and query section
            pos = 12
            # Skip query name
            while pos < len(response) and response[pos] != 0:
                pos += response[pos] + 1
            pos += 5  # Skip null byte + type (2) + class (2)
            
            # Read first answer
            if pos < len(response):
                # Skip name (may be pointer)
                if response[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(response) and response[pos] != 0:
                        pos += response[pos] + 1
                    pos += 1
                # Type (2) + Class (2) + TTL (4) + Data length (2)
                if pos + 10 <= len(response):
                    rtype = struct.unpack('!H', response[pos:pos+2])[0]
                    pos += 8  # Skip type + class + TTL
                    rdlength = struct.unpack('!H', response[pos:pos+2])[0]
                    pos += 2
                    if rtype == 1 and rdlength == 4 and pos + 4 <= len(response):
                        ip = '.'.join(str(b) for b in response[pos:pos+4])
                        self.add_log(f"[SYSTEM] DNS fallback ({fallback_dns}): resolved {ip}")
                        return ip
        except Exception as e:
            self.add_log(f"[WARN] DNS fallback failed: {e}")
        
        return None
    
    def stop(self):
        """Stop the proxy server and restore hosts file"""
        if not self.running:
            return False, "Network Capture is not active"
        
        self.stop_requested = True
        
        # Remove hosts file entries first
        self._remove_hosts_entries()
        
        # Connect to unblock the accept() call
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', self.port))
            s.close()
        except:
            pass
        
        # Wait for thread to finish
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2.0)
        
        # Clean up temp cert files
        for attr in ('_leaf_cert_file', '_leaf_key_file'):
            try:
                f = getattr(self, attr, None)
                if f and os.path.exists(f.name):
                    os.unlink(f.name)
            except:
                pass
        
        self.running = False
        self.add_log("[SYSTEM] Network Capture stopped - hosts file restored")
        return True, "Network Capture: Stopped"
    
    def _generate_leaf_cert(self, hostname, extra_sans=None):
        """Generate a leaf certificate for a specific hostname signed by our CA"""
        try:
            # Load CA cert and key using cryptography
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.ca_key_path, 'rb') as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Generate leaf key
            leaf_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Build SAN entries
            san_entries = [x509.DNSName(hostname)]
            if extra_sans:
                for d in extra_sans:
                    if d != hostname:
                        san_entries.append(x509.DNSName(d))
            
            now = datetime.now(timezone.utc)
            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]))
                .issuer_name(ca_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(int(time.time()))
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName(san_entries), critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )
            
            # Serialize to PEM
            cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
            key_pem = leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            
            return cert_pem, key_pem
        except Exception as e:
            print(f"Error generating leaf cert: {e}")
            return None, None
    
    def _run_proxy(self):
        """Main proxy server loop - direct TLS server on port 443"""
        self.running = True
        self.thread_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="proxy")
        
        try:
            # Create SSL server context with our leaf cert
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.set_alpn_protocols(['http/1.1'])  # Force HTTP/1.1, no h2
            ssl_context.load_cert_chain(
                certfile=self._leaf_cert_file.name,
                keyfile=self._leaf_key_file.name
            )
            
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.port))
            self.server_socket.listen(128)
            self.server_socket.settimeout(0.3)
            
            # Signal that server is ready (start() is waiting for this)
            if hasattr(self, '_server_ready'):
                self._server_ready.set()
            
            # Load JSON data
            json_body = ""
            if self.json_path and os.path.exists(self.json_path):
                with open(self.json_path, 'r', encoding='utf-8') as f:
                    json_body = f.read()
            
            print(f"[Proxy] TLS server listening on 127.0.0.1:{self.port}")
            
            while not self.stop_requested:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                
                if self.stop_requested:
                    client_sock.close()
                    break
                
                # Submit raw socket to thread pool - TLS handshake happens in the worker,
                # NOT on the accept thread. This prevents slow/failing handshakes from
                # blocking new connections (the root cause of /settings/application/ skips).
                self.thread_pool.submit(self._handshake_and_handle, ssl_context, client_sock, client_addr, json_body)
            
        except Exception as e:
            print(f"Proxy server error: {e}")
            self.add_log(f"[ERROR] Proxy server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            if self.thread_pool:
                self.thread_pool.shutdown(wait=False)
                self.thread_pool = None
            self.running = False
    
    def _handshake_and_handle(self, ssl_context, client_sock, client_addr, json_body):
        """Perform TLS handshake in the worker thread, then handle the connection.
        This keeps the accept loop free to accept new connections immediately."""
        try:
            client_sock.settimeout(5.0)  # Max 5s for TLS handshake
            ssl_sock = ssl_context.wrap_socket(client_sock, server_side=True)
            self._handle_client(ssl_sock, client_addr, json_body)
        except ssl.SSLError as e:
            self.add_log(f"[HANDSHAKE_FAIL] TLS handshake failed: {e}")
            try: client_sock.close()
            except: pass
        except OSError:
            # Connection reset during handshake - normal, don't log
            try: client_sock.close()
            except: pass
        except Exception as e:
            self.add_log(f"[ERROR] Connection error: {e}")
            try: client_sock.close()
            except: pass

    def _handle_client(self, ssl_sock, client_addr, json_body):
        """Handle a client connection - already TLS-unwrapped, with keep-alive support"""
        try:
            keep_alive = True
            while keep_alive and not self.stop_requested:
                # Read HTTP request from the decrypted TLS stream
                ssl_sock.settimeout(30.0)  # Keep-alive idle timeout
                request_data = b""
                try:
                    while True:
                        chunk = ssl_sock.recv(4096)
                        if not chunk:
                            return  # Client closed connection
                        request_data += chunk
                        if b"\r\n\r\n" in request_data:
                            break
                except socket.timeout:
                    return  # Keep-alive timeout - close gracefully
                
                if not request_data:
                    return
                
                req_text = request_data.decode('utf-8', errors='ignore')
                lines = req_text.split('\r\n')
                first_line = lines[0] if lines else ""
                parts = first_line.split(' ')
                method = parts[0] if parts else "GET"
                url = parts[1] if len(parts) > 1 else "/"
                
                # Extract Host header and check Connection header
                hostname = "clientsettingscdn.roblox.com"
                connection_header = "keep-alive"
                for line in lines[1:]:
                    lower_line = line.lower()
                    if lower_line.startswith("host:"):
                        hostname = line.split(":", 1)[1].strip()
                    elif lower_line.startswith("connection:"):
                        connection_header = line.split(":", 1)[1].strip().lower()
                
                # Respect client's Connection header
                if connection_header == "close":
                    keep_alive = False
                
                self.add_log(f"[DEBUG] {method} {hostname}{url}")
                
                # Route based on URL
                if "/settings/application/" in url or "/settings-compressed/application/" in url:
                    self._serve_settings_response(ssl_sock, json_body, url, method, hostname, keep_alive)
                else:
                    # Forward non-settings requests to the real server using cached IP
                    self.passthrough_count += 1
                    
                    # Trigger cacert protection when /client-version/ is seen
                    if "/client-version/" in url and self.on_client_version_callback:
                        try:
                            self.on_client_version_callback()
                        except:
                            pass
                    
                    if not self._real_server_ip:
                        # No cached IP - return 503 so Roblox retries against real server
                        error_body = b'{"error":"Service Unavailable"}'
                        response = (
                            b"HTTP/1.1 503 Service Unavailable\r\n"
                            + f"Content-Length: {len(error_body)}\r\n".encode()
                            + b"Content-Type: application/json\r\n"
                            + b"Connection: close\r\n"
                            + b"\r\n"
                            + error_body
                        )
                        ssl_sock.sendall(response)
                        self.add_log(f"[ERROR] {method} {hostname}{url} - cannot forward, no real server IP")
                        return
                    try:
                        real_hostname = "clientsettingscdn.roblox.com"
                        real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        real_sock.settimeout(10.0)
                        real_sock.connect((self._real_server_ip, 443))
                        real_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        real_ctx.check_hostname = False
                        real_ctx.verify_mode = ssl.CERT_NONE
                        real_ctx.set_alpn_protocols(['http/1.1'])
                        real_ssl = real_ctx.wrap_socket(real_sock, server_hostname=real_hostname)
                        real_ssl.sendall(request_data)
                        
                        response = b""
                        real_ssl.settimeout(5.0)
                        while True:
                            try:
                                chunk = real_ssl.recv(8192)
                                if not chunk:
                                    break
                                response += chunk
                            except:
                                break
                        
                        if response:
                            ssl_sock.sendall(response)
                        real_ssl.close()
                        real_sock.close()
                        self.add_log(f"[FORWARD] {method} {hostname}{url}")
                    except Exception as fwd_err:
                        # If forwarding fails, serve 503 instead of fake 200
                        error_body = b'{"error":"Service Unavailable"}'
                        response = (
                            b"HTTP/1.1 503 Service Unavailable\r\n"
                            + f"Content-Length: {len(error_body)}\r\n".encode()
                            + b"Content-Type: application/json\r\n"
                            + b"Connection: close\r\n"
                            + b"\r\n"
                            + error_body
                        )
                        ssl_sock.sendall(response)
                        self.add_log(f"[FORWARD_FAIL] {method} {hostname}{url} -> {fwd_err}")
                        return  # Close connection after forward failure
        except ConnectionResetError:
            pass  # WinError 10054 - client disconnected, totally normal
        except OSError as e:
            if e.winerror == 10054 or e.winerror == 10053:
                pass  # Connection reset/aborted by peer - normal
            else:
                self.add_log(f"[ERROR] {e}")
        except Exception as e:
            self.add_log(f"[ERROR] {e}")
        finally:
            try:
                ssl_sock.close()
            except:
                pass
    
    def _extract_sni(self, sock):
        """Extract SNI hostname from TLS ClientHello without consuming data"""
        try:
            data = sock.recv(4096, socket.MSG_PEEK)
            if len(data) < 5 or data[0] != 0x16:  # Not TLS handshake
                return None
            # Parse TLS record
            pos = 5  # Skip TLS record header
            if pos >= len(data) or data[pos] != 0x01:  # Not ClientHello
                return None
            pos += 4  # Skip handshake header
            pos += 2  # Skip client version
            pos += 32  # Skip random
            if pos >= len(data):
                return None
            session_len = data[pos]
            pos += 1 + session_len
            if pos + 2 > len(data):
                return None
            cipher_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2 + cipher_len
            if pos >= len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len
            # Extensions
            if pos + 2 > len(data):
                return None
            ext_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            end = pos + ext_len
            while pos + 4 < end and pos < len(data):
                ext_type = int.from_bytes(data[pos:pos+2], 'big')
                ext_data_len = int.from_bytes(data[pos+2:pos+4], 'big')
                pos += 4
                if ext_type == 0x0000:  # SNI extension
                    if pos + 2 < len(data):
                        sni_pos = pos + 2
                        if sni_pos < len(data) and data[sni_pos] == 0x00:  # Host name type
                            if sni_pos + 3 < len(data):
                                name_len = int.from_bytes(data[sni_pos+1:sni_pos+3], 'big')
                                if sni_pos + 3 + name_len <= len(data):
                                    return data[sni_pos+3:sni_pos+3+name_len].decode('ascii')
                pos += ext_data_len
        except:
            pass
        return None
    
    def _handle_mitm(self, client_sock, hostname, orig_addr, orig_port, json_body):
        """MITM a TLS connection: terminate TLS, inspect HTTP, serve modified content or tunnel"""
        try:
            # Generate leaf cert for this hostname
            cert_pem, key_pem = self._generate_leaf_cert(hostname)
            if not cert_pem or not key_pem:
                self._tunnel_to_original(client_sock, orig_addr, orig_port)
                return
            
            import tempfile
            cert_path = None
            key_path = None
            
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb') as f:
                    f.write(cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode())
                    cert_path = f.name
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb') as f:
                    f.write(key_pem if isinstance(key_pem, bytes) else key_pem.encode())
                    key_path = f.name
                
                # Create SSL context and wrap client socket (force HTTP/1.1, no h2)
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.set_alpn_protocols(['http/1.1'])
                ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                ssl_sock = ssl_context.wrap_socket(client_sock, server_side=True)
                
                # Read HTTP request from decrypted stream
                ssl_sock.settimeout(3.0)
                request_data = b""
                try:
                    while True:
                        chunk = ssl_sock.recv(4096)
                        if not chunk:
                            break
                        request_data += chunk
                        if b"\r\n\r\n" in request_data:
                            break
                except:
                    pass
                
                if request_data:
                    req_text = request_data.decode('utf-8', errors='ignore')
                    lines = req_text.split('\r\n')
                    first_line = lines[0] if lines else ""
                    parts = first_line.split(' ')
                    method = parts[0] if parts else "GET"
                    url = parts[1] if len(parts) > 1 else "/"
                    
                    # Route based on URL
                    if "/settings/application/" in url or "/settings-compressed/application/" in url:
                        self._serve_settings_response(ssl_sock, json_body, url, method, hostname)
                    elif "gamejoin" in url.lower():
                        self._forward_and_log_gamejoin(ssl_sock, hostname, orig_addr, orig_port, url, method, request_data)
                    else:
                        self.passthrough_count += 1
                        # Trigger cacert protection when /client-version/ is seen
                        if "/client-version/" in url and self.on_client_version_callback:
                            try:
                                self.on_client_version_callback()
                            except:
                                pass
                        self._tunnel_ssl_to_original(ssl_sock, hostname, orig_addr, orig_port, request_data)
                
                try:
                    ssl_sock.close()
                except:
                    pass
            finally:
                if cert_path:
                    try: os.unlink(cert_path)
                    except: pass
                if key_path:
                    try: os.unlink(key_path)
                    except: pass
        except Exception as e:
            pass
    
    def _serve_settings_response(self, ssl_sock, json_body, url, method, hostname, keep_alive=False):
        """Serve fiddler.json content as the settings response"""
        try:
            # Reload current JSON
            try:
                with open(self.json_path, 'r', encoding='utf-8') as f:
                    current_json = f.read()
            except:
                current_json = json_body if json_body else "{}"
            
            response_body = current_json.encode('utf-8')
            conn_header = b"Connection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n" if keep_alive else b"Connection: close\r\n"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(response_body)}\r\n".encode()
                + conn_header
                + b"\r\n"
                + response_body
            )
            ssl_sock.sendall(response)
            self.intercepted_count += 1
            self.add_log(f"[SETTINGS] {method} {hostname}{url}")
        except Exception as e:
            pass
    
    def _forward_and_log_gamejoin(self, ssl_client, hostname, orig_addr, orig_port, url, method, request_data):
        """Forward gamejoin request to real server and log it"""
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect((orig_addr, int(orig_port)))
            
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['http/1.1'])  # Force HTTP/1.1
            remote_ssl = ctx.wrap_socket(remote_sock, server_hostname=hostname)
            
            remote_ssl.sendall(request_data)
            
            response = b""
            remote_ssl.settimeout(5.0)
            while True:
                try:
                    chunk = remote_ssl.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except:
                    break
            
            # Extract status code for logging
            status = "???"
            try:
                first_line = response.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    status = parts[1]
            except:
                pass
            
            self.add_log(f"[GAMEJOIN] {method} {hostname}{url} -> {status}")
            
            if response:
                ssl_client.sendall(response)
            
            remote_ssl.close()
            remote_sock.close()
        except Exception as e:
            self.add_log(f"[GAMEJOIN] {method} {hostname}{url} -> Error: {str(e)}")
    
    def _tunnel_ssl_to_original(self, ssl_client, hostname, orig_addr, orig_port, initial_request):
        """Tunnel decrypted traffic to real server (re-encrypt for server side)"""
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect((orig_addr, int(orig_port)))
            
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['http/1.1'])  # Force HTTP/1.1
            remote_ssl = ctx.wrap_socket(remote_sock, server_hostname=hostname)
            
            remote_ssl.sendall(initial_request)
            self._bidirectional_relay(ssl_client, remote_ssl)
            
            remote_ssl.close()
            remote_sock.close()
        except:
            pass
    
    def _tunnel_to_original(self, client_sock, dst_addr, dst_port):
        """Tunnel raw TCP traffic to original destination without TLS interception"""
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect((dst_addr, int(dst_port)))
            self._bidirectional_relay(client_sock, remote_sock)
            remote_sock.close()
        except:
            pass
    
    def _bidirectional_relay(self, sock1, sock2):
        """Relay data bidirectionally between two sockets using select"""
        sockets = [sock1, sock2]
        timeout = 30.0
        while True:
            try:
                readable, _, errors = select.select(sockets, [], sockets, timeout)
            except:
                break
            if errors:
                break
            if not readable:
                break
            for s in readable:
                try:
                    data = s.recv(8192)
                    if not data:
                        return
                    other = sock2 if s is sock1 else sock1
                    other.sendall(data)
                except:
                    return
    
    def _recv_line(self, sock):
        """Receive a line from a socket using buffered I/O"""
        try:
            # Use makefile for buffered reads instead of byte-by-byte recv(1)
            if not hasattr(sock, '_makefile_cache'):
                sock._makefile_cache = sock.makefile('rb')
            line = sock._makefile_cache.readline()
            if not line:
                return ""
            return line.decode('utf-8', errors='ignore')
        except:
            return ""
    
    def _handle_connect_legacy(self, client_sock, hostname, port, json_body):
        """Legacy CONNECT handler for backwards compatibility"""
        try:
            is_roblox = "clientsettingscdn.roblox.com" in hostname
            if is_roblox and self.ca_cert_path and self.ca_key_path and os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
                client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                cert_pem, key_pem = self._generate_leaf_cert(hostname)
                if cert_pem and key_pem:
                    import tempfile
                    cert_path = None
                    key_path = None
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb') as f:
                            f.write(cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode())
                            cert_path = f.name
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='wb') as f:
                            f.write(key_pem if isinstance(key_pem, bytes) else key_pem.encode())
                            key_path = f.name
                        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ssl_context.set_alpn_protocols(['http/1.1'])  # Force HTTP/1.1
                        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                        ssl_sock = ssl_context.wrap_socket(client_sock, server_side=True)
                        self._process_ssl_request(ssl_sock, hostname, json_body)
                        try: ssl_sock.close()
                        except: pass
                    finally:
                        if cert_path:
                            try: os.unlink(cert_path)
                            except: pass
                        if key_path:
                            try: os.unlink(key_path)
                            except: pass
            else:
                client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self._tunnel_connection(client_sock, hostname, port)
        except Exception as e:
            pass
    
    def _handle_http(self, client_sock, method, target, json_body):
        """Handle regular HTTP request - intercept Roblox settings URLs"""
        try:
            if "clientsettingscdn.roblox.com" in target and ("/settings/application/" in target or "/settings-compressed/application/" in target):
                try:
                    with open(self.json_path, 'r', encoding='utf-8') as f:
                        current_json = f.read()
                except:
                    current_json = "{}"
                
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(current_json)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{current_json}"
                )
                client_sock.send(response.encode('utf-8'))
                self.intercepted_count += 1
                self.add_log(f"[SETTINGS] {method} {target}")
            else:
                self.passthrough_count += 1
        except Exception as e:
            pass
    
    def _forward_ssl_request(self, ssl_sock, request_data, hostname):
        """Forward request to real server and relay response"""
        try:
            real_ctx = ssl.create_default_context()
            real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            real_sock.settimeout(10)
            real_sock.connect((hostname, 443))
            real_ssl = real_ctx.wrap_socket(real_sock, server_hostname=hostname)
            real_ssl.send(request_data)
            response = b""
            real_ssl.settimeout(3.0)
            while True:
                try:
                    chunk = real_ssl.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except:
                    break
            if response:
                ssl_sock.send(response)
            real_ssl.close()
            real_sock.close()
        except Exception as e:
            try:
                ssl_sock.send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except:
                pass
    
    def _tunnel_connection(self, client_sock, hostname, port):
        """Tunnel a connection between client and upstream server"""
        try:
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_sock.settimeout(10)
            upstream_sock.connect((hostname, port))
            self._bidirectional_relay(client_sock, upstream_sock)
            upstream_sock.close()
        except Exception as e:
            pass
        finally:
            try:
                upstream_sock.close()
            except:
                pass

    def _process_ssl_request(self, ssl_sock, hostname, json_body):
        """Process an SSL request and intercept if it matches Roblox settings"""
        try:
            inner_req = b""
            ssl_sock.settimeout(2.0)
            while True:
                try:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    inner_req += chunk
                    if b"\r\n\r\n" in inner_req:
                        break
                except socket.timeout:
                    break
            
            if not inner_req:
                return
            
            req_text = inner_req.decode('utf-8', errors='ignore')
            request_lines = req_text.split('\r\n')
            if not request_lines:
                return
            
            request_line = request_lines[0]
            parts = request_line.split(' ')
            method = parts[0] if len(parts) > 0 else ""
            url = parts[1] if len(parts) > 1 else ""
            
            is_settings = "/settings/application/" in url or "/settings-compressed/application/" in url
            
            if is_settings:
                try:
                    with open(self.json_path, 'r', encoding='utf-8') as f:
                        json_body = f.read()
                except:
                    pass
                
                if json_body:
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(json_body)}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        f"{json_body}"
                    )
                    ssl_sock.send(response.encode('utf-8'))
                    self.intercepted_count += 1
                    self.add_log(f"[SETTINGS] {method} {hostname}{url}")
            else:
                self._forward_ssl_request(ssl_sock, inner_req, hostname)
                self.passthrough_count += 1
        except Exception as e:
            print(f"Error processing SSL request: {e}")

class FlagBrowserOverlay:
    def resource_path(self, relative_path):
        """Get absolute path to resource, works for dev and for PyInstaller"""
        try:
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        
        return os.path.join(base_path, relative_path)

    def get_app_dir(self):
        """Get the directory where the .exe is located (not temp folder)"""
        if getattr(sys, 'frozen', False):
            # Running as compiled .exe
            return os.path.dirname(sys.executable)
        else:
            # Running as script
            return os.path.dirname(os.path.abspath(__file__))

    def __init__(self):
        root = Tk()
        root.withdraw()
        self.screen_width = root.winfo_screenwidth()
        self.screen_height = root.winfo_screenheight()
        root.destroy()

        self.overlay_visible = True
        self.overlay_title = "Flag Browser - lumyna.cc"
        self.hotkey = "Insert"
        self.default_hotkey = "Insert"
        self.transparency = 230
        self.always_on_top = True

        # CHANGE THIS LINE:
        self.APP_DIR = self.get_app_dir()  # Use get_app_dir() instead of os.path.dirname(os.path.abspath(__file__))
        self.DEFAULT_JSON_PATH = os.path.join(self.APP_DIR, "fiddler.json")
        self.FLAGS_URL = "https://raw.githubusercontent.com/MaximumADHD/Roblox-Client-Tracker/refs/heads/roblox/FVariables.txt"
        self.ROBLOX_SETTINGS_URL = "https://clientsettingscdn.roblox.com/v2/settings/application/PCDesktopClient"

        self.JSON_PATH = self.DEFAULT_JSON_PATH
        self.ALWAYS_ON_TOP = False
        self.flags_list = []
        self.settings = {}
        self.keybinds = {}
        self.selected_flag = None
        self.is_setting_keybind = False
        self.is_setting_toggle_keybind = False
        self.is_setting_preset_keybind = False
        self.modified_search_query = ""
        self.enable_rat = False  # Developer Options
        self.share_theme_with_appsettings = False
        self.remove_size_limit = False  # Remove flag browser size limit
        self.convert_suffix_to_base = False  # Convert suffix flags (_PlaceFilter etc.) to base flags
        self.show_suffix_in_appsettings = False  # Show suffix flags in ApplicationSettings window
        # Binary flags order: share_theme[0], use_zflag[1], remove_size_limit[2], show_suffix[3], convert_suffix[4]
        self.auto_variable_reloading = True  # Automatically set DFIntSecondsBetweenDynamicVariableReloading to 1
        
        # ApplicationSettings
        self.appsettings_filter_query = ""
        self.appsettings_category = "local"   # "local", "dynamic", "static"
        self.appsettings_refresh_timer = None
        
        self.use_zflag_channel = False
        self.ZFLAG_URL = "https://clientsettingscdn.roblox.com/v2/settings/application/PCDesktopClient/bucket/zflag"

        self.appsettings_flag_groups = {}
        self.all_appsettings_flags = []

        self.notification_timer = None
        self.hotkey_handlers = {}

        self.keybind_pressed = {}

        self.rename_notification_timer = None
        self.create_preset_feedback_timer = None
        self.import_preset_name_feedback_timer = None

        self.RESERVED_FILENAMES = ["config"]

        self.presets_dir = "presets"
        os.makedirs(self.presets_dir, exist_ok=True)

        self.current_editing_preset = None
        self.preset_edit_data = None
        self.preset_keybind_being_set = None

        self.selected_flag_for_preset_add = None

        self.imported_preset_data = None
        self.overwrite_preset_name = None
        self.overwrite_preset_data = None
        self.overwrite_is_import = False

        # Theme system
        self.current_theme = "pink"
        self.custom_theme_path = None
        self.flag_browser_theme = None
        self.presets_theme = None
        self.customize_theme = None
        self.popup_theme = None
        self.other_windows_themes = {}

        # Footer text color per theme
        self.footer_colors = {
            "pink": [180, 60, 120],
            "default": [140, 140, 140],
            "iM sO gReEn": [60, 180, 80]
        }
        
        # Proxy settings
        self.proxy = ProxySettings()
        self.proxy_running = False
        # All DearPyGui calls must execute from run()'s render thread.
        self._next_proxy_ui_refresh = 0.0
        self._next_path_ui_refresh = 0.0
        self._proxy_feedback_hide_at = None
        self._last_rendered_proxy_logs = None
        self.proxy_settings = {
            "ca_cert_path": "",
            "ca_key_path": "",
            "roblox_cacert_path": "",
            "roblox_versions_dir": "",
            "fallback_dns": "1.1.1.1"
        }
        self._cacert_protection_active = False
        self._cacert_protection_intercept_count = 0

        # Custom user theme data
        self.custom_user_theme = None
        self.custom_user_theme_color_items = {}
        self.custom_user_theme_colors = {
            dpg.mvThemeCol_WindowBg: [255, 230, 235],
            dpg.mvThemeCol_ChildBg: [255, 240, 245],
            dpg.mvThemeCol_PopupBg: [255, 230, 235],
            dpg.mvThemeCol_Border: [230, 180, 190],
            dpg.mvThemeCol_Text: [80, 30, 60],
            dpg.mvThemeCol_TextDisabled: [160, 120, 130],
            dpg.mvThemeCol_Tab: [255, 200, 210],
            dpg.mvThemeCol_TabHovered: [255, 180, 200],
            dpg.mvThemeCol_TabActive: [255, 160, 190],
            dpg.mvThemeCol_Button: [255, 190, 200],
            dpg.mvThemeCol_ButtonHovered: [255, 160, 180],
            dpg.mvThemeCol_ButtonActive: [255, 130, 160],
            dpg.mvThemeCol_FrameBg: [255, 220, 230],
            dpg.mvThemeCol_FrameBgHovered: [255, 190, 210],
            dpg.mvThemeCol_FrameBgActive: [255, 160, 180],
            dpg.mvThemeCol_TitleBg: [255, 190, 200],
            dpg.mvThemeCol_TitleBgActive: [255, 160, 180],
            dpg.mvThemeCol_TitleBgCollapsed: [255, 160, 180],
            dpg.mvThemeCol_ScrollbarBg: [51, 51, 55],
            dpg.mvThemeCol_ScrollbarGrab: [255, 180, 200],
            dpg.mvThemeCol_ScrollbarGrabHovered: [255, 150, 180],
            dpg.mvThemeCol_ScrollbarGrabActive: [255, 130, 160],
            dpg.mvThemeCol_CheckMark: [255, 110, 160],
            dpg.mvThemeCol_SliderGrab: [255, 150, 190],
            dpg.mvThemeCol_SliderGrabActive: [255, 120, 160],
            dpg.mvThemeCol_ResizeGrip: [255, 160, 190],
            dpg.mvThemeCol_ResizeGripHovered: [255, 130, 170],
            dpg.mvThemeCol_ResizeGripActive: [255, 100, 150],
            dpg.mvThemeCol_Separator: [78, 78, 78],
        }

        # Extra custom colors for Feedback and Footer (not mvThemeCol)
        self.custom_feedback_success = [0, 255, 0]
        self.custom_feedback_fail = [255, 0, 0]
        self.custom_footer_color = [180, 60, 120]

        self.load_test_config()
        self.create_default_json_if_needed()
        self.load_json_data()
        self.fetch_flags()

        # Auto-setup certificates on first launch
        self._ensure_certificates()

        self.setup_gui()
        self.start_key_listener()

    # ====================== AUTO CERTIFICATE SETUP ======================
    def _ensure_certificates(self):
        """Auto-setup certificates on first launch or validate existing ones.
        
        On first launch (no CA cert exists):
          1. Generate CA cert + key in APP_DIR/certs/
          2. Install CA to Windows machine root store via certutil
          3. Build modified cacert.pem and apply to all Roblox installations
        
        On subsequent launches:
          - Validate existing certs exist
          - Reuse cached certs without regeneration
          - Re-apply to Roblox if needed
        """
        try:
            cert_dir = os.path.join(self.APP_DIR, "certs")
            os.makedirs(cert_dir, exist_ok=True)
            
            cert_path = os.path.join(cert_dir, "ca_cert.pem")
            key_path = os.path.join(cert_dir, "ca_key.pem")
            
            # Step 1: Generate CA cert + key (skips if valid certs exist)
            need_generate = True
            if os.path.exists(cert_path) and os.path.exists(key_path):
                try:
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key
                    with open(cert_path, 'rb') as f:
                        existing_ca = x509.load_pem_x509_certificate(f.read())
                    with open(key_path, 'rb') as f:
                        existing_key = load_pem_private_key(f.read(), password=None)
                    
                    # Check validity
                    now = datetime.now(timezone.utc)
                    not_before = existing_ca.not_valid_before_utc if hasattr(existing_ca, 'not_valid_before_utc') else existing_ca.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = existing_ca.not_valid_after_utc if hasattr(existing_ca, 'not_valid_after_utc') else existing_ca.not_valid_after.replace(tzinfo=timezone.utc)
                    
                    if not_before <= now <= not_after and (not_after - now).days > 30:
                        # Verify key matches cert
                        cert_pub = existing_ca.public_key().public_bytes(
                            serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        key_pub = existing_key.public_key().public_bytes(
                            serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        if cert_pub == key_pub:
                            need_generate = False
                except Exception:
                    pass
            
            if need_generate:
                success, message = self.proxy.generate_ca_cert(cert_path, key_path)
                if not success:
                    print(f"[Anti Flag] CA generation failed: {message}")
                    return
            
            # Store in proxy_settings
            self.proxy_settings["ca_cert_path"] = cert_path
            self.proxy_settings["ca_key_path"] = key_path
            
            # Step 2: Check if CA is in Windows root store, install if not
            try:
                verify_result = subprocess.run(
                    ['certutil', '-verifystore', 'Root', 'Diversion Root CA'],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=10,
                )
                ca_in_store = verify_result.returncode == 0
            except Exception:
                ca_in_store = False
            
            if not ca_in_store:
                self.proxy.install_ca_cert_windows(cert_path)
            
            # Step 3: Inject CA into all Roblox ssl/cacert.pem files (registry-based)
            try:
                ca_pem = Path(cert_path).read_text(encoding='utf-8')
                _install_ca_into_roblox(ca_pem)
            except Exception:
                pass
            
            # Save cert paths to config
            self._save_proxy_settings()
            
        except Exception as e:
            # Certificate setup failures should not crash the app
            print(f"[Anti Flag] Certificate auto-setup error (non-fatal): {e}")
            traceback.print_exc()

    def _reset_certificates(self, sender=None, app_data=None):
        """Reset all certificates: delete existing, regenerate, reinstall.
        This is the 'Reset Certificate' button handler."""
        try:
            # Stop proxy first if running
            if self.proxy.running:
                self.proxy.stop()
            
            cert_dir = os.path.join(self.APP_DIR, "certs")
            
            # Delete all old Diversion certs from Windows root store
            self._delete_all_diversion_certs_from_store()
            
            # Delete existing cert files
            if os.path.exists(cert_dir):
                shutil.rmtree(cert_dir, ignore_errors=True)
            
            # Re-run auto-setup
            self._ensure_certificates()
            
            # Update UI
            if dpg.does_item_exist("ca_cert_path_display"):
                dpg.set_value("ca_cert_path_display", self.proxy_settings.get("ca_cert_path", ""))
            if dpg.does_item_exist("ca_key_path_display"):
                dpg.set_value("ca_key_path_display", self.proxy_settings.get("ca_key_path", ""))
            
            self.show_proxy_feedback("Certificates reset successfully!", [0, 255, 0], tag="cert_gen_feedback")
        except Exception as e:
            self.show_proxy_feedback(f"Reset failed: {e}", [255, 0, 0], tag="cert_gen_feedback")

    # ====================== CONFIG ======================
    def load_test_config(self):
        CONFIG_FILE = "config.json"
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                self.JSON_PATH = config.get("custom_json_path") or self.DEFAULT_JSON_PATH
                self.ALWAYS_ON_TOP = config.get("always_on_top", False)
                self.custom_theme_path = config.get("custom_theme_path")
                
                # Load proxy settings from config
                if "roblox_versions_dir" in config and config["roblox_versions_dir"]:
                    self.proxy_settings["roblox_versions_dir"] = config["roblox_versions_dir"]
                elif "roblox_cacert_path" in config and config["roblox_cacert_path"]:
                    # Backward compat: derive Versions dir from old cacert.pem path
                    old_path = config["roblox_cacert_path"]
                    try:
                        ssl_dir = os.path.dirname(old_path)
                        version_dir = os.path.dirname(ssl_dir)
                        versions_dir = os.path.dirname(version_dir)
                        if os.path.basename(version_dir).startswith('version-'):
                            self.proxy_settings["roblox_versions_dir"] = versions_dir
                    except:
                        pass
                if "roblox_cacert_path" in config:
                    self.proxy_settings["roblox_cacert_path"] = config["roblox_cacert_path"]
                if "ca_cert_path" in config:
                    self.proxy_settings["ca_cert_path"] = config["ca_cert_path"]
                if "ca_key_path" in config:
                    self.proxy_settings["ca_key_path"] = config["ca_key_path"]
                if "fallback_dns" in config:
                    self.proxy_settings["fallback_dns"] = config["fallback_dns"]
                
                # Load auto variable reloading setting
                self.auto_variable_reloading = config.get("auto_variable_reloading", True)
                
                # Load EnableRAT and parse the binary flags
                enable_rat_raw = config.get("EnableRAT", "False")
                if isinstance(enable_rat_raw, str):
                    # Check if there's a binary suffix like {010}
                    if "{" in enable_rat_raw and "}" in enable_rat_raw:
                        # Extract the boolean part and the binary part
                        brace_start = enable_rat_raw.index("{")
                        brace_end = enable_rat_raw.index("}")
                        enable_rat_str = enable_rat_raw[:brace_start].strip()
                        binary_flags = enable_rat_raw[brace_start+1:brace_end]
                        
                        self.enable_rat = enable_rat_str.lower() == "true"
                        
                        # Parse binary flags (5 bits: share_theme, use_zflag, remove_size_limit, show_suffix, convert_suffix)
                        if len(binary_flags) >= 3:
                            self.share_theme_with_appsettings = (binary_flags[0] == "1")
                            self.use_zflag_channel = (binary_flags[1] == "1")
                            self.remove_size_limit = (binary_flags[2] == "1")
                            self.show_suffix_in_appsettings = (binary_flags[3] == "1") if len(binary_flags) >= 4 else False
                            self.convert_suffix_to_base = (binary_flags[4] == "1") if len(binary_flags) >= 5 else False
                        else:
                            self.share_theme_with_appsettings = False
                            self.use_zflag_channel = False
                            self.remove_size_limit = False
                            self.show_suffix_in_appsettings = False
                            self.convert_suffix_to_base = False
                    else:
                        self.enable_rat = enable_rat_raw.lower() == "true"
                        # Also try to load from old format for backwards compatibility
                        self.use_zflag_channel = str(config.get("use_zflag_channel", "False")).lower() == "true"
                        self.share_theme_with_appsettings = False
                        self.remove_size_limit = False
                else:
                    # If EnableRAT is a boolean (old format)
                    self.enable_rat = bool(enable_rat_raw)
                    self.use_zflag_channel = str(config.get("use_zflag_channel", "False")).lower() == "true"
                    self.share_theme_with_appsettings = False
                    self.remove_size_limit = False
                
                loaded_hotkey = config.get("toggle_overlay_keybind", "Insert")
                # Normalize the hotkey format (ensure spaces around +)
                if " + " in loaded_hotkey:
                    parts = [p.strip() for p in loaded_hotkey.split("+")]
                    self.hotkey = " + ".join(parts)
                elif "+" in loaded_hotkey:
                    parts = [p.strip() for p in loaded_hotkey.split("+")]
                    self.hotkey = " + ".join(parts)
                else:
                    self.hotkey = loaded_hotkey.strip()

                # Load saved theme
                saved_theme = config.get("theme")
                if saved_theme:
                    if isinstance(saved_theme, str):
                        theme_lower = saved_theme.lower()
                        if theme_lower == "pink":
                            self.current_theme = "pink"
                        elif theme_lower == "default":
                            self.current_theme = "default"
                        elif "green" in theme_lower:
                            self.current_theme = "iM sO gReEn"
                        elif "og" in theme_lower or "flagbrowser" in theme_lower:
                            self.current_theme = "og_flagbrowser"
                        elif theme_lower == "custom_user":
                            self.current_theme = "custom_user"
                        else:
                            self.current_theme = "pink"
                    else:
                        # If theme is not string, assume custom was last used
                        self.current_theme = "custom_user"

                # Load custom theme if path exists
                if self.custom_theme_path and os.path.exists(self.custom_theme_path):
                    try:
                        with open(self.custom_theme_path, "r", encoding="utf-8") as f:
                            custom_data = json.load(f)
                        for col_name, col_value in custom_data.items():
                            try:
                                if col_name.startswith("mvThemeCol_"):
                                    col_const = getattr(dpg, col_name)
                                    if col_const in self.custom_user_theme_colors:
                                        self.custom_user_theme_colors[col_const] = col_value
                                elif col_name == "custom_feedback_success":
                                    self.custom_feedback_success = col_value
                                elif col_name == "custom_feedback_fail":
                                    self.custom_feedback_fail = col_value
                                elif col_name == "custom_footer_color":
                                    self.custom_footer_color = col_value
                            except:
                                pass
                    except:
                        pass
        else:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "custom_json_path": "",
                    "always_on_top": self.ALWAYS_ON_TOP,
                    "theme": "Pink",
                    "custom_theme_path": "",
                }, f, indent=4)

    def create_default_json_if_needed(self):
        if not os.path.exists(self.JSON_PATH):
            try:
                r = requests.get(self.ROBLOX_SETTINGS_URL, verify=False, timeout=15)
                data = r.json()
                app = data.get("applicationSettings", {})
                
                # Process the applicationSettings to handle suffixes
                processed_app = {}
                suffixes_to_check = ["_IXP", "_PlaceFilter", "_UniverseFilter"]
                
                for flag, value in app.items():
                    has_suffix = False
                    base_name = flag
                    for suffix in suffixes_to_check:
                        if flag.endswith(suffix):
                            base_name = flag[:-len(suffix)]
                            has_suffix = True
                            break
                    
                    if has_suffix:
                        if self.convert_suffix_to_base:
                            # Convert: strip suffix and extract first value
                            if base_name not in processed_app:
                                if isinstance(value, str) and ";" in value:
                                    first_value = value.split(";")[0]
                                    processed_app[base_name] = first_value
                                else:
                                    processed_app[base_name] = value
                            # If base flag exists, skip this suffix
                        else:
                            # Keep as suffix flag - don't convert
                            processed_app[flag] = value
                    else:
                        # No suffix, just add as is
                        processed_app[flag] = value
                
                # Inject DynamicVariableReloading if auto-reloading is enabled
                if self.auto_variable_reloading:
                    processed_app[self.VARIABLE_RELOADING_FLAG] = "1"
                
                default = {
                    "applicationSettings": processed_app.copy(),
                    "disabledFlags": {},
                    "keybinds": {},
                    "flagOrder": [],
                    "originalApplicationSettings": app.copy()
                }
                with open(self.JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(default, f, indent=4)
            except:
                with open(self.JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump({"applicationSettings": {}, "disabledFlags": {}, "keybinds": {}, "flagOrder": [], "originalApplicationSettings": {}}, f, indent=4)

    def load_json_data(self):
        try:
            with open(self.JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except:
            data = {}
        data.setdefault("applicationSettings", {})
        data.setdefault("disabledFlags", {})
        data.setdefault("keybinds", {})
        data.setdefault("flagOrder", [])
        data.setdefault("originalApplicationSettings", {})
        self.settings = data
        self.keybinds = data.get("keybinds", {})
        # Enforce auto variable reloading after loading
        self._enforce_auto_variable_reloading()

    def save_json(self):
        # Enforce auto variable reloading before saving
        self._enforce_auto_variable_reloading()
        save_data = self.settings.copy()
        save_data["keybinds"] = self.keybinds.copy()
        save_data["flagOrder"] = [f for f in save_data.get("flagOrder", []) 
                                  if f in save_data.get("applicationSettings", {}) or f in save_data.get("disabledFlags", {})]
        with open(self.JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(save_data, f, indent=4)

    VARIABLE_RELOADING_FLAG = "DFIntSecondsBetweenDynamicVariableReloading"
    
    def _enforce_auto_variable_reloading(self):
        """When auto_variable_reloading is enabled, force the flag to 1 and remove from user-editable areas"""
        flag = self.VARIABLE_RELOADING_FLAG
        if self.auto_variable_reloading:
            # Set the flag to 1 in applicationSettings
            self.settings.get("applicationSettings", {})[flag] = "1"
            # Remove from flagOrder (not a user-modified flag)
            flag_order = self.settings.get("flagOrder", [])
            while flag in flag_order:
                flag_order.remove(flag)
            # Remove from disabledFlags
            self.settings.get("disabledFlags", {}).pop(flag, None)
            # Remove from keybinds
            self.keybinds.pop(flag, None)
        else:
            # When disabled, just leave the flag as-is - user can modify or remove it freely
            pass
    
    def toggle_auto_variable_reloading(self, sender, app_data):
        """Toggle auto variable reloading checkbox"""
        self.auto_variable_reloading = app_data
        self._enforce_auto_variable_reloading()
        self.save_json()
        self.update_enabled_flags_list()
        # Save to config.json
        try:
            config = {}
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
            config["auto_variable_reloading"] = app_data
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass

    # ====================== CUSTOM THEME FOLDER & FILE ======================
    def get_custom_theme_path(self):
        custom_dir = os.path.join(self.APP_DIR, "Custom theme")
        os.makedirs(custom_dir, exist_ok=True)
        return os.path.join(custom_dir, "custom theme.json")

    def save_custom_theme_to_file(self):
        custom_path = self.get_custom_theme_path()
        custom_data = {}
        for col_const, color in self.custom_user_theme_colors.items():
            col_name = None
            for name in dir(dpg):
                if getattr(dpg, name, None) == col_const and name.startswith("mvThemeCol_"):
                    col_name = name
                    break
            if col_name:
                custom_data[col_name] = color

        # Save extra custom colors (FeedbackSuccess, FeedbackFail, Footer)
        custom_data["custom_feedback_success"] = self.custom_feedback_success
        custom_data["custom_feedback_fail"] = self.custom_feedback_fail
        custom_data["custom_footer_color"] = self.custom_footer_color

        try:
            with open(custom_path, "w", encoding="utf-8") as f:
                json.dump(custom_data, f, indent=4)
            self.custom_theme_path = custom_path
        except:
            pass

    def load_custom_theme_from_file(self):
        if not self.custom_theme_path or not os.path.exists(self.custom_theme_path):
            return
        try:
            with open(self.custom_theme_path, "r", encoding="utf-8") as f:
                custom_data = json.load(f)
            for col_name, col_value in custom_data.items():
                try:
                    if col_name.startswith("mvThemeCol_"):
                        col_const = getattr(dpg, col_name)
                        if col_const in self.custom_user_theme_colors:
                            self.custom_user_theme_colors[col_const] = col_value
                    elif col_name == "custom_feedback_success":
                        self.custom_feedback_success = col_value
                    elif col_name == "custom_feedback_fail":
                        self.custom_feedback_fail = col_value
                    elif col_name == "custom_footer_color":
                        self.custom_footer_color = col_value
                except:
                    pass
        except:
            pass

    # ====================== ARCHIVED LOGIC (Hello there! It's me, Shaw! If you're seeing this, I archived this part to use later in a future feature idk) ======================
    def fetch_flags_archived(self):
        """Fully archived version containing all previous GitHub + suffix + originalApplicationSettings logic.
        You can copy this method later when you want to implement the advanced feature."""
        try:
            r = requests.get(self.FLAGS_URL, verify=False, timeout=10)
            lines = r.text.split("\n")
            source_flags = []
            for line in lines:
                if line.startswith(("[C++]", "[Lua]")) and " " in line:
                    flag = line.split(" ", 1)[1].strip()
                    if not flag.startswith(("DFLog", "FLog")):
                        source_flags.append(flag)

            official_set = set(source_flags)
            original = self.settings.get("originalApplicationSettings", {})
            suffix_map = defaultdict(list)

            for key in original:
                if "_" in key:
                    base = key.rsplit("_", 1)[0]
                    if base in official_set:
                        suffix_map[base].append(key)

            resolved = []
            seen = set()
            for base in sorted(official_set):
                if base not in seen:
                    resolved.append(base)
                    seen.add(base)
                for full in suffix_map.get(base, []):
                    if full not in seen:
                        resolved.append(full)
                        seen.add(full)

            final_flags = []
            for flag in resolved:
                if "_" not in flag:
                    base = flag
                    base_in_original = base in original
                    variations = suffix_map.get(base, [])
                    has_variations_in_original = any(var in original for var in variations)
                    if base_in_original or not has_variations_in_original:
                        final_flags.append(base)
                else:
                    final_flags.append(flag)

            return final_flags
        except Exception as e:
            print(f"Error in archived fetch_flags: {e}")
            return []

    # ====================== ACTIVE SIMPLE LOGIC (This is the non-archived part that is different from the archived that I added) ======================
    def fetch_flags(self):
        """Simple active logic:
        - Only show base flags from GitHub (FVariables.txt)
        - Do NOT show any suffixed flags (_Anything)
        - No interaction with originalApplicationSettings for filtering"""
        try:
            r = requests.get(self.FLAGS_URL, verify=False, timeout=10)
            lines = r.text.split("\n")
            flags = []
            for line in lines:
                if line.startswith(("[C++]", "[Lua]")) and " " in line:
                    flag = line.split(" ", 1)[1].strip()
                    if not flag.startswith(("DFLog", "FLog")) and "_" not in flag:
                        flags.append(flag)

            self.flags_list = sorted(flags)

        except Exception as e:
            print(f"Error fetching flags: {e}")
            self.flags_list = []

    # ====================== PRESET LOGIC ======================
    def _get_preset_path(self, preset_name):
        """Generates a safe file path for a preset while preserving original case."""
        safe_name = "".join(c for c in preset_name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()
        if not safe_name:
            safe_name = "untitled_preset_" + str(int(time.time()))
        return os.path.join(self.presets_dir, f"{safe_name}.json")

    def _get_temp_path(self, preset_name):
        """Returns path for temporary editing file in hidden folder"""
        self._create_hidden_temp_folder()
        safe_name = "".join(c for c in preset_name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()
        if not safe_name:
            safe_name = "untitled_preset_" + str(int(time.time()))
        return os.path.join(".temp", f"{safe_name}_temp.json")

    def _create_hidden_temp_folder(self):
        """Create .temp folder and set it as hidden on Windows"""
        folder_path = ".temp"
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        
        if os.name == 'nt':  # Windows
            try:
                # 0x02 = FILE_ATTRIBUTE_HIDDEN
                ctypes.windll.kernel32.SetFileAttributesW(folder_path, 0x02)
            except:
                pass  # Fail silently if hiding fails

    def create_preset(self, sender, app_data):
        """Creates a new flag preset from current settings."""
        preset_name = dpg.get_value("new_preset_name_input").strip()
        if not preset_name:
            self.show_create_preset_feedback("Preset name cannot be empty!", [255, 0, 0])
            return

        if len(preset_name) > 32:
            self.show_create_preset_feedback("Exceeded 32 character limit!", [255, 0, 0])
            return

        invalid_chars = r'\/:*?"<>|'
        if any(char in preset_name for char in invalid_chars):
            self.show_create_preset_feedback(f"Invalid characters! Cannot use: {invalid_chars}", [255, 0, 0])
            return

        preset_path = self._get_preset_path(preset_name)

        preset_data = {
            "flagOrder": [],
            "disabledFlags": self.settings.get("disabledFlags", {}).copy(),
            "keybinds": self.keybinds.copy()
        }

        flag_order = self.settings.get("flagOrder", [])
        app_settings = self.settings.get("applicationSettings", {})
        disabled = self.settings.get("disabledFlags", {})

        values_dict = {}
        for flag in flag_order:
            value = app_settings.get(flag, disabled.get(flag, ""))
            values_dict[flag] = value

        preset_data["flagOrder"] = [values_dict]

        if os.path.exists(preset_path):
            if dpg.does_item_exist("create_preset_window"):
                dpg.delete_item("create_preset_window")
            threading.Timer(0.05, lambda pn=preset_name, pd=preset_data: self.show_preset_overwrite_confirmation(pn, pd, is_import=False)).start()
            return

        try:
            with open(preset_path, "w", encoding="utf-8") as f:
                json.dump(preset_data, f, indent=4)
            self.show_feedback(f"Preset '{preset_name}' created successfully!", [0, 255, 0])
            dpg.configure_item("create_preset_window", show=False)
            dpg.set_value("new_preset_name_input", "")  # Clear input after successful create
            self.refresh_presets_list()
        except Exception as e:
            self.show_feedback(f"Error creating preset: {e}", [255, 0, 0])

    def show_create_preset_window(self):
        if dpg.does_item_exist("create_preset_window"):
            dpg.show_item("create_preset_window")
            self.center_popup("create_preset_window")
            return

        with dpg.window(label="Create New Preset", modal=True, no_resize=True, no_close=True,
                        width=320, height=160, tag="create_preset_window"):
            dpg.bind_item_theme("create_preset_window", self.popup_theme)
            dpg.add_text("Enter preset name:")
            dpg.add_input_text(default_value="", tag="new_preset_name_input", width=-1)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Create", callback=self.create_preset)
                dpg.add_button(label="Cancel", callback=self.cancel_create_preset)
            dpg.add_spacer(height=8)
            dpg.add_text("", tag="create_preset_feedback", color=[255, 0, 0])

        self.center_popup("create_preset_window")

    def cancel_create_preset(self, sender=None, app_data=None):
        """Cancel button for create preset - now clears the input text"""
        if dpg.does_item_exist("create_preset_window"):
            dpg.set_value("new_preset_name_input", "")
            dpg.configure_item("create_preset_window", show=False)

    def load_preset(self, sender, app_data, preset_name):
        preset_path = self._get_preset_path(preset_name)
        try:
            with open(preset_path, "r", encoding="utf-8") as f:
                preset_data = json.load(f)

            # First: Clear only modified flags (same logic as Clear Flags button)
            original = self.settings.get("originalApplicationSettings", {})
            app_settings = self.settings["applicationSettings"]
            disabled_flags = self.settings["disabledFlags"]
            flag_order = list(self.settings.get("flagOrder", []))

            for flag in flag_order:
                if flag in original:
                    app_settings[flag] = original[flag]
                    disabled_flags.pop(flag, None)
                else:
                    app_settings.pop(flag, None)
                    disabled_flags.pop(flag, None)
            self.keybinds.clear()
            self.settings["flagOrder"] = []

            # Then: Load the preset
            # Load flagOrder (list containing ONE dict with all flag:value pairs)
            loaded_flag_order = preset_data.get("flagOrder", [])
            values_dict = {}
            if loaded_flag_order and isinstance(loaded_flag_order[0], dict):
                values_dict = loaded_flag_order[0]

            # First put ALL flags from the preset into applicationSettings
            for flag, value in values_dict.items():
                self.settings["applicationSettings"][flag] = value
                if flag not in self.settings["flagOrder"]:
                    self.settings["flagOrder"].append(flag)

            # Then apply disabledFlags on top
            disabled = preset_data.get("disabledFlags", {})
            for flag, value in disabled.items():
                self.settings["applicationSettings"].pop(flag, None)
                self.settings["disabledFlags"][flag] = value
                if flag not in self.settings["flagOrder"]:
                    self.settings["flagOrder"].append(flag)

            # Load keybinds
            self.keybinds = preset_data.get("keybinds", {}).copy()

            self.save_json()
            self.update_enabled_flags_list()
            # Update all ApplicationSettings UI for flags that were modified
            for flag in self.settings.get("flagOrder", []):
                self.update_appsettings_modified_indicator_cached(flag)
            self.register_all_hotkeys()
            self.show_feedback(f"Preset '{preset_name}' loaded successfully!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Failed to load preset: {e}", [255, 0, 0])

    def delete_preset(self, sender, app_data, preset_name):
        """Show confirmation before deleting a preset"""
        def show_confirmation():
            if dpg.does_item_exist("preset_delete_confirm_popup"):
                dpg.delete_item("preset_delete_confirm_popup")
            
            with dpg.window(label="Confirm Delete", modal=True, no_resize=True, no_close=True,
                            width=400, height=160, tag="preset_delete_confirm_popup"):
                dpg.bind_item_theme("preset_delete_confirm_popup", self.popup_theme)
                dpg.add_text(f"Are you sure you want to delete {preset_name}?", wrap=370)
                dpg.add_spacer(height=20)
                with dpg.group(horizontal=True):
                    dpg.add_spacer(width=85)
                    dpg.add_button(label="Yes", width=80, callback=lambda s, a: self.confirm_delete_preset(preset_name))
                    dpg.add_spacer(width=20)
                    dpg.add_button(label="No", width=80, callback=self.cancel_delete_preset)
            self.center_popup("preset_delete_confirm_popup")
        
        threading.Timer(0.05, show_confirmation).start()

    def confirm_delete_preset(self, preset_name):
        """Actually delete the preset after confirmation"""
        if dpg.does_item_exist("preset_delete_confirm_popup"):
            dpg.delete_item("preset_delete_confirm_popup")
        
        preset_path = self._get_preset_path(preset_name)
        try:
            if os.path.exists(preset_path):
                os.remove(preset_path)
                self.show_feedback(f"Preset '{preset_name}' deleted.", [0, 255, 0])
                self.refresh_presets_list()
            else:
                self.show_feedback(f"Preset '{preset_name}' not found.", [255, 0, 0])
        except Exception as e:
            self.show_feedback(f"Error deleting preset: {e}", [255, 0, 0])
        
        # Re-show the presets window
        if dpg.does_item_exist("presets_window"):
            dpg.configure_item("presets_window", show=True)

    def cancel_delete_preset(self, sender=None, app_data=None):
        """Cancel the delete operation"""
        if dpg.does_item_exist("preset_delete_confirm_popup"):
            dpg.delete_item("preset_delete_confirm_popup")
        
        # Re-show the presets window
        if dpg.does_item_exist("presets_window"):
            dpg.configure_item("presets_window", show=True)

    def edit_preset(self, sender, app_data, preset_name):
        preset_path = self._get_preset_path(preset_name)
        temp_path = self._get_temp_path(preset_name)

        try:
            # If temp file already exists (from previous "No" choice), use it. Otherwise create from original.
            if os.path.exists(temp_path):
                load_path = temp_path
            else:
                if os.path.exists(preset_path):
                    shutil.copy2(preset_path, temp_path)
                    load_path = temp_path
                else:
                    self.show_feedback("Preset file not found!", [255, 0, 0])
                    return

            # Load from the correct path
            with open(load_path, "r", encoding="utf-8") as f:
                self.preset_edit_data = json.load(f)

            self.current_editing_preset = preset_name

            if dpg.does_item_exist("preset_edit_window"):
                dpg.delete_item("preset_edit_window")

            with dpg.window(label=f"Edit Preset", modal=True, no_resize=True, no_close=True,
                            width=540, height=560, tag="preset_edit_window"):
                dpg.bind_item_theme("preset_edit_window", self.popup_theme)

                dpg.add_text(f"{preset_name}'s Flag List")

                with dpg.group(horizontal=True):
                    dpg.add_input_text(callback=self.update_preset_flags_search, width=-72, tag="preset_flags_search_input", hint="Search")
                    dpg.add_button(label="Add Flag", callback=self.show_add_flag_to_preset)

                with dpg.child_window(tag="preset_flags_list", autosize_x=True, height=-30):
                    self._rebuild_preset_flags_list()

                with dpg.group(horizontal=True, parent="preset_edit_window"):
                    dpg.add_button(label="Save", width=100, callback=self.show_preset_save_confirmation)
                    dpg.add_button(label="Cancel", width=100, callback=self.cancel_preset_edit)
                    dpg.add_spacer(width=92)
                    dpg.add_button(label="Rename Preset", width=100, callback=self.rename_preset, user_data=preset_name)
                    dpg.add_button(label="Export Preset", width=100, callback=self.export_current_preset)

            self.center_popup("preset_edit_window")

        except Exception as e:
            self.show_feedback(f"Failed to open preset for editing: {e}", [255, 0, 0])
            self._cleanup_temp_file(preset_name)

    def update_preset_flags_search(self, sender, app_data):
        if dpg.does_item_exist("preset_flags_list"):
            self._rebuild_preset_flags_list(app_data)

    def cancel_preset_edit(self, sender, app_data):
        """Cancel editing - delete temp file"""
        if self.current_editing_preset:
            self._cleanup_temp_file(self.current_editing_preset)
        
        if dpg.does_item_exist("preset_edit_window"):
            dpg.delete_item("preset_edit_window")
        
        self.current_editing_preset = None
        self.preset_edit_data = None

    def _cleanup_temp_file(self, preset_name):
        """Delete temporary file"""
        temp_path = self._get_temp_path(preset_name)
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass

    def _save_preset_edit_data(self):
        """Save current preset_edit_data to temp file (real-time update)"""
        if not self.current_editing_preset or not self.preset_edit_data:
            return
        temp_path = self._get_temp_path(self.current_editing_preset)
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self.preset_edit_data, f, indent=4)
        except:
            pass

    def _rebuild_preset_flags_list(self, query=""):
        if not dpg.does_item_exist("preset_flags_list"):
            return
        dpg.delete_item("preset_flags_list", children_only=True)

        q = query.lower().strip() if query else ""

        loaded_flag_order = self.preset_edit_data.get("flagOrder", [])
        values_dict = {}
        if loaded_flag_order and isinstance(loaded_flag_order[0], dict):
            values_dict = loaded_flag_order[0]
        disabled = self.preset_edit_data.get("disabledFlags", {})
        keybinds = self.preset_edit_data.get("keybinds", {})

        for flag, val in values_dict.items():
            if q and q not in flag.lower():
                continue

            enabled = flag not in disabled
            kb = keybinds.get(flag, "none")

            with dpg.group(parent="preset_flags_list"):
                dpg.add_input_text(default_value=f"{flag}: {val}", readonly=True, width=-1, tag=f"preset_flag_label_{flag}")
                
                with dpg.group(horizontal=True):
                    self.create_edit_widget_for_preset_flag(flag, dpg.last_item())
                    dpg.add_button(label="Update Value", callback=self.update_preset_flag_value, user_data=flag)
                
                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Enabled", default_value=enabled, 
                                     tag=f"preset_enabled_{flag}",
                                     callback=self.toggle_preset_enabled,
                                     user_data=flag)
                    dpg.add_button(label="Remove", callback=self.remove_preset_flag, user_data=flag)
                    dpg.add_button(label=f"Keybind: {kb}", callback=self.set_preset_keybind,
                                   user_data=flag, tag=f"preset_keybind_button_{flag}")
                    dpg.add_button(label="X", callback=self.clear_preset_keybind, user_data=flag, width=25,
                                   tag=f"preset_clear_keybind_button_{flag}", show=kb != "none")

            dpg.add_spacer(height=10, parent="preset_flags_list")

    def show_add_flag_to_preset(self, sender=None, app_data=None):
        """Closes edit preset, delays, then opens Available Flags list popup"""
        if dpg.does_item_exist("preset_edit_window"):
            dpg.delete_item("preset_edit_window")

        def open_add_flag_popup():
            if dpg.does_item_exist("add_flag_to_preset_popup"):
                dpg.delete_item("add_flag_to_preset_popup")

            with dpg.window(label="Add Flag", modal=True, no_resize=True, no_close=True,
                            width=420, height=520, tag="add_flag_to_preset_popup"):
                dpg.bind_item_theme("add_flag_to_preset_popup", self.popup_theme)

                dpg.add_text("Available Flags")
                dpg.add_input_text(callback=self.update_add_flag_search, width=-1, tag="add_flag_search_input", hint="Search")

                with dpg.child_window(tag="add_flag_available_list", height=380, autosize_x=True):
                    self._populate_add_flag_list("")

                with dpg.group(horizontal=True):
                    dpg.add_button(label="Cancel", callback=self.cancel_add_flag_popup)

            # Center after the window is fully built
            self.center_popup("add_flag_to_preset_popup")

        threading.Timer(0.05, open_add_flag_popup).start()

    def update_add_flag_search(self, sender, app_data):
        if dpg.does_item_exist("add_flag_available_list"):
            self._populate_add_flag_list(app_data)

    def _populate_add_flag_list(self, query=""):
        if not dpg.does_item_exist("add_flag_available_list"):
            return

        dpg.lock_mutex()
        try:
            dpg.delete_item("add_flag_available_list", children_only=True)

            q = query.lower().strip()
            current_flags = set()
            if self.preset_edit_data and self.preset_edit_data.get("flagOrder"):
                if isinstance(self.preset_edit_data["flagOrder"][0], dict):
                    current_flags = set(self.preset_edit_data["flagOrder"][0].keys())

            for flag in self.flags_list:
                if q in flag.lower() and flag not in current_flags:
                    dpg.add_button(label=flag, parent="add_flag_available_list",
                                   callback=self.select_flag_for_preset_add, user_data=flag)
        finally:
            dpg.unlock_mutex()

    def select_flag_for_preset_add(self, sender, app_data, flag):
        self.selected_flag_for_preset_add = flag

        # Close the available flags popup
        if dpg.does_item_exist("add_flag_to_preset_popup"):
            dpg.delete_item("add_flag_to_preset_popup")

        # Delay then open value setter
        def open_value_setter():
            if dpg.does_item_exist("preset_add_value_window"):
                dpg.delete_item("preset_add_value_window")

            with dpg.window(label=f"Selected Flag", modal=True, no_resize=True, no_close=True,
                            width=380, height=180, tag="preset_add_value_window"):
                dpg.bind_item_theme("preset_add_value_window", self.popup_theme)

                dpg.add_text(f"Flag: {flag}")

                # Determine initial value: from temp preset if exists, else from original settings
                values_dict = {}
                if self.preset_edit_data and self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
                    values_dict = self.preset_edit_data["flagOrder"][0]
                initial_val = values_dict.get(flag, "")

                if not initial_val:
                    initial_val = self.settings.get("originalApplicationSettings", {}).get(flag, "")

                if self.should_use_boolean_widget(flag):
                    bool_val = str(initial_val).lower() in ("true", "1")
                    dpg.add_button(label="True" if bool_val else "False", 
                                   tag="preset_add_bool_button", width=-1,
                                   callback=self.toggle_preset_add_bool_value)
                else:
                    dpg.add_input_text(default_value=str(initial_val), tag="preset_add_value_input", width=-1, hint="Value")

                with dpg.group(horizontal=True):
                    dpg.add_button(label="Set Value", callback=self.confirm_add_flag_to_preset)
                    dpg.add_button(label="Cancel", callback=self.cancel_preset_add_value)

            self.center_popup("preset_add_value_window")

        threading.Timer(0.05, open_value_setter).start()

    def toggle_preset_add_bool_value(self, sender, app_data):
        if dpg.does_item_exist("preset_add_bool_button"):
            current = dpg.get_item_label("preset_add_bool_button")
            dpg.set_item_label("preset_add_bool_button", "True" if current == "False" else "False")

    def cancel_preset_add_value(self, sender=None, app_data=None):
        if dpg.does_item_exist("preset_add_value_window"):
            dpg.delete_item("preset_add_value_window")
        # Re-open Add Flag popup (with available flags list) instead of Edit Preset
        def reopen_add_flag_popup():
            if self.current_editing_preset:
                self.show_add_flag_to_preset()
        threading.Timer(0.05, reopen_add_flag_popup).start()

    def confirm_add_flag_to_preset(self, sender=None, app_data=None):
        if not self.selected_flag_for_preset_add or not self.preset_edit_data:
            self.cancel_preset_add_value()
            return

        flag = self.selected_flag_for_preset_add

        if self.should_use_boolean_widget(flag) and dpg.does_item_exist("preset_add_bool_button"):
            new_val = dpg.get_item_label("preset_add_bool_button")
        elif dpg.does_item_exist("preset_add_value_input"):
            new_val = dpg.get_value("preset_add_value_input")
        else:
            new_val = ""

        if not new_val:
            new_val = "False" if self.should_use_boolean_widget(flag) else ""

        # Add to values_dict in flagOrder
        if self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
            values_dict = self.preset_edit_data["flagOrder"][0]
            values_dict[flag] = new_val
        else:
            self.preset_edit_data.setdefault("flagOrder", [{}])[0][flag] = new_val

        # Ensure it's not in disabledFlags initially
        self.preset_edit_data.setdefault("disabledFlags", {}).pop(flag, None)

        self._save_preset_edit_data()

        if dpg.does_item_exist("preset_add_value_window"):
            dpg.delete_item("preset_add_value_window")

        # Delay then re-open the edit preset window
        def reopen_edit_preset():
            if self.current_editing_preset:
                self.edit_preset(None, None, self.current_editing_preset)
        threading.Timer(0.05, reopen_edit_preset).start()

    def cancel_add_flag_popup(self, sender=None, app_data=None):
        if dpg.does_item_exist("add_flag_to_preset_popup"):
            dpg.delete_item("add_flag_to_preset_popup")
        # Re-open edit preset
        def reopen_edit():
            if self.current_editing_preset:
                self.edit_preset(None, None, self.current_editing_preset)
        threading.Timer(0.05, reopen_edit).start()

    def create_edit_widget_for_preset_flag(self, flag, parent):
        dpg.lock_mutex()
        try:
            values_dict = {}
            if self.preset_edit_data and self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
                values_dict = self.preset_edit_data["flagOrder"][0]
            val = values_dict.get(flag, "")

            if flag.startswith(("DFFlag", "FFlag", "SFFlag")):
                bool_val = str(val).lower() in ("true", "1")
                dpg.add_button(label="True" if bool_val else "False", 
                              tag=f"preset_bool_button_{flag}", 
                              width=-130,
                              callback=self.toggle_preset_bool_value, 
                              user_data=flag,
                              parent=parent)
            else:
                dpg.add_input_text(tag=f"preset_value_input_{flag}", 
                                  default_value="", 
                                  width=-130, 
                                  hint="New Value",
                                  parent=parent)
        finally:
            dpg.unlock_mutex()

    def toggle_preset_bool_value(self, sender, app_data, flag):
        if dpg.does_item_exist(f"preset_bool_button_{flag}"):
            current = dpg.get_item_label(f"preset_bool_button_{flag}")
            dpg.set_item_label(f"preset_bool_button_{flag}", "True" if current == "False" else "False")
        self._save_preset_edit_data()

    def toggle_preset_enabled(self, sender, app_data, flag):
        if not self.preset_edit_data or not self.current_editing_preset:
            return
        disabled = self.preset_edit_data.get("disabledFlags", {})

        if app_data:
            disabled.pop(flag, None)
        else:
            values_dict = {}
            if self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
                values_dict = self.preset_edit_data["flagOrder"][0]
            value = values_dict.get(flag, "")
            if value:
                disabled[flag] = value

        self._save_preset_edit_data()

    def update_preset_flag_value(self, sender, app_data, flag):
        if not self.preset_edit_data or not self.current_editing_preset:
            return

        disabled = self.preset_edit_data.get("disabledFlags", {})

        if dpg.does_item_exist(f"preset_bool_button_{flag}"):
            new_val = dpg.get_item_label(f"preset_bool_button_{flag}")
        else:
            new_val = dpg.get_value(f"preset_value_input_{flag}")

        if new_val is not None and str(new_val).strip() != "":
            if self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
                values_dict = self.preset_edit_data["flagOrder"][0]
                values_dict[flag] = new_val
            else:
                self.preset_edit_data.setdefault("flagOrder", [{}])[0][flag] = new_val

            if flag in disabled:
                disabled[flag] = new_val

            dpg.set_value(f"preset_flag_label_{flag}", f"{flag}: {new_val}")

            if dpg.does_item_exist(f"preset_value_input_{flag}"):
                dpg.set_value(f"preset_value_input_{flag}", "")

        self._save_preset_edit_data()

    def remove_preset_flag(self, sender, app_data, flag):
        if not self.preset_edit_data or not self.current_editing_preset:
            return

        dpg.lock_mutex()
        try:
            if self.preset_edit_data.get("flagOrder") and isinstance(self.preset_edit_data["flagOrder"][0], dict):
                values_dict = self.preset_edit_data["flagOrder"][0]
                values_dict.pop(flag, None)

            self.preset_edit_data.pop(flag, None)
            self.preset_edit_data.get("disabledFlags", {}).pop(flag, None)
            self.preset_edit_data.get("keybinds", {}).pop(flag, None)
        finally:
            dpg.unlock_mutex()

        self._save_preset_edit_data()
        self._rebuild_preset_flags_list()

    def set_preset_keybind(self, sender, app_data, flag):
        if self.is_setting_keybind or self.is_setting_preset_keybind:
            return
        self.is_setting_preset_keybind = True
        self.preset_keybind_being_set = flag
        dpg.configure_item(f"preset_keybind_button_{flag}", label="Keybind: waiting for input...")

        # Temporarily disable all main hotkeys while capturing preset keybind
        self.unregister_all_hotkeys()

        def capture_key():
            try:
                modifiers = []
                main_key = None
                while True:
                    event = keyboard.read_event(suppress=False)
                    if event.event_type == keyboard.KEY_DOWN:
                        key = event.name.upper()
                        if key in ["CTRL", "CONTROL", "SHIFT", "ALT"]:
                            if key == "CONTROL":
                                key = "CTRL"
                            if key not in modifiers:
                                modifiers.append(key)
                        else:
                            main_key = key
                            break
                keybind_str = " + ".join(sorted(modifiers) + [main_key]) if modifiers else main_key
                
                keybinds = self.preset_edit_data.get("keybinds", {})
                keybinds[flag] = keybind_str
                
                dpg.configure_item(f"preset_keybind_button_{flag}", label=f"Keybind: {keybind_str}")
                dpg.configure_item(f"preset_clear_keybind_button_{flag}", show=True)
                self._save_preset_edit_data()
            finally:
                self.is_setting_preset_keybind = False
                self.preset_keybind_being_set = None
                # Re-enable main hotkeys after capture is done
                self.register_all_hotkeys()

        threading.Thread(target=capture_key, daemon=True).start()

    def clear_preset_keybind(self, sender, app_data, flag):
        keybinds = self.preset_edit_data.get("keybinds", {})
        keybinds.pop(flag, None)
        dpg.configure_item(f"preset_keybind_button_{flag}", label="Keybind: none")
        dpg.configure_item(f"preset_clear_keybind_button_{flag}", show=False)
        self._save_preset_edit_data()

    def unregister_all_hotkeys(self):
        """Only used internally to clear hotkeys during preset keybind capture"""
        for handler in list(self.hotkey_handlers.values()):
            try:
                keyboard.unhook(handler)
            except:
                try:
                    keyboard.remove_hotkey(handler)
                except:
                    pass
        self.hotkey_handlers.clear()

    def show_preset_save_confirmation(self, sender=None, app_data=None):
        current_preset = self.current_editing_preset
        current_data = self.preset_edit_data

        if dpg.does_item_exist("preset_edit_window"):
            dpg.delete_item("preset_edit_window")

        def show_confirmation():
            if dpg.does_item_exist("preset_save_confirm_popup"):
                dpg.delete_item("preset_save_confirm_popup")

            with dpg.window(label="Confirm Save", modal=True, no_resize=True, no_close=True,
                            width=400, height=160, tag="preset_save_confirm_popup"):
                dpg.bind_item_theme("preset_save_confirm_popup", self.popup_theme)
                dpg.add_text("Are you sure you want to save the changes to this preset?", wrap=370)
                dpg.add_spacer(height=20)
                with dpg.group(horizontal=True):
                    dpg.add_spacer(width=85)
                    dpg.add_button(label="Yes", width=80, callback=lambda s, a: self.save_preset_changes(current_preset, current_data))
                    dpg.add_spacer(width=20)
                    dpg.add_button(label="No", width=80, callback=self.cancel_preset_save)
            self.center_popup("preset_save_confirm_popup")

        threading.Timer(0.05, show_confirmation).start()

    def save_preset_changes(self, preset_name, preset_data):
        if not preset_name or not preset_data:
            if dpg.does_item_exist("preset_save_confirm_popup"):
                dpg.delete_item("preset_save_confirm_popup")
            return

        preset_path = self._get_preset_path(preset_name)
        try:
            with open(preset_path, "w", encoding="utf-8") as f:
                json.dump(preset_data, f, indent=4)
            
            self._cleanup_temp_file(preset_name)

            self.show_feedback(f"Preset '{preset_name}' saved successfully!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Failed to save preset: {e}", [255, 0, 0])

        if dpg.does_item_exist("preset_save_confirm_popup"):
            dpg.delete_item("preset_save_confirm_popup")
        
        self.current_editing_preset = None
        self.preset_edit_data = None

    def cancel_preset_save(self, sender, app_data):
        """Closes confirmation and reopens the edit window with small delay"""
        if dpg.does_item_exist("preset_save_confirm_popup"):
            dpg.delete_item("preset_save_confirm_popup")

        if self.current_editing_preset and self.preset_edit_data:
            def reopen_edit():
                self.edit_preset(None, None, self.current_editing_preset)
            threading.Timer(0.05, reopen_edit).start()

    def export_current_preset(self, sender=None, app_data=None):
        """Exports the main preset file (not temp) by copying its content to clipboard"""
        if not self.current_editing_preset:
            self.show_feedback("No preset is currently being edited!", [255, 0, 0])
            return

        preset_path = self._get_preset_path(self.current_editing_preset)
        temp_path = self._get_temp_path(self.current_editing_preset)

        try:
            if not os.path.exists(preset_path):
                self.show_feedback(f"Preset file not found!", [255, 0, 0])
                return

            # Check if temp file exists and has different content
            if os.path.exists(temp_path):
                with open(preset_path, "r", encoding="utf-8") as f:
                    main_content = f.read()
                with open(temp_path, "r", encoding="utf-8") as f:
                    temp_content = f.read()

                if main_content != temp_content:
                    if dpg.does_item_exist("preset_edit_window"):
                        dpg.delete_item("preset_edit_window")
                    threading.Timer(0.05, lambda pn=self.current_editing_preset: self.show_export_unsaved_confirmation(pn)).start()
                    return

            # No unsaved changes or no temp file - export directly
            with open(preset_path, "r", encoding="utf-8") as f:
                content = f.read()
            pyperclip.copy(content)
            self.show_feedback(f"Preset '{self.current_editing_preset}' exported to clipboard!", [0, 255, 0])

        except Exception as e:
            self.show_feedback(f"Export failed: {e}", [255, 0, 0])

    def show_export_unsaved_confirmation(self, preset_name):
        if dpg.does_item_exist("preset_export_unsaved_popup"):
            dpg.delete_item("preset_export_unsaved_popup")

        with dpg.window(label="Unsaved Changes", modal=True, no_resize=True, no_close=True,
                        width=400, height=160, tag="preset_export_unsaved_popup"):
            dpg.bind_item_theme("preset_export_unsaved_popup", self.popup_theme)
            dpg.add_text(f"Unsaved changes detected. If you export now, you'll export an unedited version of {preset_name}'s .json content. Export anyway?", wrap=370)
            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_spacer(width=85)
                dpg.add_button(label="Yes", width=80, callback=lambda s, a: self.confirm_export_unsaved(preset_name))
                dpg.add_spacer(width=20)
                dpg.add_button(label="No", width=80, callback=self.cancel_export_unsaved)
                dpg.add_spacer(width=80)
        self.center_popup("preset_export_unsaved_popup")

    def confirm_export_unsaved(self, preset_name):
        if dpg.does_item_exist("preset_export_unsaved_popup"):
            dpg.delete_item("preset_export_unsaved_popup")

        preset_path = self._get_preset_path(preset_name)
        try:
            if os.path.exists(preset_path):
                with open(preset_path, "r", encoding="utf-8") as f:
                    content = f.read()
                pyperclip.copy(content)
                self.show_feedback(f"Preset '{preset_name}' exported to clipboard!", [0, 255, 0])
            else:
                self.show_feedback(f"Preset file not found!", [255, 0, 0])
        except Exception as e:
            self.show_feedback(f"Export failed: {e}", [255, 0, 0])

        # Re-open edit preset window after successful export
        if self.current_editing_preset == preset_name:
            def reopen_edit():
                self.edit_preset(None, None, preset_name)
            threading.Timer(0.05, reopen_edit).start()

    def cancel_export_unsaved(self, sender=None, app_data=None):
        if dpg.does_item_exist("preset_export_unsaved_popup"):
            dpg.delete_item("preset_export_unsaved_popup")

        # Re-open edit preset window with small delay
        if self.current_editing_preset:
            def reopen_edit():
                self.edit_preset(None, None, self.current_editing_preset)
            threading.Timer(0.05, reopen_edit).start()

    def refresh_presets_list(self):
        if not dpg.does_item_exist("presets_list_child"):
            return
        dpg.delete_item("presets_list_child", children_only=True)

        preset_files = [f for f in os.listdir(self.presets_dir) if f.endswith('.json')]
        if not preset_files:
            dpg.add_text("No presets found.", parent="presets_list_child")
            return

        for filename in preset_files:
            preset_name = os.path.splitext(filename)[0]
            with dpg.group(horizontal=True, parent="presets_list_child"):
                dpg.add_input_text(default_value=preset_name, readonly=True, width=-146, tag=f"preset_name_input_{preset_name}")
                dpg.add_button(label="Load", callback=self.load_preset, user_data=preset_name)
                dpg.add_button(label="Edit", callback=self.edit_preset, user_data=preset_name)
                dpg.add_button(label="Delete", callback=self.delete_preset, user_data=preset_name)
            dpg.add_separator(parent="presets_list_child")

    def show_import_preset_popup(self):
        if dpg.does_item_exist("import_preset_popup"):
            dpg.show_item("import_preset_popup")
            self.center_popup("import_preset_popup")
            return
        with dpg.window(label="Import Preset", modal=True, no_resize=True, no_close=True,
                        width=460, height=340, tag="import_preset_popup"):
            dpg.bind_item_theme("import_preset_popup", self.popup_theme)
            dpg.add_text("Paste Preset JSON here:")
            dpg.add_input_text(multiline=True, width=-1, height=250, tag="preset_import_text")
            with dpg.group(horizontal=True):
                dpg.add_button(label="Import", callback=self.import_preset_from_input)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("import_preset_popup"))
        self.center_popup("import_preset_popup")

    def import_preset_from_input(self, sender, app_data):
        content = dpg.get_value("preset_import_text")
        try:
            data = json.loads(content)
            self.imported_preset_data = data
            if dpg.does_item_exist("import_preset_popup"):
                dpg.delete_item("import_preset_popup")
            threading.Timer(0.05, self.show_preset_name_popup_for_import).start()
        except Exception as e:
            self.show_feedback(f"Failed to parse preset JSON: {str(e)}", [255, 0, 0])

    def show_preset_name_popup_for_import(self):
        if dpg.does_item_exist("preset_name_popup"):
            dpg.show_item("preset_name_popup")
            self.center_popup("preset_name_popup")
            return

        with dpg.window(label="Import Preset", modal=True, no_resize=True, no_close=True,
                        width=320, height=160, tag="preset_name_popup"):
            dpg.bind_item_theme("preset_name_popup", self.popup_theme)
            dpg.add_text("Enter preset name:")
            dpg.add_input_text(default_value="", tag="import_preset_name_input", width=-1)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Create", callback=self.create_preset_from_import)
                dpg.add_button(label="Cancel", callback=self.cancel_preset_name_for_import)
            dpg.add_spacer(height=8)
            dpg.add_text("", tag="import_preset_name_feedback", color=[255, 0, 0])

        self.center_popup("preset_name_popup")

    def create_preset_from_import(self, sender=None, app_data=None):
        preset_name = dpg.get_value("import_preset_name_input").strip()
        if not preset_name:
            self.show_import_preset_name_feedback("Preset name cannot be empty!", [255, 0, 0])
            return

        if len(preset_name) > 32:
            self.show_import_preset_name_feedback("Exceeded 32 character limit!", [255, 0, 0])
            return

        invalid_chars = r'\/:*?"<>|'
        if any(char in preset_name for char in invalid_chars):
            self.show_import_preset_name_feedback(f"Invalid characters! Cannot use: {invalid_chars}", [255, 0, 0])
            return

        preset_path = self._get_preset_path(preset_name)
        if os.path.exists(preset_path):
            if dpg.does_item_exist("preset_name_popup"):
                dpg.delete_item("preset_name_popup")
            threading.Timer(0.05, lambda pn=preset_name, pd=self.imported_preset_data: self.show_preset_overwrite_confirmation(pn, pd, is_import=True)).start()
            return

        try:
            with open(preset_path, "w", encoding="utf-8") as f:
                json.dump(self.imported_preset_data, f, indent=4)
            self.show_feedback(f"Preset '{preset_name}' imported successfully!", [0, 255, 0])
            dpg.set_value("import_preset_name_input", "")  # Clear input after successful import
        except Exception as e:
            self.show_feedback(f"Error creating preset: {e}", [255, 0, 0])

        if dpg.does_item_exist("preset_name_popup"):
            dpg.delete_item("preset_name_popup")
        self.imported_preset_data = None
        self.refresh_presets_list()

    def cancel_preset_name_for_import(self, sender, app_data):
        if dpg.does_item_exist("preset_name_popup"):
            dpg.delete_item("preset_name_popup")
        threading.Timer(0.05, self.show_import_preset_popup).start()

    def show_preset_overwrite_confirmation(self, preset_name, preset_data, is_import=False):
        self.overwrite_preset_name = preset_name
        self.overwrite_preset_data = preset_data
        self.overwrite_is_import = is_import

        if dpg.does_item_exist("preset_overwrite_popup"):
            dpg.delete_item("preset_overwrite_popup")

        with dpg.window(label="Confirm Overwrite", modal=True, no_resize=True, no_close=True,
                        width=400, height=160, tag="preset_overwrite_popup"):
            dpg.bind_item_theme("preset_overwrite_popup", self.popup_theme)
            dpg.add_text(f"There's already a preset named {preset_name}. Overwrite it?", wrap=370)
            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_spacer(width=85)
                dpg.add_button(label="Yes", width=80, callback=self.confirm_overwrite_preset)
                dpg.add_spacer(width=20)
                dpg.add_button(label="No", width=80, callback=self.cancel_overwrite_preset)
                dpg.add_spacer(width=80)
        self.center_popup("preset_overwrite_popup")

    def confirm_overwrite_preset(self, sender=None, app_data=None):
        if not self.overwrite_preset_name or not self.overwrite_preset_data:
            if dpg.does_item_exist("preset_overwrite_popup"):
                dpg.delete_item("preset_overwrite_popup")
            return

        preset_path = self._get_preset_path(self.overwrite_preset_name)
        try:
            with open(preset_path, "w", encoding="utf-8") as f:
                json.dump(self.overwrite_preset_data, f, indent=4)
            self.show_feedback(f"Preset '{self.overwrite_preset_name}' overwritten successfully!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Failed to overwrite preset: {e}", [255, 0, 0])

        if dpg.does_item_exist("preset_overwrite_popup"):
            dpg.delete_item("preset_overwrite_popup")

        self.refresh_presets_list()
        self.overwrite_preset_name = None
        self.overwrite_preset_data = None
        self.overwrite_is_import = False

    def cancel_overwrite_preset(self, sender, app_data):
        if dpg.does_item_exist("preset_overwrite_popup"):
            dpg.delete_item("preset_overwrite_popup")

        if self.overwrite_is_import:
            threading.Timer(0.05, self.show_preset_name_popup_for_import).start()
        else:
            threading.Timer(0.05, self.show_create_preset_window).start()

        self.overwrite_preset_name = None
        self.overwrite_preset_data = None
        self.overwrite_is_import = False

    # ====================== RENAME PRESET LOGIC ======================
    def rename_preset(self, sender, app_data, preset_name):
        if dpg.does_item_exist("preset_edit_window"):
            dpg.delete_item("preset_edit_window")

        def open_rename_popup():
            if dpg.does_item_exist("rename_preset_popup"):
                dpg.delete_item("rename_preset_popup")

            with dpg.window(label="Rename Preset", modal=True, no_resize=True, no_close=True,
                            width=420, height=190, tag="rename_preset_popup"):
                dpg.bind_item_theme("rename_preset_popup", self.popup_theme)
                dpg.add_text("Enter new preset name (without .json):")
                dpg.add_input_text(default_value="", tag="rename_preset_input", width=-1)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Rename", callback=lambda s, a: self.perform_preset_rename(preset_name))
                    dpg.add_button(label="Cancel", callback=lambda s, a: self.cancel_preset_rename(preset_name))
                dpg.add_spacer(height=8)
                dpg.add_text("", tag="rename_preset_feedback", color=[255, 0, 0])

            self.center_popup("rename_preset_popup")

        threading.Timer(0.05, open_rename_popup).start()

    def perform_preset_rename(self, old_preset_name):
        new_name = dpg.get_value("rename_preset_input").strip()
        if not new_name:
            self.show_rename_preset_feedback("Preset name cannot be empty!", [255, 0, 0])
            return

        if len(new_name) > 32:
            self.show_rename_preset_feedback("Exceeded 32 character limit!", [255, 0, 0])
            return

        invalid_chars = r'\/:*?"<>|'
        if any(char in new_name for char in invalid_chars):
            self.show_rename_preset_feedback(f"Invalid characters! Cannot use: {invalid_chars}", [255, 0, 0])
            return

        if new_name == old_preset_name:
            self.cancel_preset_rename(old_preset_name)
            return

        old_path = self._get_preset_path(old_preset_name)
        new_path = self._get_preset_path(new_name)

        if os.path.exists(new_path):
            if dpg.does_item_exist("rename_preset_popup"):
                dpg.delete_item("rename_preset_popup")
            threading.Timer(0.05, lambda: self.show_preset_rename_overwrite_confirmation(old_preset_name, new_name)).start()
            return

        try:
            # Rename main preset file
            if os.path.exists(old_path):
                shutil.move(old_path, new_path)
            # Rename temp file if it exists
            old_temp = self._get_temp_path(old_preset_name)
            new_temp = self._get_temp_path(new_name)
            if os.path.exists(old_temp):
                shutil.move(old_temp, new_temp)

            # Update current editing if active
            if self.current_editing_preset == old_preset_name:
                self.current_editing_preset = new_name

            self.show_feedback(f"Preset renamed from '{old_preset_name}' to '{new_name}' successfully!", [0, 255, 0])
            if dpg.does_item_exist("rename_preset_popup"):
                dpg.delete_item("rename_preset_popup")
            self.refresh_presets_list()

            # Reopen edit window with new name
            if self.current_editing_preset == new_name and self.preset_edit_data:
                def reopen_edit():
                    self.edit_preset(None, None, new_name)
                threading.Timer(0.05, reopen_edit).start()

        except Exception as e:
            self.show_feedback(f"Rename failed: {e}", [255, 0, 0])
            if dpg.does_item_exist("rename_preset_popup"):
                dpg.delete_item("rename_preset_popup")

    def show_preset_rename_overwrite_confirmation(self, old_name, new_name):
        if dpg.does_item_exist("preset_rename_overwrite_popup"):
            dpg.delete_item("preset_rename_overwrite_popup")

        with dpg.window(label="Confirm Overwrite", modal=True, no_resize=True, no_close=True,
                        width=400, height=160, tag="preset_rename_overwrite_popup"):
            dpg.bind_item_theme("preset_rename_overwrite_popup", self.popup_theme)
            dpg.add_text(f"A preset named '{old_name}' already exists. Overwrite it with '{new_name}'?", wrap=370)
            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_spacer(width=85)
                dpg.add_button(label="Yes", width=80, callback=lambda s, a: self.confirm_preset_rename_overwrite(old_name, new_name))
                dpg.add_spacer(width=20)
                dpg.add_button(label="No", width=80, callback=self.cancel_preset_rename_overwrite)
        self.center_popup("preset_rename_overwrite_popup")

    def confirm_preset_rename_overwrite(self, old_name, new_name):
        if dpg.does_item_exist("preset_rename_overwrite_popup"):
            dpg.delete_item("preset_rename_overwrite_popup")

        old_path = self._get_preset_path(old_name)
        new_path = self._get_preset_path(new_name)

        try:
            if os.path.exists(old_path):
                shutil.move(old_path, new_path)
            self.show_feedback(f"Preset renamed from '{old_name}' to '{new_name}' (overwritten).", [0, 255, 0])
            if self.current_editing_preset == old_name:
                self.current_editing_preset = new_name
            self.refresh_presets_list()
            if self.current_editing_preset == new_name:
                def reopen():
                    self.edit_preset(None, None, new_name)
                threading.Timer(0.05, reopen).start()
        except Exception as e:
            self.show_feedback(f"Rename failed: {e}", [255, 0, 0])

        if dpg.does_item_exist("rename_preset_popup"):
            dpg.delete_item("rename_preset_popup")

    def cancel_preset_rename_overwrite(self, sender=None, app_data=None):
        if dpg.does_item_exist("preset_rename_overwrite_popup"):
            dpg.delete_item("preset_rename_overwrite_popup")
        if dpg.does_item_exist("rename_preset_popup"):
            dpg.show_item("rename_preset_popup")
            self.center_popup("rename_preset_popup")

    def cancel_preset_rename(self, preset_name):
        if dpg.does_item_exist("rename_preset_popup"):
            dpg.delete_item("rename_preset_popup")
        if self.current_editing_preset:
            def reopen_edit():
                self.edit_preset(None, None, preset_name)
            threading.Timer(0.05, reopen_edit).start()

    # ====================== THEME SYSTEM ======================
    def create_themes(self):
        # Pink theme (default)
        with dpg.theme() as self.pink_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (255, 230, 235))
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (255, 240, 245))
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (255, 230, 235))
                dpg.add_theme_color(dpg.mvThemeCol_Border, (230, 180, 190))
                dpg.add_theme_color(dpg.mvThemeCol_Text, (80, 30, 60))
                dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, (160, 120, 130))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (255, 200, 210))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (255, 180, 200))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (255, 160, 190))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (255, 190, 200))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (255, 160, 180))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (255, 130, 160))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (255, 220, 230))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (255, 190, 210))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (255, 160, 180))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (255, 190, 200))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (255, 160, 180))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (255, 160, 180))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, (51, 51, 55))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, (255, 180, 200))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, (255, 150, 180))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, (255, 130, 160))
                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (255, 110, 160))
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, (255, 150, 190))
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, (255, 120, 160))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, (255, 160, 190))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, (255, 130, 170))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, (255, 100, 150))
                dpg.add_theme_color(dpg.mvThemeCol_Separator, (78, 78, 78))

        # Default theme
        with dpg.theme() as self.default_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (30, 30, 35))
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_Border, (60, 60, 60))
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, (128, 128, 128))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (45, 45, 50))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (60, 60, 70))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (35, 35, 45))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (60, 60, 70))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (80, 80, 90))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (40, 40, 50))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (35, 35, 40))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (45, 45, 55))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (30, 30, 40))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (30, 30, 35))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (40, 72, 119))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (30, 30, 35))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, (20, 20, 25))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, (70, 70, 80))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, (90, 90, 100))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, (50, 50, 60))

        # iM sO gReEn theme
        with dpg.theme() as self.green_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (215, 252, 222))
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (240, 255, 245))
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (215, 252, 222))
                dpg.add_theme_color(dpg.mvThemeCol_Border, (180, 230, 190))
                dpg.add_theme_color(dpg.mvThemeCol_Text, (30, 80, 60))
                dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, (120, 160, 130))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (166, 255, 145))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (166, 255, 145))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (76, 255, 33))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (215, 252, 222))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (195, 250, 205))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (144, 252, 164))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (166, 255, 145))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, (180, 255, 200))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, (150, 255, 180))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, (76, 255, 33))
                dpg.add_theme_color(dpg.mvThemeCol_Header, (200, 255, 210))
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, (170, 255, 190))
                dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, (140, 255, 170))
                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (49, 255, 0))
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, (150, 255, 190))
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, (120, 255, 160))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, (166, 255, 145))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, (123, 255, 92))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, (76, 255, 33))

        # OG Flag Browser
        with dpg.theme() as self.og_flagbrowser_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (10, 10, 10))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (40, 72, 119))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (10, 10, 10))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (50, 82, 129))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (40, 72, 119))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (30, 62, 109))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (45, 88, 142))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (67, 147, 247))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (15, 58, 112))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (35, 61, 98))
                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (65, 150, 250))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, (30, 45, 65))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, (25, 40, 60))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, (15, 30, 50))

        # OG Flag Browser 2 (exclusive for ApplicationSettings window - same colors as OG Flag Browser with small differences -w-)
        with dpg.theme() as self.og_flagbrowser2_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (30, 48, 72))
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (25, 25, 25))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (10, 10, 10))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (40, 72, 119))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (10, 10, 10))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (50, 82, 129))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (40, 72, 119))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (30, 62, 109))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (45, 88, 142))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (67, 147, 247))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (15, 58, 112))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (35, 61, 98))
                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (65, 150, 250))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, (30, 45, 65))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, (25, 40, 60))
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, (15, 30, 50))

        # ====================== USER CUSTOM THEME ======================
        with dpg.theme() as self.custom_user_theme:
            with dpg.theme_component(dpg.mvAll):
                for col_constant, default_color in self.custom_user_theme_colors.items():
                    self.custom_user_theme_color_items[col_constant] = dpg.add_theme_color(
                        col_constant, default_color, category=dpg.mvThemeCat_Core
                    )

        # Set initial themes
        self.flag_browser_theme = self.pink_theme
        self.presets_theme = self.pink_theme
        self.customize_theme = self.pink_theme
        self.popup_theme = self.pink_theme

    def apply_theme_to_window(self, window_tag, theme):
        if dpg.does_item_exist(window_tag):
            dpg.bind_item_theme(window_tag, theme)

    def apply_theme_to_all(self):
        self.apply_theme_to_window("flag_browser_window", self.flag_browser_theme)
        self.apply_theme_to_window("presets_window", self.presets_theme)
        self.apply_theme_to_window("customize_window", self.customize_theme)
        self.apply_theme_to_window("proxy_window", self.flag_browser_theme)
        
        popup_windows = [
            "create_preset_window", "preset_edit_window", "preset_save_confirm_popup",
            "preset_overwrite_popup", "preset_export_unsaved_popup", "rename_preset_popup",
            "preset_rename_overwrite_popup", "import_preset_popup", "preset_name_popup",
            "add_flag_to_preset_popup", "preset_add_value_window", "clear_confirm_popup",
            "json_import_popup", "rename_popup", "preset_delete_confirm_popup"
        ]
        for tag in popup_windows:
            if dpg.does_item_exist(tag):
                dpg.bind_item_theme(tag, self.popup_theme)
        
        # Handle ApplicationSettings window
        share_enabled = getattr(self, 'share_theme_with_appsettings', False)
        if share_enabled and dpg.does_item_exist("application_settings_window"):
            # When sharing, use the flag browser theme BUT use OG Flag Browser 2 if OG Flag Browser is selected
            if self.current_theme == "og_flagbrowser":
                dpg.bind_item_theme("application_settings_window", self.og_flagbrowser2_theme)
            else:
                dpg.bind_item_theme("application_settings_window", self.flag_browser_theme)
        elif not share_enabled and dpg.does_item_exist("application_settings_window"):
            # When not sharing, always use OG Flag Browser 2
            dpg.bind_item_theme("application_settings_window", self.og_flagbrowser2_theme)

        self.update_footer_color()
        # Use a timer to avoid freezing the UI when updating asterisks and proxy colors
        threading.Timer(0.0001, self.update_asterisk_colors_in_appsettings).start()
        threading.Timer(0.0001, self.update_proxy_theme_colors).start()

    def update_asterisk_colors_in_appsettings(self):
        """Update all existing ApplicationSettings asterisks to match current theme"""
        asterisk_color = self.get_asterisk_color()
        # Loop through all cached flags and update their asterisks if they exist
        for flag in self.appsettings_flag_groups:
            tag = f"appsettings_asterisk_{flag}"
            if dpg.does_item_exist(tag):
                dpg.configure_item(tag, color=asterisk_color)

    def update_proxy_theme_colors(self):
        """Update proxy window colors to match current theme"""
        try:
            success_color = self.get_feedback_color([0, 255, 0])
            fail_color = self.get_feedback_color([255, 0, 0])
            
            # Intercepted label
            if dpg.does_item_exist("intercepted_count_text"):
                dpg.configure_item("intercepted_count_text", color=success_color)
            
            # Proxy status text
            if dpg.does_item_exist("proxy_status_text"):
                status = dpg.get_value("proxy_status_text")
                if status == "Active":
                    dpg.configure_item("proxy_status_text", color=success_color)
                else:
                    dpg.configure_item("proxy_status_text", color=fail_color)
        except:
            pass

    def update_footer_color(self):
        if dpg.does_item_exist("footer_text"):
            if self.current_theme == "custom_user":
                color = self.custom_footer_color
            else:
                color = self.footer_colors.get(self.current_theme, [140, 140, 140])
            dpg.configure_item("footer_text", color=color)

    def set_theme(self, theme_name):
        self.current_theme = theme_name
        if theme_name == "default":
            self.flag_browser_theme = self.default_theme
            self.presets_theme = self.default_theme
            self.customize_theme = self.default_theme
            self.popup_theme = self.default_theme
        elif theme_name == "iM sO gReEn":
            self.flag_browser_theme = self.green_theme
            self.presets_theme = self.green_theme
            self.customize_theme = self.green_theme
            self.popup_theme = self.green_theme
        elif theme_name == "og_flagbrowser":
            self.flag_browser_theme = self.og_flagbrowser_theme
            self.presets_theme = self.og_flagbrowser_theme
            self.customize_theme = self.og_flagbrowser_theme
            self.popup_theme = self.og_flagbrowser_theme
        elif theme_name == "custom_user":
            self.load_custom_theme_from_file()
            self.flag_browser_theme = self.custom_user_theme
            self.presets_theme = self.custom_user_theme
            self.customize_theme = self.custom_user_theme
            self.popup_theme = self.custom_user_theme
        else:  # pink
            self.flag_browser_theme = self.pink_theme
            self.presets_theme = self.pink_theme
            self.customize_theme = self.pink_theme
            self.popup_theme = self.pink_theme
        
        self.apply_theme_to_all()
        
        if dpg.does_item_exist("available_flags_list"):
            self.update_flag_list()
        if dpg.does_item_exist("enabled_flags_list"):
            self.update_enabled_flags_list()
        if dpg.does_item_exist("presets_list_child"):
            self.refresh_presets_list()

        if dpg.does_item_exist("custom_user_color_section"):
            dpg.configure_item("custom_user_color_section", show=(theme_name == "custom_user"))
        if dpg.does_item_exist("custom_apply_group"):
            dpg.configure_item("custom_apply_group", show=(theme_name == "custom_user"))

    def update_custom_user_color(self, sender, app_data, user_data):
        """This method is no longer used for real-time updates (kept only to preserve original code structure)."""
        pass

    def apply_custom_theme_changes(self, sender, app_data):
        """Apply all colors from the color pickers when the user clicks the Apply button."""
        color_list = [
            dpg.mvThemeCol_WindowBg,
            dpg.mvThemeCol_ChildBg,
            dpg.mvThemeCol_PopupBg,
            dpg.mvThemeCol_Border,
            dpg.mvThemeCol_Text,
            dpg.mvThemeCol_TextDisabled,
            dpg.mvThemeCol_Tab,
            dpg.mvThemeCol_TabHovered,
            dpg.mvThemeCol_TabActive,
            dpg.mvThemeCol_Button,
            dpg.mvThemeCol_ButtonHovered,
            dpg.mvThemeCol_ButtonActive,
            dpg.mvThemeCol_FrameBg,
            dpg.mvThemeCol_FrameBgHovered,
            dpg.mvThemeCol_FrameBgActive,
            dpg.mvThemeCol_TitleBg,
            dpg.mvThemeCol_TitleBgActive,
            dpg.mvThemeCol_TitleBgCollapsed,
            dpg.mvThemeCol_ScrollbarBg,
            dpg.mvThemeCol_ScrollbarGrab,
            dpg.mvThemeCol_ScrollbarGrabHovered,
            dpg.mvThemeCol_ScrollbarGrabActive,
            dpg.mvThemeCol_CheckMark,
            dpg.mvThemeCol_SliderGrab,
            dpg.mvThemeCol_SliderGrabActive,
            dpg.mvThemeCol_ResizeGrip,
            dpg.mvThemeCol_ResizeGripHovered,
            dpg.mvThemeCol_ResizeGripActive,
            dpg.mvThemeCol_Separator,
        ]

        for col_const in color_list:
            tag = f"custom_color_{col_const}"
            if dpg.does_item_exist(tag):
                color = dpg.get_value(tag)
                if isinstance(color, (list, tuple)):
                    color = [int(c) for c in color[:3]]
                dpg.set_value(self.custom_user_theme_color_items[col_const], color)
                if col_const in self.custom_user_theme_colors:
                    self.custom_user_theme_colors[col_const] = color

        # === Apply Feedback & Footer colors from pickers ===
        if dpg.does_item_exist("custom_feedback_success"):
            success_color = dpg.get_value("custom_feedback_success")
            if isinstance(success_color, (list, tuple)):
                self.custom_feedback_success = [int(c) for c in success_color[:3]]

        if dpg.does_item_exist("custom_feedback_fail"):
            fail_color = dpg.get_value("custom_feedback_fail")
            if isinstance(fail_color, (list, tuple)):
                self.custom_feedback_fail = [int(c) for c in fail_color[:3]]

        if dpg.does_item_exist("custom_footer_color"):
            footer_color = dpg.get_value("custom_footer_color")
            if isinstance(footer_color, (list, tuple)):
                self.custom_footer_color = [int(c) for c in footer_color[:3]]

        self.save_custom_theme_to_file()   # Save to Custom theme/custom theme.json
        self.apply_theme_to_all()
        # Update asterisk and proxy colors after applying custom theme
        threading.Timer(0.0001, self.update_asterisk_colors_in_appsettings).start()
        threading.Timer(0.0001, self.update_proxy_theme_colors).start()
        self.show_feedback("Custom theme colors applied successfully!", [0, 255, 0])
        self.show_feedback("Custom theme colors applied successfully!", [0, 255, 0])

    def theme_radio_callback(self, sender, app_data):
        if app_data == "Pink Theme (default)":
            self.set_theme("pink")
        elif app_data == "iM sO gReEn":
            self.set_theme("iM sO gReEn")
        elif app_data == "OG Flag Browser":
            self.set_theme("og_flagbrowser")
        elif app_data == "Custom theme":
            self.set_theme("custom_user")
        else:
            self.set_theme("default")

    def toggle_share_theme(self, sender, app_data):
        """Toggle sharing the current theme with ApplicationSettings window"""
        self.share_theme_with_appsettings = app_data
        self._save_developer_options_config()
        
        if app_data:
            # Apply current theme to ApplicationSettings window
            if dpg.does_item_exist("application_settings_window"):
                # When sharing, use the flag browser theme BUT use OG Flag Browser 2 if OG Flag Browser is selected
                if self.current_theme == "og_flagbrowser":
                    dpg.bind_item_theme("application_settings_window", self.og_flagbrowser2_theme)
                else:
                    dpg.bind_item_theme("application_settings_window", self.flag_browser_theme)
        else:
            # Revert ApplicationSettings to its original theme (OG Flag Browser 2)
            if dpg.does_item_exist("application_settings_window"):
                dpg.bind_item_theme("application_settings_window", self.og_flagbrowser2_theme)
        # Update asterisk and proxy colors with a small delay to prevent freezing the UI
        threading.Timer(0.05, self.update_asterisk_colors_in_appsettings).start()
        threading.Timer(0.05, self.update_proxy_theme_colors).start()

    def toggle_remove_size_limit(self, sender, app_data):
        """Toggle the minimum size limit for the flag browser window"""
        self.remove_size_limit = app_data
        self._save_developer_options_config()
        
        # Update the window's minimum size
        if dpg.does_item_exist("flag_browser_window"):
            if app_data:
                dpg.configure_item("flag_browser_window", min_size=[1, 1])
            else:
                dpg.configure_item("flag_browser_window", min_size=[310, 426])

    def toggle_convert_suffix(self, sender, app_data):
        """Toggle converting suffix flags (_PlaceFilter etc.) to base flags"""
        self.convert_suffix_to_base = app_data
        self._save_developer_options_config()
        
        # Refresh ApplicationSettings window to apply the change
        self.appsettings_flag_groups.clear()
        if dpg.does_item_exist("appsettings_list"):
            self.refresh_application_settings_list()

    def toggle_show_suffix_in_appsettings(self, sender, app_data):
        """Toggle showing suffix flags (_PlaceFilter, _UniverseFilter) in ApplicationSettings"""
        self.show_suffix_in_appsettings = app_data
        self._save_developer_options_config()
        
        # Refresh ApplicationSettings window to apply the change
        self.appsettings_flag_groups.clear()
        if dpg.does_item_exist("appsettings_list"):
            self.refresh_application_settings_list()

    def get_shortened_path(self, path: str, max_chars: int) -> str:
        if not path:
            return ""
        if len(path) <= max_chars:
            return path
        return "..." + path[-(max_chars - 3):]

    def update_json_path_display(self):
        if not dpg.does_item_exist("json_path_input"):
            return
        try:
            win_width = dpg.get_item_width("flag_browser_window")
            available_pixels = max(210, win_width - 100)
            char_width = 7.75
            available_chars = max(25, int(available_pixels / char_width))
            shortened = self.get_shortened_path(self.JSON_PATH, available_chars)
            dpg.set_value("json_path_input", shortened)
        except:
            shortened = self.get_shortened_path(self.JSON_PATH, 65)
            dpg.set_value("json_path_input", shortened)

    def get_feedback_color(self, base_color):
        """Returns the correct color to use for feedback messages when in custom theme"""
        if self.current_theme != "custom_user":
            return base_color

        if base_color == [0, 255, 0]:      # success
            return self.custom_feedback_success
        elif base_color == [255, 0, 0]:    # fail
            return self.custom_feedback_fail
        return base_color

    def get_asterisk_color(self):
        """Returns the color for ApplicationSettings asterisk.
        Only follows the feedback success theme when sharing is enabled."""
        share_enabled = getattr(self, 'share_theme_with_appsettings', False)
        if share_enabled and self.current_theme == "custom_user":
            return self.custom_feedback_success
        return [0, 255, 0]  # Default green

    def show_feedback(self, message: str, color: list):
        if self.notification_timer is not None:
            try:
                self.notification_timer.cancel()
            except:
                pass

        final_color = self.get_feedback_color(color)

        dpg.set_value("json_feedback", message)
        dpg.configure_item("json_feedback", color=final_color)
        self.notification_timer = threading.Timer(5.0, self.hide_feedback)
        self.notification_timer.daemon = True
        self.notification_timer.start()

    def show_proxy_feedback(self, message: str, color: list, tag="proxy_feedback"):
        """Show feedback; run() performs the delayed hide on the GUI thread."""
        try:
            if not dpg.does_item_exist(tag):
                return
            dpg.set_value(tag, message)
            dpg.configure_item(tag, color=self.get_feedback_color(color))
            self._proxy_feedback_hide_at = time.monotonic() + 5.0
        except Exception:
            pass

    def hide_feedback(self):
        if dpg.does_item_exist("json_feedback"):
            dpg.set_value("json_feedback", "")

    def show_rename_feedback(self, message: str, color: list):
        if self.rename_notification_timer is not None:
            try:
                self.rename_notification_timer.cancel()
            except:
                pass
        if dpg.does_item_exist("rename_feedback"):
            final_color = self.get_feedback_color(color)
            dpg.set_value("rename_feedback", message)
            dpg.configure_item("rename_feedback", color=final_color)
        self.rename_notification_timer = threading.Timer(5.0, self.hide_rename_feedback)
        self.rename_notification_timer.daemon = True
        self.rename_notification_timer.start()

    def hide_rename_feedback(self):
        if dpg.does_item_exist("rename_feedback"):
            dpg.set_value("rename_feedback", "")

    def show_create_preset_feedback(self, message: str, color: list):
        if self.create_preset_feedback_timer is not None:
            try:
                self.create_preset_feedback_timer.cancel()
            except:
                pass

        final_color = self.get_feedback_color(color)

        if dpg.does_item_exist("create_preset_feedback"):
            dpg.set_value("create_preset_feedback", message)
            dpg.configure_item("create_preset_feedback", color=final_color)
        self.create_preset_feedback_timer = threading.Timer(5.0, self.hide_create_preset_feedback)
        self.create_preset_feedback_timer.daemon = True
        self.create_preset_feedback_timer.start()

    def hide_create_preset_feedback(self):
        if dpg.does_item_exist("create_preset_feedback"):
            dpg.set_value("create_preset_feedback", "")

    def show_import_preset_name_feedback(self, message: str, color: list):
        if self.import_preset_name_feedback_timer is not None:
            try:
                self.import_preset_name_feedback_timer.cancel()
            except:
                pass

        final_color = self.get_feedback_color(color)

        if dpg.does_item_exist("import_preset_name_feedback"):
            dpg.set_value("import_preset_name_feedback", message)
            dpg.configure_item("import_preset_name_feedback", color=final_color)
        self.import_preset_name_feedback_timer = threading.Timer(5.0, self.hide_import_preset_name_feedback)
        self.import_preset_name_feedback_timer.daemon = True
        self.import_preset_name_feedback_timer.start()

    def hide_import_preset_name_feedback(self):
        if dpg.does_item_exist("import_preset_name_feedback"):
            dpg.set_value("import_preset_name_feedback", "")

    def show_rename_preset_feedback(self, message: str, color: list):
        if self.rename_notification_timer is not None:
            try:
                self.rename_notification_timer.cancel()
            except:
                pass
        if dpg.does_item_exist("rename_preset_feedback"):
            final_color = self.get_feedback_color(color)
            dpg.set_value("rename_preset_feedback", message)
            dpg.configure_item("rename_preset_feedback", color=final_color)
        self.rename_notification_timer = threading.Timer(5.0, self.hide_rename_preset_feedback)
        self.rename_notification_timer.daemon = True
        self.rename_notification_timer.start()

    def hide_rename_preset_feedback(self):
        if dpg.does_item_exist("rename_preset_feedback"):
            dpg.set_value("rename_preset_feedback", "")

    def copy_full_path_to_clipboard(self, sender, app_data, user_data):
        try:
            pyperclip.copy(self.JSON_PATH)
            self.show_feedback("Full path copied to clipboard!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Copy failed: {str(e)}", [255, 0, 0])

    def center_popup(self, tag):
        try:
            vp_w = dpg.get_viewport_width()
            vp_h = dpg.get_viewport_height()
            win_w = dpg.get_item_width(tag)
            win_h = dpg.get_item_height(tag)
            title_offset = 38
            x = (vp_w - win_w) // 2 - 10
            y = (vp_h - win_h) // 2 - title_offset // 2
            dpg.set_item_pos(tag, [max(20, x), max(20, y)])
        except:
            pass

    def create_light_pink_theme(self):
        pass

    def setup_gui(self):
        dpg.create_context()
        self.create_themes()

        dpg.create_viewport(
            title=self.overlay_title,
            width=self.screen_width,
            height=self.screen_height,
            x_pos=0, y_pos=0,
            resizable=True,
            always_on_top=self.always_on_top,
            clear_color=[0, 0, 0, 0],
            decorated=False
        )

        self.create_main_window()
        self.create_flag_browser_window()
        self.create_presets_window()
        self.create_customize_window()
        self.create_application_settings_window()
        self.create_proxy_window()

        with dpg.item_handler_registry(tag="path_click_handler") as handler:
            dpg.add_item_clicked_handler(callback=self.copy_full_path_to_clipboard)
        dpg.bind_item_handler_registry("json_path_input", "path_click_handler")

    def create_main_window(self):
        with dpg.window(label="Main", tag="main_window",
                        no_title_bar=True, no_background=True,
                        no_move=True, no_resize=True, no_scrollbar=True,
                        no_collapse=True, no_close=True):
            with dpg.menu_bar():
                with dpg.menu(label="Menu"):
                    dpg.add_menu_item(label="Flag Browser", 
                                      callback=lambda: dpg.configure_item("flag_browser_window", show=not dpg.is_item_shown("flag_browser_window")))
                    dpg.add_menu_item(label="Presets", 
                                      callback=lambda: dpg.configure_item("presets_window", show=not dpg.is_item_shown("presets_window")))
                    dpg.add_menu_item(label="Customize", 
                                      callback=lambda: dpg.configure_item("customize_window", show=not dpg.is_item_shown("customize_window")))
                    dpg.add_menu_item(label="ApplicationSettings", 
                                      callback=lambda: dpg.configure_item("application_settings_window", show=not dpg.is_item_shown("application_settings_window")))
                    dpg.add_menu_item(label="Proxy", 
                                      callback=lambda: dpg.configure_item("proxy_window", show=not dpg.is_item_shown("proxy_window")))
                    dpg.add_menu_item(label=f"Toggle Overlay ({self.hotkey})", callback=self.toggle_overlay, tag="toggle_overlay_menu_item")
                    dpg.add_menu_item(label="Exit", callback=self.clean_exit)

    def create_flag_browser_window(self):
        with dpg.window(label="Flag Browser - lumyna.cc", tag="flag_browser_window",
                width=480, height=655, pos=[100, 100], show=False, 
                no_collapse=False, no_close=False, min_size=[310, 426] if not self.remove_size_limit else [1, 1]):
            dpg.bind_item_theme("flag_browser_window", self.flag_browser_theme)
            
            with dpg.tab_bar():
                with dpg.tab(label="Flag Browser"):
                    with dpg.child_window(tag="main_content", autosize_x=True, height=-23, no_scrollbar=True):
                        dpg.add_text("Available Flags")
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(callback=self.update_search, width=-75, tag="search_input", hint="Search")
                        
                        with dpg.child_window(tag="available_flags_list", resizable_y=True, autosize_x=True, height=190):
                            self.update_flag_list()

                        dpg.add_spacer(height=8)
                        dpg.add_text("Selected Flag: None", tag="selected_flag_text")
                        
                        with dpg.group(horizontal=True, tag="value_group"):
                            dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value")
                        
                        dpg.add_button(label="Set Value", callback=self.set_flag_value)

                        dpg.add_spacer(height=10)
                        dpg.add_separator()

                        with dpg.group(horizontal=True):
                            dpg.add_text("Modified Flags")
                            dpg.add_input_text(hint="Search", callback=self.update_modified_search,
                                               width=-89, tag="modified_search_input")
                            dpg.add_button(label="Toggle All", callback=self.toggle_all_modified, width=80)

                        with dpg.child_window(tag="enabled_flags_list", autosize_x=True, autosize_y=True):
                            self.update_enabled_flags_list()

                with dpg.tab(label="Settings"):
                    dpg.add_spacer(height=8)
                    dpg.add_input_text(label="JSON Path", default_value="", readonly=True,
                                       tag="json_path_input", width=-75, no_horizontal_scroll=True, enabled=False)
                    
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="Select File", callback=self.select_json_file)
                        dpg.add_button(label="Rename JSON", callback=self.show_rename_popup)
                    
                    dpg.add_spacer(height=12)
                    dpg.add_separator()
                    dpg.add_spacer(height=12)
                    
                    dpg.add_checkbox(label="AlwaysOnTop Enabled", default_value=self.ALWAYS_ON_TOP,
                                     callback=self.toggle_always_on_top, tag="always_on_top_checkbox")
                    
                    dpg.add_checkbox(label="Automatically set VariableReloading",
                                     default_value=self.auto_variable_reloading,
                                     callback=self.toggle_auto_variable_reloading,
                                     tag="auto_variable_reloading_checkbox")
                    
                    # Toggle Overlay Keybind
                    with dpg.group(horizontal=True):
                        dpg.add_text("Toggle Overlay Keybind:")
                        dpg.add_button(label=f"{self.hotkey}", tag="toggle_overlay_keybind_button",
                                       callback=self.set_toggle_overlay_keybind)
                        dpg.add_button(label="X", callback=self.clear_toggle_overlay_keybind, width=25,
                                       tag="clear_toggle_keybind_button", show=(self.hotkey != self.default_hotkey))
                    
                    dpg.add_spacer(height=12)
                    dpg.add_separator()
                    dpg.add_spacer(height=12)
                    
                    dpg.add_button(label="Import JSON", callback=self.show_json_import_popup)
                    dpg.add_button(label="Export JSON", callback=self.export_json)
                    dpg.add_button(label="Refresh ApplicationSettings", callback=self.import_latest_from_roblox)
                    dpg.add_button(label="Clear Flags", callback=self.show_clear_confirmation)
                    
                    dpg.add_spacer(height=8)
                    dpg.add_text("", tag="json_feedback")
                    dpg.add_separator()
                
                # Developer Options tab - only shown when EnableRAT is True
                if self.enable_rat:
                    with dpg.tab(label="Developer Options"):
                        dpg.add_spacer(height=8)
                        dpg.add_text("Developer Options", color=dpg.mvThemeCol_Text)
                        dpg.add_spacer(height=8)
                        dpg.add_separator()
                        dpg.add_spacer(height=8)
                        
                        # Share theme with ApplicationSettings checkmark
                        dpg.add_checkbox(label="Share theme with ApplicationSettings window", 
                                        tag="share_theme_checkbox",
                                        default_value=getattr(self, 'share_theme_with_appsettings', False),
                                        callback=self.toggle_share_theme)
                        
                        # ZFlag checkmark
                        dpg.add_checkbox(label="Use ZFlag Channel in ApplicationSettings", 
                                        tag="zflag_channel_checkbox",
                                        default_value=self.use_zflag_channel,
                                        callback=self.toggle_zflag_channel)
                        
                        # Remove size limit checkmark
                        dpg.add_checkbox(label="Remove Flag Browser size limit",
                                        tag="remove_size_limit_checkbox",
                                        default_value=self.remove_size_limit,
                                        callback=self.toggle_remove_size_limit)
                        
                        # Show suffix flags in ApplicationSettings checkmark
                        dpg.add_checkbox(label="Show suffix flags in ApplicationSettings",
                                        tag="show_suffix_appsettings_checkbox",
                                        default_value=self.show_suffix_in_appsettings,
                                        callback=self.toggle_show_suffix_in_appsettings)
                        
                        # Convert suffix flags to base flags checkmark
                        dpg.add_checkbox(label="Convert suffix flags to base flags (_PlaceFilter, _UniverseFilter)",
                                        tag="convert_suffix_checkbox",
                                        default_value=self.convert_suffix_to_base,
                                        callback=self.toggle_convert_suffix)
                        dpg.add_spacer(height=8)
                        
                        dpg.add_separator()
                        dpg.add_spacer(height=8)
                        
                        # Fetch Flags button
                        dpg.add_button(label="Fetch Latest Flags", callback=self.fetch_flags_manual, width=-1)
                        dpg.add_text("", tag="fetch_flags_feedback", color=[0, 255, 0])
                        dpg.add_spacer(height=12)
                        dpg.add_separator()
                        dpg.add_spacer(height=8)
                        
                        # Reset to Default button
                        dpg.add_button(label="Reset to Default JSON", callback=self.reset_to_default_json, width=-1)
                        dpg.add_text("", tag="reset_json_feedback", color=[0, 255, 0])
                        dpg.add_spacer(height=12)
                        dpg.add_separator()
                        dpg.add_spacer(height=8)

            with dpg.group(horizontal=True):
                dpg.add_spacer(width=7)
                dpg.add_text("© 2026 Flag Browser | Made by lumyna.cc", 
                             tag="footer_text", 
                             color=self.footer_colors.get(self.current_theme, [140, 140, 140]))

    def fetch_flags_manual(self, sender=None, app_data=None):
        """Manually fetch flags from GitHub"""
        try:
            self.fetch_flags()
            self.update_flag_list()
            self.show_developer_feedback("fetch_flags_feedback", "Flags fetched successfully!", [0, 255, 0])
        except Exception as e:
            self.show_developer_feedback("fetch_flags_feedback", f"Failed to fetch flags: {e}", [255, 0, 0])

    def reset_to_default_json(self, sender=None, app_data=None):
        """Reset the JSON file to default settings"""
        try:
            # Backup current JSON with the previous file's name and content
            old_json_path = self.JSON_PATH
            if os.path.exists(old_json_path):
                backup_name = os.path.splitext(os.path.basename(old_json_path))[0]
                backup_path = os.path.join(os.path.dirname(old_json_path), f"{backup_name}.json.backup")
                shutil.copy2(old_json_path, backup_path)
            
            # Determine which URL to use based on ZFlag checkbox
            url = self.ZFLAG_URL if self.use_zflag_channel else self.ROBLOX_SETTINGS_URL
            
            # Fetch latest settings from the appropriate URL
            r = requests.get(url, verify=False, timeout=15)
            data = r.json()
            app = data.get("applicationSettings", {})
            
            app_settings = app.copy()
            
            # Inject DynamicVariableReloading if auto-reloading is enabled
            if self.auto_variable_reloading:
                app_settings[self.VARIABLE_RELOADING_FLAG] = "1"
            
            default_data = {
                "applicationSettings": app_settings,
                "disabledFlags": {},
                "keybinds": {},
                "flagOrder": [],
                "originalApplicationSettings": app.copy()
            }
            
            # Remove the old JSON file if it exists
            if os.path.exists(old_json_path):
                os.remove(old_json_path)
            
            # Reset JSON path to default (fiddler.json)
            self.JSON_PATH = self.DEFAULT_JSON_PATH
            
            # Write the new default JSON file
            with open(self.JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=4)
            
            # Reset config.json to clear the custom_json_path
            try:
                config = {}
                if os.path.exists("config.json"):
                    with open("config.json", "r", encoding="utf-8") as f:
                        config = json.load(f)
                config["custom_json_path"] = ""  # Clear the custom path
                with open("config.json", "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=4)
            except:
                pass
            
            # Reload the data
            self.load_json_data()
            self.update_enabled_flags_list()
            self.update_json_path_display()
            self.appsettings_flag_groups.clear()
            self.refresh_application_settings_list()
            
            channel_name = "ZFlag" if self.use_zflag_channel else "default"
            self.show_developer_feedback("reset_json_feedback", f"JSON reset to {channel_name} default successfully! Backup created.", [0, 255, 0])
        except Exception as e:
            self.show_developer_feedback("reset_json_feedback", f"Reset failed: {e}", [255, 0, 0])

    def clear_temp_cache(self, sender=None, app_data=None):
        """Clear the .temp folder cache"""
        try:
            if os.path.exists(".temp"):
                shutil.rmtree(".temp", ignore_errors=True)
                os.makedirs(".temp", exist_ok=True)
                self._create_hidden_temp_folder()
                self.show_developer_feedback("clear_cache_feedback", "Temp cache cleared successfully!", [0, 255, 0])
            else:
                self.show_developer_feedback("clear_cache_feedback", "No temp cache found.", [255, 255, 0])
        except Exception as e:
            self.show_developer_feedback("clear_cache_feedback", f"Failed to clear cache: {e}", [255, 0, 0])

    def open_logs_folder(self, sender=None, app_data=None):
        """Open the logs folder (creates logs directory if needed)"""
        logs_dir = os.path.join(self.APP_DIR, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        os.startfile(logs_dir)

    def reload_json_data(self, sender=None, app_data=None):
        """Reload JSON data from disk"""
        try:
            self.load_json_data()
            self.update_enabled_flags_list()
            self.appsettings_flag_groups.clear()
            self.refresh_application_settings_list()
            self.refresh_presets_list()
            self.show_developer_feedback("reload_json_feedback", "JSON data reloaded successfully!", [0, 255, 0])
        except Exception as e:
            self.show_developer_feedback("reload_json_feedback", f"Failed to reload: {e}", [255, 0, 0])

    def show_developer_feedback(self, tag, message, color):
        """Show feedback message in Developer Options tab"""
        if dpg.does_item_exist(tag):
            dpg.set_value(tag, message)
            dpg.configure_item(tag, color=color)
            threading.Timer(3.0, lambda: dpg.set_value(tag, "") if dpg.does_item_exist(tag) else None).start()

    def create_presets_window(self):
        with dpg.window(label="Presets", tag="presets_window",
                        width=350, height=500, pos=[600, 100], show=False,
                        no_collapse=False, no_close=False):
            dpg.bind_item_theme("presets_window", self.presets_theme)
            
            dpg.add_text("Saved Presets")
            dpg.add_button(label="Create New Preset", callback=self.show_create_preset_window, width=-1)
            dpg.add_button(label="Import Preset", callback=self.show_import_preset_popup, width=-1)
            
            with dpg.child_window(tag="presets_list_child", autosize_x=True, autosize_y=True):
                pass
            
            self.refresh_presets_list()

    def create_customize_window(self):
        with dpg.window(label="Customize", tag="customize_window",
                        width=270, height=450, pos=[600, 100], show=False,
                        no_collapse=False, no_close=False):
            dpg.bind_item_theme("customize_window", self.customize_theme)
            
            dpg.add_text("Theme Selection")
            dpg.add_spacer(height=10)
            
            dpg.add_radio_button(items=["Pink Theme (default)", "iM sO gReEn", "OG Flag Browser", "Custom theme"], 
                                default_value="Pink Theme (default)" if self.current_theme == "pink" else "iM sO gReEn" if self.current_theme == "iM sO gReEn" else "OG Flag Browser" if self.current_theme == "og_flagbrowser" else "Custom theme",
                                callback=self.theme_radio_callback, 
                                tag="theme_radio")

            with dpg.group(tag="custom_apply_group", show=(self.current_theme == "custom_user")):
                dpg.add_button(label="Apply Custom Theme Changes", callback=self.apply_custom_theme_changes, width=-1)

            with dpg.group(tag="custom_user_color_section", show=(self.current_theme == "custom_user")):
                dpg.add_separator()
                dpg.add_text("Custom theme colors")
                dpg.add_spacer(height=8)

                color_list = [
                    ("WindowBg", dpg.mvThemeCol_WindowBg),
                    ("ChildBg", dpg.mvThemeCol_ChildBg),
                    ("PopupBg", dpg.mvThemeCol_PopupBg),
                    ("Border", dpg.mvThemeCol_Border),
                    ("Text", dpg.mvThemeCol_Text),
                    ("TextDisabled", dpg.mvThemeCol_TextDisabled),
                    ("Tab", dpg.mvThemeCol_Tab),
                    ("TabHovered", dpg.mvThemeCol_TabHovered),
                    ("TabActive", dpg.mvThemeCol_TabActive),
                    ("Button", dpg.mvThemeCol_Button),
                    ("ButtonHovered", dpg.mvThemeCol_ButtonHovered),
                    ("ButtonActive", dpg.mvThemeCol_ButtonActive),
                    ("FrameBg", dpg.mvThemeCol_FrameBg),
                    ("FrameBgHovered", dpg.mvThemeCol_FrameBgHovered),
                    ("FrameBgActive", dpg.mvThemeCol_FrameBgActive),
                    ("TitleBg", dpg.mvThemeCol_TitleBg),
                    ("TitleBgActive", dpg.mvThemeCol_TitleBgActive),
                    ("TitleBgCollapsed", dpg.mvThemeCol_TitleBgCollapsed),
                    ("ScrollbarBg", dpg.mvThemeCol_ScrollbarBg),
                    ("ScrollbarGrab", dpg.mvThemeCol_ScrollbarGrab),
                    ("ScrollbarGrabHovered", dpg.mvThemeCol_ScrollbarGrabHovered),
                    ("ScrollbarGrabActive", dpg.mvThemeCol_ScrollbarGrabActive),
                    ("CheckMark", dpg.mvThemeCol_CheckMark),
                    ("SliderGrab", dpg.mvThemeCol_SliderGrab),
                    ("SliderGrabActive", dpg.mvThemeCol_SliderGrabActive),
                    ("ResizeGrip", dpg.mvThemeCol_ResizeGrip),
                    ("ResizeGripHovered", dpg.mvThemeCol_ResizeGripHovered),
                    ("ResizeGripActive", dpg.mvThemeCol_ResizeGripActive),
                    ("Separator", dpg.mvThemeCol_Separator),
                ]

                for label_text, col_const in color_list:
                    default_val = self.custom_user_theme_colors.get(col_const, [255, 255, 255])
                    dpg.add_color_edit(label=label_text, default_value=default_val,
                                       tag=f"custom_color_{col_const}",
                                       no_alpha=True,
                                       no_inputs=True)

                dpg.add_separator()
                dpg.add_text("Feedback & Footer Colors")
                dpg.add_spacer(height=8)

                dpg.add_color_edit(label="FeedbackSuccess", default_value=self.custom_feedback_success,
                                   tag="custom_feedback_success", no_alpha=True, no_inputs=True)

                dpg.add_color_edit(label="FeedbackFail", default_value=self.custom_feedback_fail,
                                   tag="custom_feedback_fail", no_alpha=True, no_inputs=True)

                dpg.add_color_edit(label="Footer", default_value=self.custom_footer_color,
                                   tag="custom_footer_color", no_alpha=True, no_inputs=True)

    def create_application_settings_window(self):
        with dpg.window(label="ApplicationSettings", tag="application_settings_window",
                        width=600, height=435, pos=[300, 150], show=False,
                        no_collapse=False, no_close=False):
            dpg.bind_item_theme("application_settings_window", self.og_flagbrowser2_theme)
            
            # Filter row
            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="appsettings_filter_input",
                                   hint="filter",
                                   width=-200,
                                   callback=self.update_appsettings_filter)
                dpg.add_button(label="Clear", 
                               callback=self.clear_appsettings_filter,
                              )

            # Radio buttons
            dpg.add_radio_button(items=["Local", "Dynamic", "Static"],
                                 default_value="Local",
                                 callback=self.set_appsettings_category,
                                 tag="appsettings_category_radio",
                                 horizontal=True)

            # Flag list
            with dpg.child_window(tag="appsettings_list", 
                                  autosize_x=True, 
                                  autosize_y=True):
                pass
            
            # Apply item spacing style directly so it persists through theme changes
            with dpg.theme() as appsettings_spacing_theme:
                with dpg.theme_component(dpg.mvAll):
                    dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 4, 4)
            dpg.bind_item_theme("appsettings_list", appsettings_spacing_theme)
            
            # Initial load
            self.refresh_application_settings_list()

    def create_proxy_window(self):
        with dpg.window(label="Network Capture", tag="proxy_window",
                        width=500, height=650, pos=[350, 100], show=False,
                        no_collapse=False, no_close=False):
            dpg.bind_item_theme("proxy_window", self.flag_browser_theme)
            
            # Network Capture status
            with dpg.group(horizontal=True):
                dpg.add_text("Network Capture:")
                dpg.add_text("Stopped", tag="proxy_status_text", color=self.get_feedback_color([255, 0, 0]))
            
            dpg.add_spacer(height=10)
            
            dpg.add_spacer(height=5)
            
            # Fallback DNS configuration
            dpg.add_text("Fallback DNS:")
            with dpg.group(horizontal=True):
                dpg.add_input_text(default_value=self.proxy_settings.get("fallback_dns", "1.1.1.1"),
                                 tag="proxy_fallback_dns_input",
                                 width=-120,
                                 callback=self._on_fallback_dns_changed)
                dpg.add_button(label="Use Default", callback=self._reset_fallback_dns, width=110)
            

            
            # File paths (auto-managed)
            dpg.add_text("CA Certificate:")
            ca_display = self.proxy_settings["ca_cert_path"] or "Auto-managed"
            dpg.add_input_text(default_value=ca_display, 
                             tag="ca_cert_path_display", 
                             readonly=True, 
                             width=-1)
            
            dpg.add_spacer(height=5)
            
            dpg.add_text("CA Key:")
            key_display = self.proxy_settings["ca_key_path"] or "Auto-managed"
            dpg.add_input_text(default_value=key_display, 
                             tag="ca_key_path_display", 
                             readonly=True, 
                             width=-1)
            
            dpg.add_spacer(height=10)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Reset Certificate button (regenerate + reinstall everything)
            dpg.add_button(label="Reset Certificate", 
                          callback=self._reset_certificates, width=-1)
            dpg.add_text("", tag="cert_gen_feedback")

            
            dpg.add_spacer(height=10)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Control buttons
            with dpg.group(horizontal=True):
                dpg.add_button(label="Start Capture", 
                             callback=self.toggle_proxy, 
                             tag="proxy_start_button",
                             width=120)
                dpg.add_button(label="Clear Logs", 
                             callback=self.clear_proxy_logs,
                             width=100)
            
            dpg.add_text("", tag="proxy_feedback")
            
            dpg.add_spacer(height=10)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Statistics
            with dpg.group(horizontal=True):
                dpg.add_text("Intercepted:", tag="intercepted_count_text", color=self.get_feedback_color([0, 255, 0]))
                dpg.add_text("0", tag="intercepted_count")
                dpg.add_text("  |  ")
                dpg.add_text("Pass-through:", tag="passthrough_count_text")
                dpg.add_text("0", tag="passthrough_count")
            
            dpg.add_spacer(height=10)
            
            # Logs
            dpg.add_text("Request Logs:")
            with dpg.child_window(tag="proxy_logs_list", autosize_x=True, height=200):
                dpg.add_text("No logs yet", tag="no_logs_text")



    def _save_proxy_settings(self):
        """Save proxy settings to config.json"""
        try:
            config = {}
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
            config["roblox_cacert_path"] = self.proxy_settings.get("roblox_cacert_path", "")
            config["roblox_versions_dir"] = self.proxy_settings.get("roblox_versions_dir", "")
            config["ca_cert_path"] = self.proxy_settings.get("ca_cert_path", "")
            config["ca_key_path"] = self.proxy_settings.get("ca_key_path", "")
            config["fallback_dns"] = self.proxy_settings.get("fallback_dns", "1.1.1.1")
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving proxy settings: {e}")


    def _delete_all_diversion_certs_from_store(self):
        """Delete ALL Diversion/FlagBrowser certs from the Windows trusted root store.
        Returns (deleted_count, error_message_or_None)"""
        deleted_count = 0
        try:
            # Delete by CN "Diversion Root CA" to catch all old + current certs
            for _ in range(20):
                result = subprocess.run(
                    ['certutil', '-delstore', 'Root', 'Diversion Root CA'],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                stdout_lower = result.stdout.lower()
                if result.returncode == 0 and ("deleted" in stdout_lower or "succeeded" in stdout_lower):
                    deleted_count += 1
                else:
                    break
            
            # Also try the old serial-based deletion if we have a current cert
            cert_path = self.proxy_settings.get("ca_cert_path", "")
            if cert_path and os.path.exists(cert_path):
                try:
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                    cert_obj = x509.load_pem_x509_certificate(cert_data)
                    serial_hex = format(cert_obj.serial_number, 'x')
                    for _ in range(20):
                        result = subprocess.run(
                            ['certutil', '-delstore', 'Root', serial_hex],
                            capture_output=True, text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                        stdout_lower = result.stdout.lower()
                        if result.returncode == 0 and ("deleted" in stdout_lower or "succeeded" in stdout_lower):
                            deleted_count += 1
                        else:
                            break
                except:
                    pass
        except Exception as e:
            return deleted_count, str(e)
        
        return deleted_count, None

    def _kill_roblox(self):
        """Force-close all RobloxPlayerBeta.exe instances.
        Certificate changes while Roblox is running would cause TLS failures."""
        try:
            subprocess.run(
                ['taskkill', '/F', '/IM', 'RobloxPlayerBeta.exe'],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass



    def _find_roblox_version_folders(self):
        """Auto-detect all Roblox/Bloxstrap-fork version folders containing ssl/cacert.pem"""
        seen_paths = set()
        results = []
        
        # Collect all Versions directories to scan
        versions_dirs = []
        
        # 1. Default Roblox path
        default_versions = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Roblox', 'Versions')
        if os.path.exists(default_versions):
            versions_dirs.append(default_versions)
        
        # 2. User-selected Versions directory (supports Froststrap, Fishstrap, etc.)
        user_versions = self.proxy_settings.get("roblox_versions_dir", "")
        if user_versions and os.path.exists(user_versions):
            if os.path.normpath(user_versions) not in [os.path.normpath(d) for d in versions_dirs]:
                versions_dirs.append(user_versions)
        
        # 3. Backward compat: derive from old roblox_cacert_path
        user_cacert = self.proxy_settings.get("roblox_cacert_path", "")
        if user_cacert and os.path.exists(user_cacert):
            try:
                ssl_dir = os.path.dirname(user_cacert)
                version_dir = os.path.dirname(ssl_dir)
                derived_versions = os.path.dirname(version_dir)
                if os.path.basename(version_dir).startswith('version-') and os.path.exists(derived_versions):
                    if os.path.normpath(derived_versions) not in [os.path.normpath(d) for d in versions_dirs]:
                        versions_dirs.append(derived_versions)
            except:
                pass
        
        # Scan all Versions directories
        for versions_dir in versions_dirs:
            try:
                for entry in os.listdir(versions_dir):
                    full_path = os.path.join(versions_dir, entry)
                    norm = os.path.normpath(full_path)
                    if norm in seen_paths:
                        continue
                    if os.path.isdir(full_path) and entry.startswith('version-'):
                        cacert_path = os.path.join(full_path, 'ssl', 'cacert.pem')
                        if os.path.exists(cacert_path):
                            mtime = os.path.getmtime(full_path)
                            results.append((mtime, full_path, cacert_path, entry))
                            seen_paths.add(norm)
            except:
                pass
        
        results.sort(reverse=True)  # Newest first
        return results
    
    def _get_clean_original_cacert(self):
        """Get a clean original cacert.pem (without any FlagBrowser certs) from the best source"""
        source_path = None
        
        # Try user-selected Versions directory first - use the most recently modified version
        versions_dir = self.proxy_settings.get("roblox_versions_dir", "")
        if versions_dir and os.path.exists(versions_dir):
            version_folders = self._find_version_folders_in(versions_dir)
            if version_folders:
                # Sort by version folder mtime (newest first) to pick the freshest cacert.pem
                version_folders.sort(
                    key=lambda x: os.path.getmtime(os.path.dirname(os.path.dirname(x[0]))),
                    reverse=True
                )
                source_path = version_folders[0][0]
        
        # Fall back to auto-detect
        if not source_path:
            roblox_folders = self._find_roblox_version_folders()
            if roblox_folders:
                source_path = roblox_folders[0][2]  # cacert_path from newest version
        
        if not source_path:
            return None, "Could not find Roblox's cacert.pem. Select Versions folder first."
        
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                content = f.read().rstrip()
            
            # Strip any existing Diversion/FlagBrowser certs from the content
            clean = content
            idx = 0
            while idx < len(clean):
                begin = clean.find("-----BEGIN CERTIFICATE-----", idx)
                if begin == -1:
                    break
                end = clean.find("-----END CERTIFICATE-----", begin)
                if end == -1:
                    break
                end += len("-----END CERTIFICATE-----")
                
                cert_block = clean[begin:end]
                try:
                    cert_der = ssl.PEM_cert_to_DER_cert(cert_block)
                    cert_obj = x509.load_der_x509_certificate(cert_der)
                    
                    # Check org name (covers both old "FlagBrowser" and current "lumyna.cc")
                    org_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    org_name = org_attrs[0].value if org_attrs else ""
                    
                    # Check common name for "Diversion Root CA"
                    cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    cn_name = cn_attrs[0].value if cn_attrs else ""
                    
                    is_ours = (
                        (org_name and ("FlagBrowser" in org_name or "lumyna.cc" in org_name))
                        or ("Diversion" in cn_name)
                    )
                    
                    if is_ours:
                        remove_start = begin
                        if remove_start > 0 and clean[remove_start - 1] == '\n':
                            remove_start -= 1
                        clean = clean[:remove_start] + clean[end:]
                        continue
                except:
                    pass
                idx = end
            
            return clean.rstrip(), None
        except Exception as e:
            return None, f"Error reading cacert.pem: {e}"
    
    def _build_modified_cacert(self):
        """Build modified cacert.pem with our CA appended, save to Modifications/ssl/"""
        cert_path = self.proxy_settings.get("ca_cert_path", "")
        if not cert_path or not os.path.exists(cert_path):
            return False, "No CA certificate found. Generate one first."
        
        try:
            with open(cert_path, 'r', encoding='utf-8') as f:
                ca_content = f.read().strip()
        except Exception as e:
            return False, f"Error reading CA cert: {e}"
        
        original_content, error = self._get_clean_original_cacert()
        if original_content is None:
            return False, error
        
        # Build final: original + our CA
        modified = original_content + "\n" + ca_content + "\n"
        
        mods_ssl_dir = os.path.join(self.APP_DIR, "Modifications", "ssl")
        os.makedirs(mods_ssl_dir, exist_ok=True)
        mod_cacert_path = os.path.join(mods_ssl_dir, "cacert.pem")
        
        try:
            with open(mod_cacert_path, 'w', encoding='utf-8') as f:
                f.write(modified)
            return True, mod_cacert_path
        except PermissionError:
            return False, "Permission denied! Run as Admin."
        except Exception as e:
            return False, f"Error writing modifications: {e}"
    
    def _apply_modifications(self):
        """Apply Modifications/ssl/cacert.pem to all version folders in the selected Versions directory."""
        mod_cacert = os.path.join(self.APP_DIR, "Modifications", "ssl", "cacert.pem")
        if not os.path.exists(mod_cacert):
            return False, "No modifications to apply. Install CA to Roblox first."
        
        versions_dir = self.proxy_settings.get("roblox_versions_dir", "")
        applied = []
        errors = []
        
        if versions_dir and os.path.exists(versions_dir):
            # Apply to ALL version-*/ssl/cacert.pem in the selected Versions folder
            version_folders = self._find_version_folders_in(versions_dir)
            
            if not version_folders:
                return False, "No version folders found in selected Versions directory."
            
            for cacert_path, ver_name in version_folders:
                try:
                    shutil.copy2(mod_cacert, cacert_path)
                    applied.append(ver_name)
                except Exception as e:
                    errors.append(f"{ver_name}: {e}")
        else:
            # No custom path - fall back to auto-detected Roblox paths
            for _, folder_path, cacert_path, version_name in self._find_roblox_version_folders():
                try:
                    shutil.copy2(mod_cacert, cacert_path)
                    applied.append(version_name)
                except Exception as e:
                    errors.append(f"{version_name}: {e}")
        
        if applied:
            return True, f"Applied to {len(applied)} version(s)"
        if errors:
            return False, f"Failed to apply: {'; '.join(errors)}"
        return False, "No Roblox version folders found to apply to."
    
    def _find_version_folders_in(self, versions_dir):
        """Find all version-*/ssl/cacert.pem paths within a specific Versions directory.
        Returns list of (cacert_path, version_name) tuples."""
        results = []
        try:
            for entry in os.listdir(versions_dir):
                full_path = os.path.join(versions_dir, entry)
                if os.path.isdir(full_path) and entry.startswith('version-'):
                    cacert_path = os.path.join(full_path, 'ssl', 'cacert.pem')
                    if os.path.exists(cacert_path):
                        results.append((cacert_path, entry))
        except:
            pass
        return results


    def toggle_proxy(self, sender=None, app_data=None):
        """Start or stop network capture"""
        if not self.proxy.running:
            # Start capture
            ca_cert = self.proxy_settings["ca_cert_path"]
            ca_key = self.proxy_settings["ca_key_path"]
            # Always use the flag browser's JSON path
            json_path = self.JSON_PATH
            
            if not json_path or not os.path.exists(json_path):
                self.show_proxy_feedback("Please select a valid JSON file to serve!", [255, 0, 0])
                return
            
            # Check if CA cert is configured
            if not ca_cert or not ca_key or not os.path.exists(ca_cert) or not os.path.exists(ca_key):
                self.show_proxy_feedback("No CA certificate configured. Generate one first.", [255, 255, 0])
                return
            
            # Auto-inject CA into all Roblox installations before starting
            try:
                ca_pem = Path(ca_cert).read_text(encoding='utf-8')
                _install_ca_into_roblox(ca_pem)
            except Exception:
                pass
            
            fallback_dns = self.proxy_settings.get("fallback_dns", "1.1.1.1")
            success, message = self.proxy.start(443, json_path, ca_cert, ca_key, fallback_dns=fallback_dns)
            
            if success:
                dpg.set_value("proxy_status_text", "Active")
                dpg.configure_item("proxy_status_text", color=self.get_feedback_color([0, 255, 0]))
                dpg.set_item_label("proxy_start_button", "Stop Capture")
                self.show_proxy_feedback(message, [0, 255, 0])
                
                # Wire up cacert protection callback and reset state
                self.proxy.on_client_version_callback = self._on_client_version_passthrough
                self._cacert_protection_active = False
                self._cacert_protection_intercept_count = 0
                
                # Start updating stats
                self._start_proxy_stats_updater()
            else:
                self.show_proxy_feedback(message, [255, 0, 0])
        else:
            # Stop capture
            success, message = self.proxy.stop()
            
            if success:
                dpg.set_value("proxy_status_text", "Stopped")
                dpg.configure_item("proxy_status_text", color=self.get_feedback_color([255, 0, 0]))
                dpg.set_item_label("proxy_start_button", "Start Capture")
                self.show_proxy_feedback(message, [255, 0, 0])

    def _on_fallback_dns_changed(self, sender=None, app_data=None):
        """Update fallback DNS setting"""
        if app_data:
            self.proxy_settings["fallback_dns"] = app_data.strip()
            self._save_proxy_settings()
    
    def _reset_fallback_dns(self, sender=None, app_data=None):
        """Reset fallback DNS to default (1.1.1.1)"""
        self.proxy_settings["fallback_dns"] = "1.1.1.1"
        if dpg.does_item_exist("proxy_fallback_dns_input"):
            dpg.set_value("proxy_fallback_dns_input", "1.1.1.1")
        self._save_proxy_settings()

    def _on_client_version_passthrough(self):
        """Called from the proxy when a /client-version/ request passes through.
        Starts the cacert protection loop that continuously checks and reapplies
        the Diversion cert to all Roblox installations until 10 settings interceptions occur."""
        if self._cacert_protection_active:
            return  # Already running
        
        # Need CA cert to inject
        cert_path = self.proxy_settings.get("ca_cert_path", "")
        if not cert_path or not os.path.exists(cert_path):
            return
        
        # Record the interception count at the moment /client-version/ was seen
        self._cacert_protection_active = True
        self._cacert_protection_base_count = self.proxy.intercepted_count if self.proxy else 0
        
        def protection_loop():
            try:
                ca_pem = Path(cert_path).read_text(encoding='utf-8')
                while self._cacert_protection_active and self.proxy and self.proxy.running:
                    # Check if we've exceeded 10 interceptions since activation
                    current_intercepts = self.proxy.intercepted_count
                    since_activation = current_intercepts - self._cacert_protection_base_count
                    if since_activation >= 10:
                        self._cacert_protection_active = False
                        if self.proxy:
                            self.proxy.add_log("[SYSTEM] Cacert protection ended (10 interceptions reached)")
                        break
                    
                    # Re-inject CA into all Roblox installations (registry-based)
                    try:
                        _install_ca_into_roblox(ca_pem)
                    except:
                        pass
                    
                    time.sleep(0.5)  # Check every 0.5 seconds
            except:
                pass
            finally:
                self._cacert_protection_active = False
        
        thread = threading.Thread(target=protection_loop, daemon=True)
        thread.start()
        if self.proxy:
            self.proxy.add_log("[SYSTEM] Cacert protection started (watching all Roblox installations)")

    def _strip_our_certs_from_content(self, content):
        """Strip any Diversion/FlagBrowser certificates from cacert.pem content string."""
        clean = content
        idx = 0
        while idx < len(clean):
            begin = clean.find("-----BEGIN CERTIFICATE-----", idx)
            if begin == -1:
                break
            end = clean.find("-----END CERTIFICATE-----", begin)
            if end == -1:
                break
            end += len("-----END CERTIFICATE-----")
            
            cert_block = clean[begin:end]
            try:
                cert_der = ssl.PEM_cert_to_DER_cert(cert_block)
                cert_obj = x509.load_der_x509_certificate(cert_der)
                
                org_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                org_name = org_attrs[0].value if org_attrs else ""
                cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn_name = cn_attrs[0].value if cn_attrs else ""
                
                is_ours = (
                    (org_name and ("FlagBrowser" in org_name or "lumyna.cc" in org_name))
                    or ("Diversion" in cn_name)
                )
                
                if is_ours:
                    remove_start = begin
                    if remove_start > 0 and clean[remove_start - 1] == '\n':
                        remove_start -= 1
                    clean = clean[:remove_start] + clean[end:]
                    continue
            except:
                pass
            idx = end
        
        return clean.rstrip()

    def clear_proxy_logs(self, sender=None, app_data=None):
        """Clear proxy logs"""
        self.proxy.clear_logs()
        if dpg.does_item_exist("proxy_logs_list"):
            dpg.delete_item("proxy_logs_list", children_only=True)
            dpg.add_text("No logs yet", parent="proxy_logs_list", tag="no_logs_text")

    def _start_proxy_stats_updater(self):
        """Request an immediate refresh; do not start a DPG worker thread."""
        self._next_proxy_ui_refresh = 0.0
        self._last_rendered_proxy_logs = None

    def _update_proxy_stats_ui(self):
        """Run only from run(), on DearPyGui's main/render thread."""
        if not self.proxy or not self.proxy.running:
            return
        if not dpg.does_item_exist("proxy_window"):
            return

        if dpg.does_item_exist("intercepted_count"):
            dpg.set_value("intercepted_count", str(self.proxy.intercepted_count))
        if dpg.does_item_exist("passthrough_count"):
            dpg.set_value("passthrough_count", str(self.proxy.passthrough_count))

        logs = self.proxy.get_logs()
        display_logs = tuple(logs[-50:])
        if display_logs == self._last_rendered_proxy_logs:
            return
        self._last_rendered_proxy_logs = display_logs

        if not dpg.does_item_exist("proxy_logs_list"):
            return
        dpg.delete_item("proxy_logs_list", children_only=True)
        if not logs:
            dpg.add_text("No logs yet", parent="proxy_logs_list")
            return

        for log in reversed(display_logs):
            log_text = log if isinstance(log, str) else (
                f"[{log.get('timestamp','')}] {log.get('method','')} {log.get('url','')}"
            )
            if "[SETTINGS]" in log_text:
                color = self.get_feedback_color([0, 255, 0])
            elif "[GAMEJOIN]" in log_text:
                color = [80, 160, 255]
            elif "[HANDSHAKE_FAIL]" in log_text or "[ERROR]" in log_text or "Error" in log_text:
                color = self.get_feedback_color([255, 0, 0])
            elif "[SYSTEM]" in log_text:
                color = [255, 200, 50]
            else:
                color = [180, 180, 180]
            dpg.add_text(log_text, color=color, parent="proxy_logs_list")

    def toggle_zflag_channel(self, sender, app_data):
        """Toggle between normal and ZFlag channel URLs"""
        self.use_zflag_channel = app_data
        self._save_developer_options_config()
        
        # Save the preference to config
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                config = json.load(f)
            config["use_zflag_channel"] = str(self.use_zflag_channel)
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass
        
        # Fetch new settings from the selected URL
        url = self.ZFLAG_URL if self.use_zflag_channel else self.ROBLOX_SETTINGS_URL
        
        try:
            r = requests.get(url, verify=False, timeout=15)
            r.raise_for_status()
            data = r.json()
            new_settings = data.get("applicationSettings", {})
            
            # Update originalApplicationSettings with new channel values
            self.settings["originalApplicationSettings"] = new_settings.copy()
            
            # Rebuild applicationSettings: start with new channel's flags,
            # then overlay user-modified values (from flagOrder) on top.
            # This removes channel-exclusive unmodified flags from the list.
            flag_order = self.settings.get("flagOrder", [])
            disabled_flags = self.settings.get("disabledFlags", {})
            old_app_settings = self.settings.get("applicationSettings", {})
            
            # Start fresh with new channel flags
            new_app_settings = new_settings.copy()
            
            # Restore user-modified flags (flagOrder tracks what user touched)
            for flag in flag_order:
                if flag in old_app_settings:
                    # User had this enabled - keep the user's value
                    new_app_settings[flag] = old_app_settings[flag]
                # disabled flags stay in disabledFlags, no action needed
            
            self.settings["applicationSettings"] = new_app_settings
            
            # Save and refresh
            self.save_json()
            
            # Refresh ApplicationSettings window
            self.appsettings_flag_groups.clear()
            if dpg.does_item_exist("appsettings_list"):
                self.refresh_application_settings_list()
            
            # Refresh modified flags list
            self.update_enabled_flags_list()
            
            channel_name = "ZFlag" if self.use_zflag_channel else "default"
            self.show_feedback(f"Switched to {channel_name} channel successfully!", [0, 255, 0])
            
        except Exception as e:
            # Revert checkbox if fetch fails
            self.use_zflag_channel = not self.use_zflag_channel
            if dpg.does_item_exist("zflag_channel_checkbox"):
                dpg.set_value("zflag_channel_checkbox", self.use_zflag_channel)
            self.show_feedback(f"Failed to switch channel: {str(e)}", [255, 0, 0])

    def refresh_application_settings_list(self, sender=None, app_data=None):
        """Completely rebuild the ApplicationSettings list - only called on initial load or manual refresh"""
        if not dpg.does_item_exist("appsettings_list"):
            return

        dpg.lock_mutex()
        try:
            # Clear the cache
            self.appsettings_flag_groups.clear()
            
            dpg.delete_item("appsettings_list", children_only=True)

            # Get all relevant data sources
            app_settings = self.settings.get("applicationSettings", {})
            disabled_flags = self.settings.get("disabledFlags", {})
            original = self.settings.get("originalApplicationSettings", {})
            
            # Start with all flags from original ApplicationSettings
            combined_settings = original.copy()
            
            # For enabled flags, ONLY include them if they exist in original
            for flag, value in app_settings.items():
                if flag in original:
                    combined_settings[flag] = value
            
            # For disabled flags, ONLY include them if they exist in original
            for flag, value in disabled_flags.items():
                if flag in original:
                    combined_settings[flag] = value

            if not combined_settings:
                dpg.add_text("No ApplicationSettings loaded.", parent="appsettings_list")
                return

            allowed_prefixes = ("DF", "FF", "FInt", "FS", "SF")
            
            # Process flags to handle suffixes
            processed_flags = {}
            # All known suffixes that indicate a variant flag
            suffixes_to_process = ["_PlaceFilter", "_UniverseFilter", "_IXP", "_DataCenterFilter"]
            
            # Track which base flags came from suffix conversion
            suffix_source_map = {}  # base_name -> original suffix flag name
            
            for flag in sorted(combined_settings.keys()):
                # Check if flag matches allowed prefixes
                if not any(flag.startswith(p) for p in allowed_prefixes):
                    continue
                # Skip flags starting with those prefixes
                if flag.startswith(("DFLog", "FLog")):
                    continue
                
                value = combined_settings[flag]
                
                # Check if this flag has a suffix we want to process
                has_suffix = False
                base_name = flag
                for suffix in suffixes_to_process:
                    if flag.endswith(suffix):
                        base_name = flag[:-len(suffix)]
                        has_suffix = True
                        break
                
                if has_suffix:
                    if self.convert_suffix_to_base:
                        # Convert: strip suffix and extract first value
                        if base_name not in processed_flags and base_name not in combined_settings:
                            if isinstance(value, str) and ";" in value:
                                first_value = value.split(";")[0]
                                processed_flags[base_name] = first_value
                            else:
                                processed_flags[base_name] = value
                        suffix_source_map[base_name] = flag
                    # If base flag already exists/processed, skip this suffix
                    elif self.show_suffix_in_appsettings:
                        # Keep as suffix flag - show in ApplicationSettings
                        processed_flags[flag] = value
                    # else: hide suffix flags (default behavior)
                else:
                    # No suffix, just add as is (but only if not already processed from a suffix)
                    if flag not in processed_flags:
                        processed_flags[flag] = value
            
            # Store the full flag list for filtering
            self.all_appsettings_flags = sorted(processed_flags.keys())

            # Create UI for all processed flags
            for flag in self.all_appsettings_flags:
                value = processed_flags[flag]
                
                # Determine if this flag is modified
                # For converted suffix flags, compare against the suffix original's first value
                if flag in suffix_source_map:
                    # This is a converted base flag - compare its value against the suffix's original first value
                    source_suffix_flag = suffix_source_map[flag]
                    suffix_orig = original.get(source_suffix_flag, "N/A")
                    if suffix_orig != "N/A" and isinstance(suffix_orig, str) and ";" in suffix_orig:
                        orig_first = suffix_orig.split(";")[0]
                    else:
                        orig_first = suffix_orig
                    is_modified = str(value) != str(orig_first) and orig_first != "N/A"
                else:
                    orig_val = original.get(flag, "N/A")
                    is_modified = str(value) != str(orig_val) and orig_val != "N/A"

                # Create a group for this flag row
                group_tag = f"appsettings_group_{flag}"
                with dpg.group(parent="appsettings_list", horizontal=True, tag=group_tag):
                    self.create_appsettings_value_widget(flag, value)
                    dpg.add_text(flag)
                    if is_modified:
                        dpg.add_text("*", color=self.get_asterisk_color(), tag=f"appsettings_asterisk_{flag}")
                
                # Store in cache with visibility flag
                self.appsettings_flag_groups[flag] = {
                    "group": group_tag,
                    "is_modified": is_modified,
                    "visible": True
                }
            
            # Apply initial filter
            self._apply_appsettings_filter()

        finally:
            dpg.unlock_mutex()

    def _apply_appsettings_filter(self):
        """Apply the current filter by showing/hiding groups - O(n) but very fast"""
        if not dpg.does_item_exist("appsettings_list"):
            return
        
        dpg.lock_mutex()
        try:
            q = self.appsettings_filter_query.lower().strip()
            cat = self.appsettings_category
            
            # Get original settings for value comparison
            original = self.settings.get("originalApplicationSettings", {})
            app_settings = self.settings.get("applicationSettings", {})
            disabled_flags = self.settings.get("disabledFlags", {})
            
            visible_count = 0
            
            for flag, cache_entry in self.appsettings_flag_groups.items():
                # Check if flag matches filter
                matches_filter = True
                
                # Get current value for this flag
                current_value = None
                if flag in app_settings:
                    current_value = str(app_settings[flag])
                elif flag in disabled_flags:
                    current_value = str(disabled_flags[flag])
                else:
                    current_value = str(original.get(flag, ""))
                
                # Check if query matches flag name OR flag value
                if q:
                    flag_matches = q in flag.lower()
                    value_matches = q in current_value.lower()
                    
                    if not (flag_matches or value_matches):
                        matches_filter = False
                
                # Apply category filter
                if matches_filter:
                    if cat == "dynamic" and not flag.startswith("DF"):
                        matches_filter = False
                    elif cat == "static" and not flag.startswith(("FF", "FInt", "FS", "SF")):
                        matches_filter = False
                
                group_tag = cache_entry["group"]
                if dpg.does_item_exist(group_tag):
                    if matches_filter:
                        dpg.show_item(group_tag)
                        cache_entry["visible"] = True
                        visible_count += 1
                    else:
                        dpg.hide_item(group_tag)
                        cache_entry["visible"] = False
            
            # Show "no flags" message if needed
            self._update_no_flags_message(visible_count)
        finally:
            dpg.unlock_mutex()

    def _update_no_flags_message(self, visible_count):
        """Show or hide the 'no flags match' message"""
        dpg.lock_mutex()
        try:
            no_flags_tag = "appsettings_no_flags_message"
            
            if visible_count == 0:
                if not dpg.does_item_exist(no_flags_tag):
                    dpg.add_text("No flags match the current filter.", 
                                 parent="appsettings_list", 
                                 tag=no_flags_tag)
                else:
                    dpg.show_item(no_flags_tag)
            else:
                if dpg.does_item_exist(no_flags_tag):
                    dpg.hide_item(no_flags_tag)
        finally:
            dpg.unlock_mutex()

    def update_appsettings_filter(self, sender, app_data):
        """Called when user types in the filter box - now instant!"""
        self.appsettings_filter_query = app_data.lower().strip() if app_data else ""
        self._apply_appsettings_filter()

    def clear_appsettings_filter(self, sender=None, app_data=None):
        """Clear button next to the filter input"""
        self.appsettings_filter_query = ""
        if dpg.does_item_exist("appsettings_filter_input"):
            dpg.set_value("appsettings_filter_input", "")
        self._apply_appsettings_filter()

    def set_appsettings_category(self, sender, app_data):
        """Radio buttons: Local / Dynamic / Static"""
        if app_data == "Local":
            self.appsettings_category = "local"
        elif app_data == "Dynamic":
            self.appsettings_category = "dynamic"
        elif app_data == "Static":
            self.appsettings_category = "static"
        self._apply_appsettings_filter()

    def update_flag_list(self, query=""):
        if not dpg.does_item_exist("available_flags_list"): 
            return

        dpg.lock_mutex()
        try:
            scroll_y = dpg.get_y_scroll("available_flags_list") if dpg.does_item_exist("available_flags_list") else 0.0

            dpg.delete_item("available_flags_list", children_only=True)
            q = query.lower()
            for flag in self.flags_list:
                if q in flag.lower():
                    dpg.add_button(label=flag, parent="available_flags_list",
                                   callback=self.select_flag, user_data=flag)

            if scroll_y > 0 and dpg.does_item_exist("available_flags_list"):
                dpg.set_y_scroll("available_flags_list", scroll_y)

        finally:
            dpg.unlock_mutex()

    def is_integer_flag(self, flag):
        if not flag:
            return False
        return flag.startswith(("DFInt", "FInt"))

    def create_appsettings_value_widget(self, flag, value=None):
        """Creates the value widget + +/- buttons"""
        if value is None:
            value = self.settings["applicationSettings"].get(flag, "")
            if value == "" and flag in self.settings.get("disabledFlags", {}):
                value = self.settings["disabledFlags"][flag]

        if self.is_integer_flag(flag):
            # Integer: wide value input + small + / - buttons
            dpg.add_input_text(default_value=str(value), width=150,
                               tag=f"appsettings_int_input_{flag}",
                               callback=self.update_appsettings_value,
                               user_data=flag)
            dpg.add_button(label="+", width=20,
                           callback=self.increment_appsettings_int,
                           user_data=flag)
            dpg.add_button(label="-", width=20,
                           callback=self.decrement_appsettings_int,
                           user_data=flag)

        elif self.should_use_boolean_widget(flag):
            # Boolean: wide True/False button (only for simple True/False values)
            bool_val = str(value).lower() in ("true", "1")
            dpg.add_button(label="True" if bool_val else "False",
                           tag=f"appsettings_bool_button_{flag}",
                           width=198.5,
                           callback=self.toggle_appsettings_bool,
                           user_data=flag)
        elif self.is_boolean_flag(flag):
            # Boolean flag name but complex value (e.g. PlaceFilter/UniverseFilter with semicolons)
            # Show as text input so the user can edit the full value
            dpg.add_input_text(default_value=str(value), width=198.5,
                               tag=f"appsettings_text_input_{flag}",
                               callback=self.update_appsettings_value,
                               user_data=flag)
        else:
            # Normal value: wide input
            dpg.add_input_text(default_value=str(value), width=198.5,
                               tag=f"appsettings_text_input_{flag}",
                               callback=self.update_appsettings_value,
                               user_data=flag)

    def update_appsettings_value(self, sender, app_data, flag):
        """Real-time save when user types in the input"""
        if app_data is None:
            return
        
        # Update settings
        self.settings["applicationSettings"][flag] = app_data
        self.settings["disabledFlags"].pop(flag, None)
        self.save_json()
        
        # Update enabled flags list
        self.update_enabled_flags_list()
        
        # Update the modified indicator using cache
        self.update_appsettings_modified_indicator_cached(flag)

    def increment_appsettings_int(self, sender, app_data, flag):
        try:
            current = 0
            if flag in self.settings["applicationSettings"]:
                current = int(self.settings["applicationSettings"].get(flag, 0))
            elif flag in self.settings["disabledFlags"]:
                current = int(self.settings["disabledFlags"].get(flag, 0))
            else:
                current = int(self.settings.get("originalApplicationSettings", {}).get(flag, 0))
            
            new_value = str(current + 1)
            
            self.settings["applicationSettings"][flag] = new_value
            self.settings["disabledFlags"].pop(flag, None)
            self.save_json()
            
            if dpg.does_item_exist(f"appsettings_int_input_{flag}"):
                dpg.set_value(f"appsettings_int_input_{flag}", new_value)
            
            self.update_enabled_flags_list()
            self.update_appsettings_modified_indicator_cached(flag)
        except:
            pass

    def decrement_appsettings_int(self, sender, app_data, flag):
        try:
            current = 0
            if flag in self.settings["applicationSettings"]:
                current = int(self.settings["applicationSettings"].get(flag, 0))
            elif flag in self.settings["disabledFlags"]:
                current = int(self.settings["disabledFlags"].get(flag, 0))
            else:
                current = int(self.settings.get("originalApplicationSettings", {}).get(flag, 0))
            
            new_value = str(current - 1)
            
            self.settings["applicationSettings"][flag] = new_value
            self.settings["disabledFlags"].pop(flag, None)
            self.save_json()
            
            if dpg.does_item_exist(f"appsettings_int_input_{flag}"):
                dpg.set_value(f"appsettings_int_input_{flag}", new_value)
            
            self.update_enabled_flags_list()
            self.update_appsettings_modified_indicator_cached(flag)
        except:
            pass

    def toggle_appsettings_bool(self, sender, app_data, flag):
        if dpg.does_item_exist(f"appsettings_bool_button_{flag}"):
            current = dpg.get_item_label(f"appsettings_bool_button_{flag}")
            new_label = "True" if current == "False" else "False"
            dpg.set_item_label(f"appsettings_bool_button_{flag}", new_label)
            
            self.settings["applicationSettings"][flag] = new_label
            self.settings["disabledFlags"].pop(flag, None)
            self.save_json()
            
            self.update_enabled_flags_list()
            self.update_appsettings_modified_indicator_cached(flag)

    def debounced_appsettings_refresh(self):
        """Refresh ApplicationSettings list after user stops typing"""
        if dpg.does_item_exist("appsettings_list"):
            # Store current scroll position
            scroll_y = dpg.get_y_scroll("appsettings_list") if dpg.does_item_exist("appsettings_list") else 0.0
            
            self.refresh_application_settings_list()
            
            # Restore scroll position
            if scroll_y > 0 and dpg.does_item_exist("appsettings_list"):
                dpg.set_y_scroll("appsettings_list", scroll_y)

    def update_appsettings_modified_indicator_cached(self, flag):
        """Update the modified indicator (*) and widget value using the cache - O(1) operation"""
        # Check if flag is in cache (i.e., currently displayed)
        if flag not in self.appsettings_flag_groups:
            return
        
        original = self.settings.get("originalApplicationSettings", {})
        
        # Get current value
        current_value = None
        if flag in self.settings["applicationSettings"]:
            current_value = self.settings["applicationSettings"][flag]
        elif flag in self.settings["disabledFlags"]:
            current_value = self.settings["disabledFlags"][flag]
        else:
            current_value = original.get(flag, "N/A")
        
        orig_val = original.get(flag, "N/A")
        is_modified = str(current_value) != str(orig_val) and orig_val != "N/A"
        
        cache_entry = self.appsettings_flag_groups[flag]
        was_modified = cache_entry["is_modified"]
        
        asterisk_tag = f"appsettings_asterisk_{flag}"
        group_tag = cache_entry["group"]
        
        # Update the widget value if it exists
        if self.is_integer_flag(flag):
            if dpg.does_item_exist(f"appsettings_int_input_{flag}"):
                dpg.set_value(f"appsettings_int_input_{flag}", str(current_value))
        elif self.is_boolean_flag(flag):
            if dpg.does_item_exist(f"appsettings_bool_button_{flag}"):
                bool_val = str(current_value).lower() in ("true", "1")
                dpg.set_item_label(f"appsettings_bool_button_{flag}", "True" if bool_val else "False")
        else:
            if dpg.does_item_exist(f"appsettings_text_input_{flag}"):
                dpg.set_value(f"appsettings_text_input_{flag}", str(current_value))
        
        # Update asterisk
        if is_modified and not was_modified:
            # Add asterisk
            if dpg.does_item_exist(group_tag):
                dpg.add_text("*", color=self.get_asterisk_color(), tag=asterisk_tag, parent=group_tag)
            cache_entry["is_modified"] = True
        elif not is_modified and was_modified:
            # Remove asterisk
            if dpg.does_item_exist(asterisk_tag):
                dpg.delete_item(asterisk_tag)
            cache_entry["is_modified"] = False


    def update_search(self, s, data):
        self.update_flag_list(data)

    def update_modified_search(self, s, data):
        self.modified_search_query = data.lower() if data else ""
        self.update_enabled_flags_list()

    def is_boolean_flag(self, flag):
        if not flag:
            return False
        return flag.startswith(("DFFlag", "FFlag", "SFFlag"))

    def get_effective_value(self, flag):
        app_settings = self.settings.get("applicationSettings", {})
        disabled_flags = self.settings.get("disabledFlags", {})
        original = self.settings.get("originalApplicationSettings", {})
        
        if flag in app_settings:
            return app_settings[flag]
        if flag in disabled_flags:
            return disabled_flags[flag]
        if flag in original:
            return original[flag]
        return ""

    def should_use_boolean_widget(self, flag):
        if not self.is_boolean_flag(flag):
            return False
        value = str(self.get_effective_value(flag)).strip()
        if ";" in value or len(value.split()) > 1 or (value.isdigit() and len(value) > 2):
            return False
        return True

    def replace_value_widget(self):
        dpg.lock_mutex()
        try:
            if not dpg.does_item_exist("value_group"):
                return
            dpg.delete_item("value_group", children_only=True)

            if self.selected_flag and self.should_use_boolean_widget(self.selected_flag):
                dpg.add_button(label="False", tag="flag_value_bool_button", width=-150,
                               callback=self.toggle_bool_value, parent="value_group")
            else:
                dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value", parent="value_group")
        finally:
            dpg.unlock_mutex()

    def toggle_bool_value(self, sender, app_data):
        if dpg.does_item_exist("flag_value_bool_button"):
            current = dpg.get_item_label("flag_value_bool_button")
            dpg.set_item_label("flag_value_bool_button", "True" if current == "False" else "False")

    def select_flag(self, s, a, flag):
        self.selected_flag = flag
        dpg.set_value("selected_flag_text", f"Selected Flag: {flag}")
        self.replace_value_widget()

        current_val = self.get_effective_value(flag)

        dpg.lock_mutex()
        try:
            if self.should_use_boolean_widget(flag) and dpg.does_item_exist("flag_value_bool_button"):
                if flag not in self.settings.get("originalApplicationSettings", {}):
                    dpg.set_item_label("flag_value_bool_button", "False")
                else:
                    bool_val = str(current_val).lower() in ("true", "1")
                    dpg.set_item_label("flag_value_bool_button", "True" if bool_val else "False")
            elif dpg.does_item_exist("flag_value_input"):
                dpg.set_value("flag_value_input", str(current_val))
        finally:
            dpg.unlock_mutex()

    def set_flag_value(self, s, a):
        if self.selected_flag:
            if self.should_use_boolean_widget(self.selected_flag) and dpg.does_item_exist("flag_value_bool_button"):
                val = dpg.get_item_label("flag_value_bool_button")
            elif dpg.does_item_exist("flag_value_input"):
                val = dpg.get_value("flag_value_input")
            else:
                val = ""

            self.save_flag(self.selected_flag, val)
            
            dpg.lock_mutex()
            try:
                dpg.delete_item("value_group", children_only=True)
                dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value", parent="value_group")
            finally:
                dpg.unlock_mutex()
            
            self.selected_flag = None
            dpg.set_value("selected_flag_text", "Selected Flag: None")

    def create_edit_widget_for_flag(self, flag, parent):
        dpg.lock_mutex()
        try:
            if self.should_use_boolean_widget(flag):
                current_val = self.get_effective_value(flag)
                bool_val = str(current_val).lower() in ("true", "1")
                dpg.add_button(label="True" if bool_val else "False", 
                              tag=f"edit_bool_button_{flag}", 
                              width=-130,
                              callback=self.toggle_edit_bool_value, 
                              user_data=flag,
                              parent=parent)
            else:
                dpg.add_input_text(tag=f"edit_value_{flag}", 
                                  default_value="", 
                                  width=-130, 
                                  hint="New Value",
                                  parent=parent)
        finally:
            dpg.unlock_mutex()

    def toggle_edit_bool_value(self, sender, app_data, flag):
        if dpg.does_item_exist(f"edit_bool_button_{flag}"):
            current = dpg.get_item_label(f"edit_bool_button_{flag}")
            dpg.set_item_label(f"edit_bool_button_{flag}", "True" if current == "False" else "False")

    def toggle_all_modified(self, s, a):
        app_settings = self.settings.get("applicationSettings", {})
        disabled_flags = self.settings.get("disabledFlags", {})
        flag_order = self.settings.get("flagOrder", [])

        has_disabled = any(f in disabled_flags for f in flag_order)

        if has_disabled:
            for flag in list(flag_order):
                if flag in disabled_flags:
                    app_settings[flag] = disabled_flags.pop(flag)
        else:
            for flag in list(flag_order):
                if flag in app_settings:
                    disabled_flags[flag] = app_settings.pop(flag)

        self.save_json()
        self.update_enabled_flags_list()

    def update_enabled_flags_list(self):
        if not dpg.does_item_exist("enabled_flags_list"): 
            return

        dpg.lock_mutex()
        try:
            scroll_y = dpg.get_y_scroll("enabled_flags_list") if dpg.does_item_exist("enabled_flags_list") else 0.0

            dpg.delete_item("enabled_flags_list", children_only=True)
            flag_order = self.settings.setdefault("flagOrder", [])

            search = self.modified_search_query

            for index, flag in enumerate(flag_order):
                if search and search not in flag.lower():
                    continue

                enabled = flag in self.settings.get("applicationSettings", {})
                val = self.get_effective_value(flag)
                kb = self.keybinds.get(flag, "none")
                has_keybind = flag in self.keybinds

                with dpg.group(parent="enabled_flags_list"):
                    dpg.add_input_text(default_value=f"{flag}: {val}", readonly=True, width=-1)
                    
                    with dpg.group(horizontal=True):
                        self.create_edit_widget_for_flag(flag, dpg.last_item())
                        dpg.add_button(label="Update Value", callback=self.update_flag_value, user_data=flag)
                    
                    with dpg.group(horizontal=True):
                        dpg.add_checkbox(label="Enabled", default_value=enabled,
                                         callback=self.toggle_flag_visibility, user_data=flag)
                        dpg.add_button(label="Remove", callback=self.remove_flag, user_data=flag)
                        dpg.add_button(label=f"Keybind: {kb}", callback=self.set_keybind,
                                       user_data=flag, tag=f"keybind_button_{flag}")
                        dpg.add_button(label="X", callback=self.clear_keybind, user_data=flag, width=25,
                                       tag=f"clear_keybind_button_{flag}", show=has_keybind)

                if index < len(flag_order) - 1:
                    dpg.add_spacer(height=10, parent="enabled_flags_list")

            dpg.set_y_scroll("enabled_flags_list", scroll_y)
        finally:
            dpg.unlock_mutex()

    def update_flag_value(self, s, a, flag):
        if self.should_use_boolean_widget(flag) and dpg.does_item_exist(f"edit_bool_button_{flag}"):
            new_val = dpg.get_item_label(f"edit_bool_button_{flag}")
        else:
            new_val = dpg.get_value(f"edit_value_{flag}")

        if new_val is not None and str(new_val).strip() != "":
            if flag in self.settings.get("applicationSettings", {}):
                self.settings["applicationSettings"][flag] = new_val
            else:
                self.settings["disabledFlags"][flag] = new_val
            self.save_json()
            self.update_enabled_flags_list()
            self.update_appsettings_modified_indicator_cached(flag)

    def save_flag(self, name, value):
        if name not in self.settings.get("flagOrder", []):
            self.settings.setdefault("flagOrder", []).append(name)
        if name in self.settings.get("disabledFlags", {}):
            self.settings["disabledFlags"][name] = value
        else:
            self.settings["applicationSettings"][name] = value
        self.save_json()
        self.update_enabled_flags_list()
        # Update ApplicationSettings window if the flag is displayed there
        self.update_appsettings_modified_indicator_cached(name)

    def _toggle_flag_internal(self, flag):
        if flag in self.settings.get("applicationSettings", {}):
            self.settings["disabledFlags"][flag] = self.settings["applicationSettings"].pop(flag)
        else:
            self.settings["applicationSettings"][flag] = self.settings["disabledFlags"].pop(flag)
        if flag not in self.settings.get("flagOrder", []):
            self.settings.setdefault("flagOrder", []).append(flag)
        self.update_appsettings_modified_indicator_cached(flag)

    def toggle_flag_visibility(self, s, a, flag):
        self._toggle_flag_internal(flag)
        self.save_json()
        self.update_enabled_flags_list()

    def batch_toggle_flags(self, flags):
        if not flags:
            return
        for flag in flags:
            self._toggle_flag_internal(flag)
        self.save_json()
        self.update_enabled_flags_list()

    def remove_flag(self, s, a, flag):
        original = self.settings.get("originalApplicationSettings", {})
        app_settings = self.settings["applicationSettings"]
        disabled_flags = self.settings["disabledFlags"]

        if flag in original:
            app_settings[flag] = original[flag]
            disabled_flags.pop(flag, None)
        else:
            app_settings.pop(flag, None)
            disabled_flags.pop(flag, None)

        self.keybinds.pop(flag, None)
        if flag in self.settings.get("flagOrder", []):
            self.settings["flagOrder"].remove(flag)

        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)
        self.register_all_hotkeys()

        self.show_feedback(f"Removed '{flag}' (restored original if available)", [0, 255, 0])

    def clear_all_fflags_confirmed(self, s, a):
        dpg.delete_item("clear_confirm_popup")
        if not self.settings.get("flagOrder"):
            self.show_feedback("No modified flags to clear.", [255, 0, 0])
            return

        original = self.settings.get("originalApplicationSettings", {})
        app_settings = self.settings["applicationSettings"]
        disabled_flags = self.settings["disabledFlags"]
        flag_order = list(self.settings.get("flagOrder", []))

        cleared = 0
        for flag in flag_order:
            if flag in original:
                app_settings[flag] = original[flag]
                disabled_flags.pop(flag, None)
            else:
                app_settings.pop(flag, None)
                disabled_flags.pop(flag, None)
            self.keybinds.pop(flag, None)
            cleared += 1
            self.update_appsettings_modified_indicator_cached(flag)

        self.settings["flagOrder"] = []
        self.save_json()
        self.update_enabled_flags_list()
        self.register_all_hotkeys()

        self.show_feedback(f"Cleared {cleared} modified flags successfully.", [0, 255, 0])

    def clear_keybind(self, s, a, flag):
        if flag in self.keybinds:
            del self.keybinds[flag]
        self.save_json()
        self.register_all_hotkeys()
        dpg.configure_item(f"keybind_button_{flag}", label="Keybind: none")
        dpg.configure_item(f"clear_keybind_button_{flag}", show=False)

    def set_keybind(self, s, a, flag):
        if self.is_setting_keybind or self.is_setting_preset_keybind:
            return
        self.is_setting_keybind = True
        self.register_all_hotkeys()
        dpg.configure_item(f"keybind_button_{flag}", label="Keybind: waiting for input...")

        def capture_key():
            try:
                modifiers = []
                main_key = None
                while True:
                    event = keyboard.read_event(suppress=False)
                    if event.event_type == keyboard.KEY_DOWN:
                        key = event.name.upper()
                        if key in ["CTRL", "CONTROL", "SHIFT", "ALT"]:
                            if key == "CONTROL":
                                key = "CTRL"
                            if key not in modifiers:
                                modifiers.append(key)
                        else:
                            main_key = key
                            break
                keybind_str = " + ".join(sorted(modifiers) + [main_key]) if modifiers else main_key
                
                # Check if this keybind conflicts with toggle overlay keybind
                if keybind_str.upper() == self.hotkey.upper():
                    self.show_feedback("Cannot set same keybind as Toggle Overlay.", [255, 0, 0])
                    dpg.configure_item(f"keybind_button_{flag}", label=f"Keybind: {self.keybinds.get(flag, 'None')}")
                    return
                
                self.keybinds[flag] = keybind_str
                self.save_json()
                dpg.configure_item(f"keybind_button_{flag}", label=f"Keybind: {keybind_str}")
                dpg.configure_item(f"clear_keybind_button_{flag}", show=True)
            finally:
                self.is_setting_keybind = False
                self.register_all_hotkeys()

        threading.Thread(target=capture_key, daemon=True).start()

    def set_toggle_overlay_keybind(self, s, a):
        if self.is_setting_keybind or self.is_setting_preset_keybind or self.is_setting_toggle_keybind:
            return
        self.is_setting_toggle_keybind = True
        # Unregister current hotkey before capturing new one
        for key in list(self.hotkey_handlers.keys()):
            if self.hotkey in key:
                try:
                    handler = self.hotkey_handlers.pop(key)
                    keyboard.remove_hotkey(handler)
                except:
                    pass
        dpg.configure_item("toggle_overlay_keybind_button", label="waiting for input...")

        def capture_key():
            try:
                modifiers = []
                main_key = None
                while True:
                    event = keyboard.read_event(suppress=False)
                    if event.event_type == keyboard.KEY_DOWN:
                        key = event.name.upper()
                        if key in ["CTRL", "CONTROL", "SHIFT", "ALT"]:
                            if key == "CONTROL":
                                key = "CTRL"
                            if key not in modifiers:
                                modifiers.append(key)
                        else:
                            main_key = key
                            break
                
                # Fix Insert casing to match default
                if main_key == "INSERT":
                    main_key = "Insert"
                
                keybind_str = " + ".join(sorted(modifiers) + [main_key]) if modifiers else main_key
                
                # Check if this keybind conflicts with any modified flag keybind
                conflicting = False
                for flag, kb in self.keybinds.items():
                    if kb.upper() == keybind_str.upper():
                        conflicting = True
                        break
                
                if conflicting:
                    # Reject - show feedback and restore old keybind
                    self.show_feedback("Cannot set same keybind as modified flag.", [255, 0, 0])
                    dpg.configure_item("toggle_overlay_keybind_button", label=f"{self.hotkey}")
                    self.register_all_hotkeys()
                    return
                
                self.hotkey = keybind_str
                
                # Update UI
                dpg.configure_item("toggle_overlay_keybind_button", label=f"{keybind_str}")
                # Only show X button if keybind is NOT the default (Insert)
                dpg.configure_item("clear_toggle_keybind_button", show=(keybind_str.lower() != self.default_hotkey.lower()))
                
                # Update menu item
                if dpg.does_item_exist("toggle_overlay_menu_item"):
                    dpg.configure_item("toggle_overlay_menu_item", label=f"Toggle Overlay ({keybind_str})")
                
                # Re-register all hotkeys (including the new toggle keybind)
                self.register_all_hotkeys()
                
                # Save config
                self.save_toggle_overlay_keybind_config()
            finally:
                self.is_setting_toggle_keybind = False

        threading.Thread(target=capture_key, daemon=True).start()

    def clear_toggle_overlay_keybind(self, s, a):
        # Unregister current hotkey
        for key in list(self.hotkey_handlers.keys()):
            if self.hotkey in key:
                try:
                    handler = self.hotkey_handlers.pop(key)
                    keyboard.remove_hotkey(handler)
                except:
                    pass
        
        self.hotkey = self.default_hotkey
        
        # Update UI
        dpg.configure_item("toggle_overlay_keybind_button", label=f"{self.default_hotkey}")
        dpg.configure_item("clear_toggle_keybind_button", show=False)
        
        # Update menu item
        if dpg.does_item_exist("toggle_overlay_menu_item"):
            dpg.configure_item("toggle_overlay_menu_item", label=f"Toggle Overlay ({self.default_hotkey})")
        
        # Re-register all hotkeys
        self.register_all_hotkeys()
        
        # Save config
        self.save_toggle_overlay_keybind_config()

    def _save_developer_options_config(self):
        """Save developer options state to config.json"""
        try:
            # Read existing config
            config = {}
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
            
            # Build binary string: share_theme, use_zflag, remove_size_limit, show_suffix, convert_suffix
            binary_flags = ""
            binary_flags += "1" if self.share_theme_with_appsettings else "0"
            binary_flags += "1" if self.use_zflag_channel else "0"
            binary_flags += "1" if self.remove_size_limit else "0"
            binary_flags += "1" if self.show_suffix_in_appsettings else "0"
            binary_flags += "1" if self.convert_suffix_to_base else "0"
            
            if self.enable_rat:
                # EnableRAT is True
                if binary_flags != "00000":
                    config["EnableRAT"] = f"True {{{binary_flags}}}"
                else:
                    config["EnableRAT"] = "True"
            else:
                # EnableRAT is False
                if binary_flags != "00000":
                    config["EnableRAT"] = f"False {{{binary_flags}}}"
                else:
                    config["EnableRAT"] = "False"
            
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass

    def save_toggle_overlay_keybind_config(self):
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                config = json.load(f)
            config["toggle_overlay_keybind"] = self.hotkey
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass

    def _parse_keybind(self, keybind_str):
        """Parse a keybind string into (modifiers_list, main_key).
        e.g. 'ctrl + shift + f1' -> (['ctrl', 'shift'], 'f1')
             'Insert' -> ([], 'insert')
        """
        parts = [p.strip().lower() for p in keybind_str.split("+")]
        if len(parts) == 1:
            return [], parts[0]
        return parts[:-1], parts[-1]

    def _make_press_handler(self, keybind_str, modifiers, callback):
        """Create an on_press_key handler that checks modifiers manually.
        This fires even when other non-modifier keys (like WASD) are held."""
        def on_press(event):
            # Check all required modifiers are held
            for mod in modifiers:
                if not keyboard.is_pressed(mod):
                    return
            callback()
        return on_press

    def register_all_hotkeys(self):
        # Remove all previously registered handlers
        for key, handler in list(self.hotkey_handlers.items()):
            try:
                keyboard.unhook(handler)
            except:
                try:
                    keyboard.remove_hotkey(handler)
                except:
                    pass
        self.hotkey_handlers.clear()

        if self.is_setting_keybind or self.is_setting_preset_keybind:
            return

        keybind_to_flags = defaultdict(list)
        for flag, keybind in self.keybinds.items():
            keybind_to_flags[keybind].append(flag)

        for keybind_str, flags_list in keybind_to_flags.items():
            # Skip flag keybinds that conflict with toggle overlay keybind
            if keybind_str.upper() == self.hotkey.upper():
                continue
            
            modifiers, main_key = self._parse_keybind(keybind_str)

            def make_batch_callback(flist=flags_list, kb_str=keybind_str):
                def callback():
                    if kb_str not in self.keybind_pressed or not self.keybind_pressed[kb_str]:
                        self.keybind_pressed[kb_str] = True
                        self.batch_toggle_flags(flist)
                return callback

            def make_release_callback(kb_str=keybind_str):
                def on_release(e=None):
                    if kb_str in self.keybind_pressed:
                        self.keybind_pressed[kb_str] = False
                return on_release

            try:
                press_handler = self._make_press_handler(keybind_str, modifiers, make_batch_callback())
                handler_press = keyboard.on_press_key(main_key, press_handler, suppress=False)
                self.hotkey_handlers[keybind_str + "_press"] = handler_press

                handler_release = keyboard.on_release_key(main_key, make_release_callback())
                self.hotkey_handlers[keybind_str + "_release"] = handler_release

            except:
                pass

        # Register toggle overlay keybind
        try:
            toggle_kb = self.hotkey
            modifiers, main_key = self._parse_keybind(self.hotkey)
            parts = self.hotkey.split(" + ")
            
            def toggle_callback():
                # Only trigger if not already pressed (prevent repeats while held)
                if toggle_kb not in self.keybind_pressed or not self.keybind_pressed[toggle_kb]:
                    self.keybind_pressed[toggle_kb] = True
                    self.toggle_overlay()
            
            def toggle_release_callback():
                if toggle_kb in self.keybind_pressed:
                    self.keybind_pressed[toggle_kb] = False
            
            # Register press handler using on_press_key + modifier check
            press_handler = self._make_press_handler(self.hotkey, modifiers, toggle_callback)
            handler_press = keyboard.on_press_key(main_key, press_handler, suppress=False)
            self.hotkey_handlers[toggle_kb + "_press"] = handler_press
            
            # Register release handler - listen for all keys in the combination
            for part in parts:
                def make_release_handler(key=part.lower()):
                    def on_release(e=None):
                        # Check if all modifier keys are released
                        toggle_release_callback()
                    return on_release
                keyboard.on_release_key(part.lower(), make_release_handler())
            
            # Also register a general release handler using the full hotkey
            if " + " in self.hotkey:
                main_key_release = self.hotkey.split(" + ")[-1].lower()
            else:
                main_key_release = self.hotkey.lower()
            
            keyboard.on_release_key(main_key_release, lambda e=None: toggle_release_callback())

        except Exception as e:
            print(f"Error registering toggle keybind: {e}")

    def import_latest_from_roblox(self, s, a):
        try:
            # Determine which URL to use based on ZFlag checkbox
            url = self.ZFLAG_URL if self.use_zflag_channel else self.ROBLOX_SETTINGS_URL
            
            r = requests.get(url, verify=False, timeout=15)
            r.raise_for_status()
            data = r.json()
            new_settings = data.get("applicationSettings", {})

            updated = 0
            added = 0
            original = self.settings.setdefault("originalApplicationSettings", {})
            app_settings = self.settings["applicationSettings"]
            disabled_flags = self.settings["disabledFlags"]

            for flag, new_value in new_settings.items():
                if flag in app_settings:
                    current_value = app_settings[flag]
                    location = "app"
                elif flag in disabled_flags:
                    current_value = disabled_flags[flag]
                    location = "disabled"
                else:
                    current_value = None
                    location = None

                if current_value is None:
                    app_settings[flag] = new_value
                    original[flag] = new_value
                    added += 1
                else:
                    orig_value = original.get(flag)
                    if str(current_value) == str(orig_value):
                        if location == "app":
                            app_settings[flag] = new_value
                        else:
                            disabled_flags[flag] = new_value
                        original[flag] = new_value
                        updated += 1

            self.save_json()
            self.update_enabled_flags_list()
            
            # Always clear cache and refresh the ApplicationSettings data, regardless of window state
            self.appsettings_flag_groups.clear()
            self.refresh_application_settings_list()
            
            self.show_feedback(f"Successfully added {added} new flags and refreshed {updated}.", [0, 255, 0])

        except Exception as e:
            self.show_feedback(f"Refresh failed: {str(e)}", [255, 0, 0])

    def show_clear_confirmation(self, s, a):
        if dpg.does_item_exist("clear_confirm_popup"):
            dpg.show_item("clear_confirm_popup")
            self.center_popup("clear_confirm_popup")
            return

        with dpg.window(label="Confirm Clear", modal=True, no_resize=True, no_close=True,
                        width=400, height=160, tag="clear_confirm_popup"):
            dpg.bind_item_theme("clear_confirm_popup", self.popup_theme)
            dpg.add_text("Are you sure you want to remove all modified flags?", wrap=370)
            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_spacer(width=85)
                dpg.add_button(label="Yes", width=80, callback=self.clear_all_fflags_confirmed)
                dpg.add_spacer(width=20)
                dpg.add_button(label="No", width=80, callback=lambda: dpg.delete_item("clear_confirm_popup"))
                dpg.add_spacer(width=80)
        self.center_popup("clear_confirm_popup")

    def select_json_file(self):
        was_visible = self.overlay_visible
        if was_visible:
            self.toggle_overlay()

        root = Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        root.destroy()

        if file_path:
            # Normalize paths for comparison
            file_path = os.path.abspath(file_path)
            file_path_dir = os.path.dirname(file_path)
            file_path_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_path_name)[0]
            
            # Check reserved filenames (like config)
            reserved_lower = [name.lower() for name in self.RESERVED_FILENAMES]
            if base_name.lower() in reserved_lower:
                self.show_feedback(f"Cannot select reserved file: {base_name}", [255, 0, 0])
                if was_visible and not self.overlay_visible:
                    self.toggle_overlay()
                return
            
            # Get normalized paths for restricted directories
            app_dir = os.path.abspath(self.APP_DIR)
            presets_dir = os.path.abspath(self.presets_dir)
            custom_theme_dir = os.path.abspath(os.path.join(self.APP_DIR, "Custom theme"))
            temp_dir = os.path.abspath(".temp")
            current_json_path = os.path.abspath(self.JSON_PATH)
            
            # Check if the selected file is in a restricted directory
            # Allow if it's the currently used JSON file
            if file_path == current_json_path:
                pass  # Allow re-selecting the current file
            elif file_path_dir == presets_dir or file_path_dir.startswith(presets_dir + os.sep):
                self.show_feedback("Cannot select files from the presets folder!", [255, 0, 0])
                if was_visible and not self.overlay_visible:
                    self.toggle_overlay()
                return
            elif file_path_dir == custom_theme_dir or file_path_dir.startswith(custom_theme_dir + os.sep):
                self.show_feedback("Cannot select files from the Custom theme folder!", [255, 0, 0])
                if was_visible and not self.overlay_visible:
                    self.toggle_overlay()
                return
            elif file_path_dir == temp_dir or file_path_dir.startswith(temp_dir + os.sep):
                self.show_feedback("Cannot select files from the .temp folder!", [255, 0, 0])
                if was_visible and not self.overlay_visible:
                    self.toggle_overlay()
                return
            elif file_path_dir == app_dir and file_path_name.lower() == "config.json":
                self.show_feedback("Cannot select config.json!", [255, 0, 0])
                if was_visible and not self.overlay_visible:
                    self.toggle_overlay()
                return

            self.JSON_PATH = file_path
            
            # Save config properly
            try:
                with open("config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
                config["custom_json_path"] = self.JSON_PATH
                with open("config.json", "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=4)
            except:
                pass
            
            self.load_json_data()
            self.update_enabled_flags_list()
            self.update_json_path_display()
            filename = os.path.basename(self.JSON_PATH)
            self.show_feedback(f"Selected {filename} successfully!", [0, 255, 0])
        else:
            self.show_feedback("Select File was cancelled.", [255, 0, 0])

        if was_visible and not self.overlay_visible:
            self.toggle_overlay()

    def toggle_always_on_top(self, s, a):
        self.ALWAYS_ON_TOP = a
        dpg.configure_viewport(0, always_on_top=a)
        
        # Save config properly
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                config = json.load(f)
            config["always_on_top"] = a
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass

    def show_rename_popup(self):
        if dpg.does_item_exist("rename_popup"):
            dpg.show_item("rename_popup")
            self.center_popup("rename_popup")
            return
        with dpg.window(label="Rename JSON File", modal=True, no_resize=True, no_close=True,
                        width=420, height=190, tag="rename_popup"):
            dpg.bind_item_theme("rename_popup", self.popup_theme)
            dpg.add_text("Enter new filename (without .json):")
            current_name = os.path.splitext(os.path.basename(self.JSON_PATH))[0]
            dpg.add_input_text(default_value=current_name, tag="rename_input", width=-1)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Rename", callback=self.perform_rename)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("rename_popup"))
            
            dpg.add_spacer(height=8)
            dpg.add_text("", tag="rename_feedback", color=[255, 0, 0])

        self.center_popup("rename_popup")

    def perform_rename(self):
        new_name = dpg.get_value("rename_input").strip()
        if not new_name:
            dpg.delete_item("rename_popup")
            return

        reserved_lower = [name.lower() for name in self.RESERVED_FILENAMES]
        if new_name.lower() in reserved_lower:
            self.show_rename_feedback(f"Cannot use reserved name: {new_name}", [255, 0, 0])
            return

        invalid_chars = r'\/:*?"<>|'
        if any(char in new_name for char in invalid_chars):
            self.show_rename_feedback(f"Invalid characters! Cannot use: {invalid_chars}", [255, 0, 0])
            return

        new_name += ".json"
        new_path = os.path.join(os.path.dirname(self.JSON_PATH), new_name)
        try:
            shutil.move(self.JSON_PATH, new_path)
            self.JSON_PATH = new_path
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump({"custom_json_path": self.JSON_PATH, "always_on_top": self.ALWAYS_ON_TOP}, f)
            
            self.update_json_path_display()
            self.show_feedback(f"Renamed to {new_name} successfully!", [0, 255, 0])
            dpg.delete_item("rename_popup")
        except Exception as e:
            self.show_feedback(f"Rename failed: {e}", [255, 0, 0])
            dpg.delete_item("rename_popup")

    def show_json_import_popup(self):
        if dpg.does_item_exist("json_import_popup"):
            dpg.show_item("json_import_popup")
            self.center_popup("json_import_popup")
            return
        with dpg.window(label="Import JSON", modal=True, no_resize=True, no_close=True,
                        width=460, height=340, tag="json_import_popup"):
            dpg.bind_item_theme("json_import_popup", self.popup_theme)
            dpg.add_text("Paste JSON here:")
            dpg.add_input_text(multiline=True, width=-1, height=250, tag="json_input_text")
            with dpg.group(horizontal=True):
                dpg.add_button(label="Import", callback=self.import_json_from_input)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("json_import_popup"))
        self.center_popup("json_import_popup")

    def import_json_from_input(self, s, a):
        content = dpg.get_value("json_input_text")
        try:
            data = json.loads(content)
            for k, v in data.items():
                if k in self.settings.get("disabledFlags", {}):
                    self.settings["disabledFlags"][k] = v
                else:
                    self.settings["applicationSettings"][k] = v
                if k not in self.settings.get("flagOrder", []):
                    self.settings.setdefault("flagOrder", []).append(k)
            self.save_json()
            self.update_enabled_flags_list()
            self.show_feedback("Import successful!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Import failed: {e}", [255, 0, 0])
        dpg.delete_item("json_import_popup")

    def export_json(self, s, a):
        try:
            export_data = {k: self.settings["applicationSettings"].get(k, self.settings["disabledFlags"].get(k, ""))
                           for k in self.settings.get("flagOrder", [])}
            pyperclip.copy(json.dumps(export_data, indent=4))
            self.show_feedback("Exported to clipboard!", [0, 255, 0])
        except Exception as e:
            self.show_feedback(f"Export failed: {e}", [255, 0, 0])

    def toggle_overlay(self):
        self.overlay_visible = not self.overlay_visible
        hwnd = win32gui.FindWindow(None, self.overlay_title)
        if hwnd:
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW if self.overlay_visible else win32con.SW_HIDE)

    def make_window_clickable(self):
        hwnd = win32gui.FindWindow(None, self.overlay_title)
        if hwnd:
            style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE,
                                   (style | win32con.WS_EX_LAYERED) & ~win32con.WS_EX_TRANSPARENT)
            win32gui.SetLayeredWindowAttributes(hwnd, 0, self.transparency, win32con.LWA_ALPHA)

    def start_key_listener(self):
        pass

    def cleanup_temp_folder(self):
        """Clean up all temporary files on exit"""
        try:
            if os.path.exists(".temp"):
                shutil.rmtree(".temp", ignore_errors=True)
        except:
            pass

    def save_config_with_theme(self):
        """Save config including current theme and custom theme path"""
        # Read existing config first to preserve proxy paths and other settings
        config = {}
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
        except:
            pass
        
        # Update with current settings
        config["custom_json_path"] = self.JSON_PATH
        config["always_on_top"] = self.ALWAYS_ON_TOP
        config["custom_theme_path"] = self.custom_theme_path or ""
        config["toggle_overlay_keybind"] = self.hotkey
        config["auto_variable_reloading"] = self.auto_variable_reloading
        
        # Ensure proxy paths are saved
        config["roblox_cacert_path"] = self.proxy_settings.get("roblox_cacert_path", config.get("roblox_cacert_path", ""))
        config["roblox_versions_dir"] = self.proxy_settings.get("roblox_versions_dir", config.get("roblox_versions_dir", ""))
        config["ca_cert_path"] = self.proxy_settings.get("ca_cert_path", config.get("ca_cert_path", ""))
        config["ca_key_path"] = self.proxy_settings.get("ca_key_path", config.get("ca_key_path", ""))

        # Build binary flags string
        binary_flags = ""
        binary_flags += "1" if self.share_theme_with_appsettings else "0"
        binary_flags += "1" if self.use_zflag_channel else "0"
        binary_flags += "1" if self.remove_size_limit else "0"
        binary_flags += "1" if self.show_suffix_in_appsettings else "0"
        binary_flags += "1" if self.convert_suffix_to_base else "0"

        if self.enable_rat:
            # EnableRAT is True
            if binary_flags != "00000":
                config["EnableRAT"] = f"True {{{binary_flags}}}"
            else:
                config["EnableRAT"] = "True"
        else:
            # EnableRAT is False
            if binary_flags != "00000":
                config["EnableRAT"] = f"False {{{binary_flags}}}"
            else:
                config["EnableRAT"] = "False"

        if self.current_theme == "custom_user":
            config["theme"] = "custom_user"
            self.save_custom_theme_to_file()
        else:
            if self.current_theme == "pink":
                config["theme"] = "Pink"
            elif self.current_theme == "default":
                config["theme"] = "default"
            elif self.current_theme == "iM sO gReEn":
                config["theme"] = "iM sO gReEn"
            elif self.current_theme == "og_flagbrowser":
                config["theme"] = "og_flagbrowser"
            else:
                config["theme"] = "Pink"

        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except:
            pass

    def clean_exit(self):
        # Stop proxy if running (this also removes hosts file entries)
        if self.proxy.running:
            self.proxy.stop()
        # Always try to remove hosts entries on exit as safety net
        try:
            self.proxy._remove_hosts_entries()
        except:
            pass
        
        self.cleanup_temp_folder()
        self.save_json()
        self.save_config_with_theme()
        keyboard.unhook_all()
        dpg.stop_dearpygui()

    def run(self):
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)
        self.make_window_clickable()

        # Apply the loaded theme after GUI is created
        if self.current_theme == "custom_user":
            self.set_theme("custom_user")
        elif self.current_theme == "iM sO gReEn":
            self.set_theme("iM sO gReEn")
        elif self.current_theme == "og_flagbrowser":
            self.set_theme("og_flagbrowser")
        elif self.current_theme == "default":
            self.set_theme("default")
        else:
            self.set_theme("pink")

        # Keep every DearPyGui call on this render thread.
        self._next_path_ui_refresh = 0.0
        self._next_proxy_ui_refresh = 0.0
        self.register_all_hotkeys()

        while dpg.is_dearpygui_running():
            now = time.monotonic()

            if now >= self._next_path_ui_refresh:
                self._next_path_ui_refresh = now + 0.15
                try:
                    if dpg.does_item_exist("json_path_input"):
                        self.update_json_path_display()
                except Exception:
                    pass

            if self.proxy and self.proxy.running and now >= self._next_proxy_ui_refresh:
                self._next_proxy_ui_refresh = now + 0.50
                try:
                    self._update_proxy_stats_ui()
                except Exception:
                    traceback.print_exc()

            if self._proxy_feedback_hide_at and now >= self._proxy_feedback_hide_at:
                self._proxy_feedback_hide_at = None
                try:
                    if dpg.does_item_exist("proxy_feedback"):
                        dpg.set_value("proxy_feedback", "")
                except Exception:
                    pass

            dpg.render_dearpygui_frame()
            time.sleep(1/60)  # Cap at 60 FPS to prevent CPU spin

        dpg.destroy_context()

    def path_update_loop(self):
        while dpg.is_dearpygui_running():
            try:
                if dpg.does_item_exist("json_path_input"):
                    self.update_json_path_display()
            except:
                pass
            time.sleep(0.15)


if __name__ == "__main__":
    # Set process priority to ABOVE_NORMAL so the keyboard hook
    # doesn't get starved when Roblox uses heavy CPU
    try:
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.kernel32.SetPriorityClass(handle, 0x00008000)  # ABOVE_NORMAL_PRIORITY_CLASS
    except:
        pass
    app = FlagBrowserOverlay()
    app.run()
