import os
import sys
import json
import struct
import time
import secrets
import threading
import queue
import string
import math
import uuid
import tempfile
import stat
import shutil
import zipfile
import hmac
import hashlib
import platform
import re
import subprocess
from urllib.parse import quote
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

if os.name == 'nt':
    try:
        import winreg
    except ImportError:
        winreg = None

try:
    import windnd
    WINDND_AVAILABLE = True
except ImportError:
    WINDND_AVAILABLE = False

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# =====================================================================
# 1. CONSTANTS & SYSTEM CONFIG
# =====================================================================
APP_DATA_DIR = Path(os.getenv('LOCALAPPDATA', Path.home())) / "SecureVaultApp"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
POINTER_FILE = APP_DATA_DIR / "pointer_v3.json"
LICENSE_FILE = APP_DATA_DIR / "license.dat"

MAGIC_BYTES = b"SVAULT03"
VERSION = 3
CHUNK_SIZE = 4 * 1024 * 1024
MAX_METADATA_SIZE = 10 * 1024 * 1024
NO_WINDOW_FLAG = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

# المفتاح السري للتحقق من السيريالات (يجب أن يتطابق مع الموجود في لوحة الـ HTML)
SIGNING_SECRET_KEY = bytes([
    115, 118, 97, 117, 108, 116, 95, 104, 97, 114, 100, 101, 110, 101, 100, 95,
    109, 97, 115, 116, 101, 114, 95, 115, 105, 103, 110, 95, 50, 48, 50, 54
])

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def sanitize_filename(filename: str) -> str:
    clean = Path(filename).name
    clean = re.sub(r'[<>:"/\\|?*]', '_', clean)
    return clean if clean else f"file_{uuid.uuid4().hex[:6]}"

def open_file_externally(filepath: Path):
    try:
        if os.name == 'nt':
            os.startfile(str(filepath))
        elif sys.platform == 'darwin':
            os.system(f'open "{filepath}"')
        else:
            os.system(f'xdg-open "{filepath}"')
    except Exception:
        pass

def close_file_viewers(target_path: Path):
    if os.name != 'nt':
        return
    try:
        target_name = target_path.name
        safe_name = target_name.replace("'", "''")
        
        if target_path.is_dir():
            encoded_name = quote(target_name).replace("'", "''")
            ps_cmd = f"""
            $shell = New-Object -ComObject Shell.Application
            foreach ($w in $shell.Windows()) {{
                if ($w.LocationURL -and ($w.LocationURL -like '*{safe_name}*' -or $w.LocationURL -like '*{encoded_name}*')) {{
                    $w.Quit()
                }}
            }}
            """
        else:
            ps_cmd = f"""
            $fn = [regex]::Escape('{safe_name}')
            Get-Process | Where-Object {{ $_.MainWindowTitle -match $fn }} | Stop-Process -Force
            """

        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                       capture_output=True, creationflags=NO_WINDOW_FLAG, timeout=3)
    except Exception:
        pass

# =====================================================================
# 2. UNIVERSAL ENTRY
# =====================================================================
class SafeEntry(ctk.CTkEntry):
    def __init__(self, master, is_readonly=False, **kwargs):
        super().__init__(master, **kwargs)
        self.is_readonly = is_readonly
        
        self.bind("<Button-3>", self.show_context_menu)
        self._entry.bind("<Button-3>", self.show_context_menu)
        
        self.bind("<KeyPress>", self.handle_universal_keys)
        self._entry.bind("<KeyPress>", self.handle_universal_keys)

    def show_context_menu(self, event):
        menu = tk.Menu(self, tearoff=0, bg="#27272a", fg="white", activebackground="#2563eb", activeforeground="white", font=("Arial", 10))
        top_app = self.winfo_toplevel()
        is_ar = getattr(top_app, 'lang', 'ar') == 'ar'

        if not self.is_readonly:
            menu.add_command(label="لصق (Paste)" if is_ar else "Paste", command=self.paste_text)
            menu.add_command(label="قص (Cut)" if is_ar else "Cut", command=self.cut_text)
        menu.add_command(label="نسخ (Copy)" if is_ar else "Copy", command=self.copy_text)
        menu.add_command(label="تحديد الكل (Select All)" if is_ar else "Select All", command=self.select_all_text)
        
        menu.tk_popup(event.x_root, event.y_root)

    def paste_text(self):
        if self.is_readonly: return
        try:
            text = self.clipboard_get()
            if not text: return
            try:
                self._entry.delete("sel.first", "sel.last")
            except Exception:
                pass
            self._entry.insert("insert", text)
        except Exception:
            pass

    def copy_text(self):
        try:
            try:
                text = self._entry.selection_get()
            except Exception:
                text = self.get()
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
        except Exception:
            pass

    def cut_text(self):
        if self.is_readonly: return
        self.copy_text()
        try:
            self._entry.delete("sel.first", "sel.last")
        except Exception:
            self.delete(0, 'end')

    def select_all_text(self):
        self._entry.select_range(0, 'end')
        self._entry.icursor('end')

    def handle_universal_keys(self, event):
        ctrl_held = (event.state & 4) != 0 or (event.state & 0x20000) != 0
        if ctrl_held:
            if event.keycode == 86 or event.keysym.lower() in ('v', 'arabic_ra'):
                self.paste_text()
                return "break"
            elif event.keycode == 67 or event.keysym.lower() in ('c', 'arabic_hamzaupright'):
                self.copy_text()
                return "break"
            elif event.keycode == 65 or event.keysym.lower() in ('a', 'arabic_sheen'):
                self.select_all_text()
                return "break"
            elif event.keycode == 88 or event.keysym.lower() in ('x', 'arabic_hamza'):
                self.cut_text()
                return "break"

# =====================================================================
# 3. LOCALIZATION DICTIONARIES
# =====================================================================
TRANSLATIONS = {
    "en": {
        "title": "High-Assurance Secure Vault",
        "setup_title": "Security Architecture Setup",
        "step1": "Select Vault Storage Directory",
        "no_path": "No directory selected.",
        "quota": "Vault Storage Quota (GB):",
        "timeout": "Auto-lock Timeout (seconds):",
        "pwd": "Enter Master Password",
        "pwd_confirm": "Confirm Master Password",
        "pwd_mismatch": "Passwords do not match!",
        "entropy": "Password Strength",
        "init_vault": "Initialize Security Architecture",
        "login_title": "Security Authentication",
        "unlock": "Unlock Vault",
        "dash_title": "Encrypted Storage Dashboard",
        "lock": "Lock Session",
        "import_file": "➕ Import File(s)",
        "import_folder": "📁 Import Folder",
        "refresh": "🔄 Refresh List",
        "settings": "⚙️ Settings",
        "lang": "Interface Language",
        "change_pwd": "Change Master Password",
        "old_pwd": "Current Master Password",
        "new_pwd": "New Master Password",
        "confirm_new_pwd": "Confirm New Password",
        "save": "Save Settings",
        "delete": "Delete",
        "preview": "Preview",
        "export": "Export",
        "empty": "No encrypted files found. Drag and drop items here.",
        "err_auth": "Authentication failed. Incorrect password.",
        "msg_locked": "Session locked. Decrypted viewers closed and cache shredded.",
        "license_title": "Hardware-Bound System Activation",
        "serial_placeholder": "Enter activation serial key...",
        "activate": "Activate System",
        "license_expired": "Invalid activation serial or hardware mismatch!",
        "license_success": "Activation completed successfully.",
        "hwid_label": "Hardware Machine ID (HWID):",
        "pwd_changed": "Master password updated successfully.",
        "confirm_delete": "Permanently delete this encrypted item?",
        "quota_exceeded": "Storage quota or disk space exceeded!",
        "corrupt_file": "Corrupt or tampered file detected.",
        "export_success": "Item successfully decrypted and restored.",
        "save_success": "Settings saved successfully.",
        "copied": "Copied to clipboard!",
        "copy_btn": "📋 Copy",
        "locate_vault": "Locate Vault Folder",
        "vault_missing": "Vault storage directory is missing or inaccessible. Please select it.",
        "confirm_shred_title": "Secure Shredding Choice",
        "confirm_shred_msg": "Do you want to securely SHRED and delete the original file(s)/folder(s) after encryption?\n\n• Click [Yes] to permanently overwrite and shred the originals.\n• Click [No] to keep the originals untouched.",
        "success": "Success",
        "error": "Error",
        "confirm": "Confirm"
    },
    "ar": {
        "title": "الخزنة المشفرة عالية الأمان والموثوقية",
        "setup_title": "تأسيس معمارية الحماية للخزنة",
        "step1": "اختر مسار حفظ الخزنة",
        "no_path": "لم يتم اختيار مسار بعد.",
        "quota": "مساحة التخزين القصوى (جيجابايت):",
        "timeout": "زمن القفل التلقائي عند الخمول (بالثواني):",
        "pwd": "أدخل كلمة المرور الرئيسية",
        "pwd_confirm": "تأكيد كلمة المرور الرئيسية",
        "pwd_mismatch": "كلمتا المرور غير متطابقتين!",
        "entropy": "قوة كلمة المرور",
        "init_vault": "تأسيس وإنشاء الخزنة",
        "login_title": "المصادقة الأمنية",
        "unlock": "فتح الخزنة",
        "dash_title": "لوحة التحكم بالبيانات المشفرة",
        "lock": "قفل الخزنة",
        "import_file": "➕ استيراد ملف (أو ملفات)",
        "import_folder": "📁 استيراد مجلد",
        "refresh": "🔄 تحديث القائمة",
        "settings": "⚙️ الإعدادات",
        "lang": "لغة الواجهة",
        "change_pwd": "تغيير كلمة المرور الرئيسية",
        "old_pwd": "كلمة المرور الحالية",
        "new_pwd": "كلمة المرور الجديدة",
        "confirm_new_pwd": "تأكيد كلمة المرور الجديدة",
        "save": "حفظ الإعدادات",
        "delete": "حذف",
        "preview": "معاينة",
        "export": "استخراج",
        "empty": "لا توجد ملفات مشفرة. اسحب وأفلت الملفات هنا.",
        "err_auth": "فشلت المصادقة. كلمة المرور غير صحيحة.",
        "msg_locked": "تم قفل الجلسة، وإغلاق نوافذ المعاينة، وتمزيق الملفات المؤقتة.",
        "license_title": "تفعيل النظام المقيد بعتاد الجهاز",
        "serial_placeholder": "أدخل سريال التفعيل هنا...",
        "activate": "تفعيل النظام",
        "license_expired": "سريال التفعيل غير صالح أو لا يتطابق مع هذا الجهاز!",
        "license_success": "تم تفعيل البرنامج بنجاح.",
        "hwid_label": "معرف عتاد الجهاز الثابت (HWID):",
        "pwd_changed": "تم تغيير كلمة المرور الرئيسية بنجاح.",
        "confirm_delete": "هل أنت متأكد من حذف هذا الملف نهائياً؟",
        "quota_exceeded": "تم تجاوز المساحة المحددة أو نفدت مساحة القرص!",
        "corrupt_file": "الملف تالف أو تم العبث بمحتواه المشفر.",
        "export_success": "تم استخراج وفك تشفير الملف بنجاح.",
        "save_success": "تم حفظ التعديلات بنجاح.",
        "copied": "تم النسخ إلى الحافظة!",
        "copy_btn": "📋 نسخ",
        "locate_vault": "تحديد مجلد الخزنة",
        "vault_missing": "مجلد حفظ الخزنة غير موجود أو تم نقله. يرجى اختياره مجدداً.",
        "confirm_shred_title": "تأكيد خيار تمزيق النسخ الأصلية",
        "confirm_shred_msg": "هل ترغب في تمزيق وحذف الملفات/المجلدات الأصلية بشكل آمن بعد تشفيرها لمنع استرجاعها؟\n\n• اضغط [نعم] لإعادة الكتابة فوق النسخ الأصلية وحذفها نهائياً.\n• اضغط [لا] للاحتفاظ بالنسخ الأصلية كما هي دون حذف.",
        "success": "نجاح",
        "error": "خطأ",
        "confirm": "تأكيد"
    }
}

# =====================================================================
# 4. LICENSING & HARDWARE BINDING (SECURE CLIENT VERSION)
# =====================================================================
class LicenseManager:
    @staticmethod
    def get_hardware_id() -> str:
        if os.name == 'nt' and winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return hashlib.sha256(guid.encode('utf-8')).hexdigest()[:16].upper()
            except Exception:
                pass
        fallback = f"{platform.machine()}-{os.getenv('PROCESSOR_IDENTIFIER', 'GENERIC_CPU')}"
        return hashlib.sha256(fallback.encode('utf-8')).hexdigest()[:16].upper()

    @staticmethod
    def check_license() -> bool:
        current_hwid = LicenseManager.get_hardware_id()
        if not LICENSE_FILE.exists(): return False
        try:
            data = json.loads(LICENSE_FILE.read_text('utf-8'))
            if data.get("hwid") != current_hwid: return False
            
            serial = data.get("serial", "")
            parts = serial.split("-")
            if len(parts) != 4 or parts[0] != "SVAULT": return False
            
            target_hwid, expiry_str, provided_sig = parts[1], parts[2], parts[3]
            if target_hwid != current_hwid: return False
            
            payload = f"{target_hwid}:{expiry_str}"
            expected_sig = hmac.new(SIGNING_SECRET_KEY, payload.encode('utf-8'), hashlib.sha256).hexdigest()[:8].upper()
            if provided_sig != expected_sig: return False
            
            if datetime.now() > datetime.strptime(expiry_str, "%Y%m%d"): return False
            return True
        except Exception:
            return False

    @staticmethod
    def activate_serial(key_input: str) -> bool:
        key_input = key_input.strip()
        current_hwid = LicenseManager.get_hardware_id()
        
        serial = key_input.upper()
        parts = serial.split("-")
        if len(parts) != 4 or parts[0] != "SVAULT": return False
        
        target_hwid, expiry_str, provided_sig = parts[1], parts[2], parts[3]
        if target_hwid != current_hwid: return False
        
        payload = f"{target_hwid}:{expiry_str}"
        expected_sig = hmac.new(SIGNING_SECRET_KEY, payload.encode('utf-8'), hashlib.sha256).hexdigest()[:8].upper()
        
        if provided_sig == expected_sig:
            try:
                exp_date = datetime.strptime(expiry_str, "%Y%m%d")
                if datetime.now() <= exp_date:
                    data = {
                        "type": "CLIENT",
                        "hwid": current_hwid,
                        "serial": serial,
                        "expires_at": exp_date.isoformat()
                    }
                    LICENSE_FILE.write_text(json.dumps(data), 'utf-8')
                    return True
            except Exception:
                pass
        return False

# =====================================================================
# 5. CRYPTOGRAPHIC & SECURE SHREDDING ENGINE
# =====================================================================
class VaultSecurityError(Exception): pass
class AuthenticationError(Exception): pass

def generate_salt(size: int = 16) -> bytes:
    return os.urandom(size)

def derive_kek(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**16, r=8, p=1).derive(password.encode('utf-8'))

def wrap_master_key(password: str, salt: bytes, mk: bytes) -> str:
    nonce = os.urandom(12)
    return (nonce + AESGCM(derive_kek(password, salt)).encrypt(nonce, mk, b"wrap")).hex()

def unwrap_master_key(password: str, salt: bytes, wrapped: str) -> bytes:
    try:
        data = bytes.fromhex(wrapped)
        return AESGCM(derive_kek(password, salt)).decrypt(data[:12], data[12:], b"wrap")
    except Exception:
        raise AuthenticationError("Invalid password.")

def derive_file_key(mk: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"file_enc_v3").derive(mk)

class StreamingAEAD:
    def __init__(self, mk: bytes):
        self.mk = mk

    def _nonce(self, idx: int) -> bytes:
        return struct.pack('<Q', idx) + b'\x00\x00\x00\x00'

    def encrypt_file(self, src: Path, dest: Path, meta: dict, abort_event: threading.Event, p_cb):
        sz = src.stat().st_size
        chunks = (sz // CHUNK_SIZE) + (1 if sz % CHUNK_SIZE != 0 else 0) if sz > 0 else 0
        salt = generate_salt(16)
        aes = AESGCM(derive_file_key(self.mk, salt))
        meta.update({"size": sz, "chunks": chunks})
        m_bytes = json.dumps(meta).encode('utf-8')
        
        with open(src, 'rb') as f_in, open(dest, 'wb') as f_out:
            f_out.write(MAGIC_BYTES + struct.pack('<H', VERSION) + salt)
            enc_m = aes.encrypt(self._nonce(0), m_bytes, b"meta")
            f_out.write(struct.pack('<I', len(enc_m)) + enc_m)
            idx = 1
            proc = 0
            while True:
                if abort_event and abort_event.is_set():
                    raise InterruptedError()
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                enc = aes.encrypt(self._nonce(idx), chunk, None)
                f_out.write(struct.pack('<I', len(enc)) + enc)
                proc += len(chunk)
                idx += 1
                if p_cb:
                    p_cb(proc, sz if sz > 0 else 1)
            os.fsync(f_out.fileno())

    def decrypt_file(self, src: Path, dest: Path, abort_event: threading.Event, p_cb):
        with open(src, 'rb') as f_in:
            if f_in.read(8) != MAGIC_BYTES:
                raise VaultSecurityError("Invalid vault format.")
            f_in.read(2)
            salt = f_in.read(16)
            aes = AESGCM(derive_file_key(self.mk, salt))
            
            len_bytes = f_in.read(4)
            if not len_bytes or len(len_bytes) < 4:
                raise VaultSecurityError("Corrupt header.")
            meta_len = struct.unpack('<I', len_bytes)[0]
            if meta_len > MAX_METADATA_SIZE:
                raise VaultSecurityError("Suspicious metadata size.")
            
            try:
                meta = json.loads(aes.decrypt(self._nonce(0), f_in.read(meta_len), b"meta").decode('utf-8'))
                sz = meta.get('size', 0)
                chunks = meta.get('chunks', 0)
            except Exception:
                raise VaultSecurityError("Metadata corruption or invalid key.")

            with open(dest, 'wb') as f_out:
                idx = 1
                proc = 0
                while idx <= chunks:
                    if abort_event and abort_event.is_set():
                        raise InterruptedError()
                    chunk_len_bytes = f_in.read(4)
                    if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                        break
                    chunk_len = struct.unpack('<I', chunk_len_bytes)[0]
                    if chunk_len > CHUNK_SIZE + 64:
                        raise VaultSecurityError("Corrupted chunk boundary.")
                    chunk = aes.decrypt(self._nonce(idx), f_in.read(chunk_len), None)
                    f_out.write(chunk)
                    proc += len(chunk)
                    idx += 1
                    if p_cb:
                        p_cb(proc, sz if sz > 0 else 1)
                os.fsync(f_out.fileno())

    def extract_metadata(self, path: Path) -> dict:
        with open(path, 'rb') as f:
            if f.read(8) != MAGIC_BYTES:
                return {"orig_name": "Corrupted Item"}
            f.read(2)
            salt = f.read(16)
            aes = AESGCM(derive_file_key(self.mk, salt))
            try:
                meta_len_bytes = f.read(4)
                if len(meta_len_bytes) < 4:
                    return {"orig_name": "Invalid Header"}
                meta_len = struct.unpack('<I', meta_len_bytes)[0]
                if meta_len > MAX_METADATA_SIZE:
                    return {"orig_name": "Invalid Header"}
                return json.loads(aes.decrypt(self._nonce(0), f.read(meta_len), b"meta").decode('utf-8'))
            except Exception:
                return {"orig_name": "Tampered / Corrupted"}

class FilesystemSecurity:
    @staticmethod
    def secure_delete(p: Path):
        if not p.exists() or not p.is_file(): return
        try:
            os.chmod(p, stat.S_IWRITE)
        except Exception:
            pass

        for _ in range(5):
            try:
                sz = p.stat().st_size
                if sz > 0:
                    with open(p, "ba+", buffering=0) as f:
                        for b in [b'\x00', b'\xFF', os.urandom(1)]:
                            f.seek(0)
                            w = 0
                            while w < sz:
                                chunk = min(CHUNK_SIZE, sz - w)
                                f.write(b * chunk if len(b) == 1 else os.urandom(chunk))
                                w += chunk
                            f.flush()
                            os.fsync(f.fileno())
                p.unlink()
                return
            except (PermissionError, OSError):
                time.sleep(0.15)
                try:
                    os.chmod(p, stat.S_IWRITE)
                except Exception:
                    pass

    @staticmethod
    def secure_wipe_tree(folder: Path):
        if not folder.exists() or not folder.is_dir(): return
        try:
            for root, dirs, files in os.walk(folder, topdown=False):
                for name in files:
                    FilesystemSecurity.secure_delete(Path(root) / name)
                for name in dirs:
                    try:
                        d_path = Path(root) / name
                        d_path.rmdir()
                    except Exception:
                        pass
            try:
                folder.rmdir()
            except Exception:
                pass
        except Exception:
            pass

# =====================================================================
# 6. VAULT STORAGE MANAGER
# =====================================================================
class VaultManager:
    def __init__(self):
        self.vault_dir = None
        self.config_path = None
        self.config = self._init_config()

    def _init_config(self) -> dict:
        default = {
            "v": 3, "salt": "", "encrypted_mk": "",
            "settings": {"quota_gb": 10.0, "timeout_sec": 300, "lang": "ar"}
        }
        if POINTER_FILE.exists():
            try:
                ptr = json.loads(POINTER_FILE.read_text('utf-8'))
                target_str = ptr.get("vault_dir", "")
                if target_str:
                    target = Path(target_str)
                    if target.exists() and target.is_dir():
                        self.vault_dir = target
                        self.config_path = target / "svault.json"
                        if self.config_path.exists():
                            loaded = json.loads(self.config_path.read_text('utf-8'))
                            for k, v in default["settings"].items():
                                loaded.setdefault("settings", {})[k] = loaded.get("settings", {}).get(k, v)
                            return loaded
            except Exception:
                pass
        return default

    def bind_location(self, d: Path):
        d.mkdir(parents=True, exist_ok=True)
        self.vault_dir = d
        self.config_path = d / "svault.json"
        POINTER_FILE.write_text(json.dumps({"vault_dir": str(d.resolve())}), 'utf-8')

    def atomic_save(self):
        if not self.config_path: return
        tmp = self.config_path.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(self.config_path)

    def verify_quota(self, size: int):
        if not self.vault_dir:
            raise VaultSecurityError("Vault storage directory not found.")
        current_used = sum(f.stat().st_size for f in self.vault_dir.glob("*.vault") if f.is_file())
        if current_used + size > (self.config['settings']['quota_gb'] * 1024**3):
            raise VaultSecurityError("Storage quota exceeded.")
        if size > shutil.disk_usage(self.vault_dir).free:
            raise VaultSecurityError("Disk space exhausted on host drive.")

    def get_files(self) -> list:
        if not self.vault_dir or not self.vault_dir.exists():
            return []
        return [f for f in self.vault_dir.glob("*.vault") if f.is_file()]

# =====================================================================
# 7. SESSION STATE & TASK QUEUE
# =====================================================================
def evaluate_entropy(pwd: str, lang: str = "ar") -> dict:
    c = sum([
        26 if any(x in string.ascii_lowercase for x in pwd) else 0,
        26 if any(x in string.ascii_uppercase for x in pwd) else 0,
        10 if any(x in string.digits for x in pwd) else 0,
        32 if any(x in string.punctuation for x in pwd) else 0
    ])
    weak_msg = "ضعيفة" if lang == "ar" else "Weak"
    mod_msg = "متوسطة" if lang == "ar" else "Moderate"
    strong_msg = "قوية" if lang == "ar" else "Strong"

    if len(pwd) < 8 or c == 0:
        return {"valid": False, "msg": weak_msg}
    ent = len(pwd) * math.log2(c)
    return {"valid": True, "msg": strong_msg if ent >= 60 else mod_msg}

class SessionState:
    def __init__(self, timeout: int):
        self.timeout = timeout
        self.last_ping = time.time()
        self.locked = True
        self.mk = None
        self.temp_dir = Path(tempfile.gettempdir()) / f"svault_{secrets.token_hex(6)}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.is_modal_active = False
        self.active_previews = set()

    def ping(self):
        self.last_ping = time.time()

    def check_security(self) -> bool:
        if self.locked or self.is_modal_active:
            return False
        if time.time() - self.last_ping > self.timeout:
            self.lock()
            return True
        return False

    def unlock(self, mk: bytes):
        self.mk = mk
        self.locked = False
        self.ping()

    def track_preview(self, path: Path):
        self.active_previews.add(path)

    def lock(self):
        self.locked = True
        self.mk = None
        self.close_all_previews()
        self.cleanup_temp()

    def close_all_previews(self):
        for p in list(self.active_previews):
            close_file_viewers(p)
        self.active_previews.clear()
        time.sleep(0.2)

    def cleanup_temp(self):
        if self.temp_dir.exists():
            FilesystemSecurity.secure_wipe_tree(self.temp_dir)
            try:
                self.temp_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

class TaskEvent:
    PROGRESS = 0
    DONE = 1
    ERROR = 2

class WorkerManager:
    def __init__(self, cb):
        self.q = queue.Queue()
        self.cb = cb

    def submit(self, func, *args):
        def runner():
            try:
                func(*args)
            except Exception as e:
                self.q.put({"type": TaskEvent.ERROR, "err": str(e)})
        threading.Thread(target=runner, daemon=True).start()

    def poll(self):
        while not self.q.empty():
            self.cb(self.q.get_nowait())

# =====================================================================
# 8. GUI SCREENS
# =====================================================================
class LicenseScreen(ctk.CTkFrame):
    def __init__(self, master, alert=""):
        super().__init__(master)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        c = ctk.CTkFrame(self, fg_color="#18181b", corner_radius=15, border_width=1, border_color="#27272a")
        c.grid(row=0, column=0, padx=20, pady=30)

        ctk.CTkButton(c, text="English" if master.lang == "ar" else "العربية", width=80, height=28, fg_color="#27272a", command=master.toggle_language).pack(anchor="ne", padx=15, pady=10)

        if alert:
            ctk.CTkLabel(c, text=alert, text_color="#ef4444", font=("Arial", 13, "bold")).pack(pady=5)
        ctk.CTkLabel(c, text="🛡️", font=("Arial", 48)).pack(pady=10)
        ctk.CTkLabel(c, text=master.tr("license_title"), font=("Arial", 20, "bold")).pack(pady=5)

        hwid = LicenseManager.get_hardware_id()
        ctk.CTkLabel(c, text=master.tr("hwid_label"), text_color="gray").pack(pady=(10, 0))
        
        hwid_frame = ctk.CTkFrame(c, fg_color="transparent")
        hwid_frame.pack(pady=5)
        
        self.hwid_box = SafeEntry(hwid_frame, width=280, justify="center", font=("Consolas", 14, "bold"), is_readonly=True)
        self.hwid_box.pack(side="left", padx=5)
        self.hwid_box.insert(0, hwid)
        self.hwid_box.configure(state="readonly")
        
        ctk.CTkButton(hwid_frame, text=master.tr("copy_btn"), width=60, fg_color="#27272a", hover_color="#3f3f46", command=lambda: self.copy_to_clip(hwid)).pack(side="left")

        self.serial_entry = SafeEntry(c, placeholder_text=master.tr("serial_placeholder"), width=350, height=40)
        self.serial_entry.pack(pady=15)
        ctk.CTkButton(c, text=master.tr("activate"), fg_color="#10b981", hover_color="#059669", height=40, font=("Arial", 14, "bold"), command=self.verify).pack(pady=(5, 25))

    def copy_to_clip(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo(self.master.tr("success"), self.master.tr("copied"))

    def verify(self):
        if LicenseManager.activate_serial(self.serial_entry.get()):
            messagebox.showinfo(self.master.tr("success"), self.master.tr("license_success"))
            self.master.check_license_and_boot()
        else:
            messagebox.showerror(self.master.tr("error"), self.master.tr("license_expired"))

class SetupWizard(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        c = ctk.CTkFrame(self, fg_color="#18181b", corner_radius=15, border_width=1, border_color="#27272a")
        c.grid(row=0, column=0, padx=20, pady=25)

        ctk.CTkButton(c, text="English" if master.lang == "ar" else "العربية", width=80, height=28, fg_color="#27272a", command=master.toggle_language).pack(anchor="ne", padx=15, pady=10)
        ctk.CTkLabel(c, text=master.tr("setup_title"), font=("Arial", 22, "bold")).pack(pady=8)

        self.btn_dir = ctk.CTkButton(c, text=master.tr("step1"), command=self.select_dir)
        self.btn_dir.pack(pady=6)
        self.lbl_dir = ctk.CTkLabel(c, text=master.tr("no_path"), text_color="gray", wraplength=350)
        self.lbl_dir.pack(pady=2)

        cfg_row = ctk.CTkFrame(c, fg_color="transparent")
        cfg_row.pack(pady=5)
        
        q_box = ctk.CTkFrame(cfg_row, fg_color="transparent")
        q_box.pack(side="left", padx=10)
        ctk.CTkLabel(q_box, text=master.tr("quota"), font=("Arial", 11)).pack()
        self.quota = SafeEntry(q_box, width=100, justify="center")
        self.quota.insert(0, "10")
        self.quota.pack(pady=2)

        t_box = ctk.CTkFrame(cfg_row, fg_color="transparent")
        t_box.pack(side="left", padx=10)
        ctk.CTkLabel(t_box, text=master.tr("timeout"), font=("Arial", 11)).pack()
        self.timeout_box = SafeEntry(t_box, width=100, justify="center")
        self.timeout_box.insert(0, "300")
        self.timeout_box.pack(pady=2)

        self.pwd = SafeEntry(c, placeholder_text=master.tr("pwd"), show="*", width=320)
        self.pwd.pack(pady=6)
        self.pwd.bind("<KeyRelease>", self.check_strength)

        self.pwd_confirm = SafeEntry(c, placeholder_text=master.tr("pwd_confirm"), show="*", width=320)
        self.pwd_confirm.pack(pady=6)
        self.pwd_confirm.bind("<KeyRelease>", self.check_strength)

        self.lbl_ent = ctk.CTkLabel(c, text=master.tr("entropy"))
        self.lbl_ent.pack(pady=4)
        self.btn_init = ctk.CTkButton(c, text=master.tr("init_vault"), command=self.do_setup, state="disabled", fg_color="#2563eb", height=40)
        self.btn_init.pack(pady=15)
        self.target = None

    def select_dir(self):
        self.master.session.is_modal_active = True
        d = filedialog.askdirectory()
        self.master.session.is_modal_active = False
        self.master.session.ping()
        if d:
            self.target = Path(d) / "SVault_Encrypted_Data"
            self.lbl_dir.configure(text=str(self.target))
            self.check_strength(None)

    def check_strength(self, _):
        pwd = self.pwd.get()
        res = evaluate_entropy(pwd, self.master.lang)
        color = "#10b981" if res['valid'] else "#ef4444"
        self.lbl_ent.configure(text=f"{self.master.tr('entropy')}: {res['msg']}", text_color=color)
        can_proceed = res['valid'] and (pwd == self.pwd_confirm.get()) and (self.target is not None)
        self.btn_init.configure(state="normal" if can_proceed else "disabled")

    def do_setup(self):
        if self.pwd.get() != self.pwd_confirm.get():
            messagebox.showerror(self.master.tr("error"), self.master.tr("pwd_mismatch"))
            return
        try:
            quota_val = float(self.quota.get().strip())
        except Exception:
            quota_val = 10.0

        try:
            timeout_val = int(self.timeout_box.get().strip())
            if timeout_val < 5: timeout_val = 5
        except Exception:
            timeout_val = 300
        
        salt, mk = generate_salt(16), os.urandom(32)
        self.master.vault.bind_location(self.target)
        self.master.vault.config['settings']['quota_gb'] = quota_val
        self.master.vault.config['settings']['timeout_sec'] = timeout_val
        self.master.session.timeout = timeout_val
        self.master.vault.config.update({"salt": salt.hex(), "encrypted_mk": wrap_master_key(self.pwd.get(), salt, mk)})
        self.master.vault.atomic_save()
        self.master.show_login()

class LoginScreen(ctk.CTkFrame):
    def __init__(self, master, alert=""):
        super().__init__(master)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        c = ctk.CTkFrame(self, fg_color="#18181b", corner_radius=15, border_width=1, border_color="#27272a")
        c.grid(row=0, column=0, padx=20, pady=30)

        ctk.CTkButton(c, text="English" if master.lang == "ar" else "العربية", width=80, height=28, fg_color="#27272a", command=master.toggle_language).pack(anchor="ne", padx=15, pady=10)

        if alert:
            ctk.CTkLabel(c, text=alert, text_color="#f59e0b", font=("Arial", 12, "bold"), wraplength=350).pack(pady=5)
        ctk.CTkLabel(c, text="🔒", font=("Arial", 48)).pack(pady=10)
        ctk.CTkLabel(c, text=master.tr("login_title"), font=("Arial", 22, "bold")).pack(pady=5)

        self.pwd = SafeEntry(c, placeholder_text=master.tr("pwd"), show="*", width=300, height=40)
        self.pwd.pack(pady=15)
        self.pwd.bind("<Return>", lambda e: self.login())

        ctk.CTkButton(c, text=master.tr("unlock"), fg_color="#2563eb", hover_color="#1d4ed8", height=40, font=("Arial", 14, "bold"), command=self.login).pack(pady=(0, 25))

    def login(self):
        pwd = self.pwd.get()
        if not pwd: return
        try:
            salt = bytes.fromhex(self.master.vault.config['salt'])
            mk = unwrap_master_key(pwd, salt, self.master.vault.config['encrypted_mk'])
            self.master.session.timeout = self.master.vault.config['settings'].get('timeout_sec', 300)
            self.master.session.unlock(mk)
            self.master.show_dashboard()
        except AuthenticationError:
            messagebox.showerror(self.master.tr("error"), self.master.tr("err_auth"))
            self.pwd.delete(0, 'end')

class Dashboard(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.is_busy = False
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        h = ctk.CTkFrame(self, height=60, fg_color="#18181b", corner_radius=0)
        h.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(h, text=master.tr("dash_title"), font=("Arial", 18, "bold")).pack(side="left", padx=20, pady=15)

        self.btn_lock = ctk.CTkButton(h, text=master.tr("lock"), fg_color="#dc2626", hover_color="#b91c1c", width=100, command=self.manual_lock)
        self.btn_lock.pack(side="right", padx=10)

        self.btn_settings = ctk.CTkButton(h, text=master.tr("settings"), fg_color="#27272a", hover_color="#3f3f46", width=100, command=self.show_settings)
        self.btn_settings.pack(side="right", padx=10)

        c = ctk.CTkFrame(self, fg_color="transparent")
        c.grid(row=1, column=0, sticky="nsew", padx=15, pady=15)
        c.grid_columnconfigure(1, weight=1)
        c.grid_rowconfigure(0, weight=1)

        ctrl = ctk.CTkFrame(c, width=220, fg_color="#18181b", corner_radius=12)
        ctrl.grid(row=0, column=0, sticky="ns", padx=(0, 15))
        ctrl.grid_propagate(False)

        self.btn_file = ctk.CTkButton(ctrl, text=master.tr("import_file"), height=38, command=self.import_file)
        self.btn_file.pack(pady=(20, 8), padx=12, fill="x")

        self.btn_folder = ctk.CTkButton(ctrl, text=master.tr("import_folder"), fg_color="#7c3aed", hover_color="#6d28d9", height=38, command=self.import_folder)
        self.btn_folder.pack(pady=8, padx=12, fill="x")

        self.btn_ref = ctk.CTkButton(ctrl, text=master.tr("refresh"), fg_color="#2563eb", hover_color="#1d4ed8", height=38, command=self.refresh_list)
        self.btn_ref.pack(pady=8, padx=12, fill="x")

        self.prog = ctk.CTkProgressBar(ctrl)
        self.prog.pack(pady=20, padx=12, fill="x")
        self.prog.set(0)

        if WINDND_AVAILABLE and not getattr(self.master, '_dnd_hooked', False):
            try:
                windnd.hook_dropfiles(self.master, func=self.on_drop)
                self.master._dnd_hooked = True
            except Exception:
                pass

        self.list_frame = ctk.CTkScrollableFrame(c, fg_color="#18181b", corner_radius=12)
        self.list_frame.grid(row=0, column=1, sticky="nsew")
        self.engine = StreamingAEAD(master.session.mk)
        
        self.check_vault_integrity()
        self.refresh_list()

    def check_vault_integrity(self):
        if not self.master.vault.vault_dir or not self.master.vault.vault_dir.exists():
            messagebox.showwarning(self.master.tr("error"), self.master.tr("vault_missing"))
            self.locate_vault_folder()

    def locate_vault_folder(self):
        self.master.session.is_modal_active = True
        d = filedialog.askdirectory(title=self.master.tr("locate_vault"))
        self.master.session.is_modal_active = False
        self.master.session.ping()
        if d:
            p = Path(d)
            self.master.vault.bind_location(p)
            self.refresh_list()

    def set_busy(self, state: bool):
        self.is_busy = state
        st = "disabled" if state else "normal"
        self.btn_file.configure(state=st)
        self.btn_folder.configure(state=st)
        self.btn_ref.configure(state=st)

    def manual_lock(self):
        self.master.session.lock()
        self.master.show_login(self.master.tr("msg_locked"))

    def refresh_list(self):
        if self.is_busy: return
        for w in self.list_frame.winfo_children():
            w.destroy()
        files = self.master.vault.get_files()
        if not files:
            ctk.CTkLabel(self.list_frame, text=self.master.tr("empty"), text_color="gray", font=("Arial", 14)).pack(pady=60)
            return

        for f in files:
            r = ctk.CTkFrame(self.list_frame, fg_color="#27272a", corner_radius=8)
            r.pack(fill="x", pady=4, padx=5)
            try:
                meta = self.engine.extract_metadata(f)
                name = sanitize_filename(meta.get('orig_name', 'Unknown'))
                icon = "📁" if meta.get('is_folder') else "📄"
                
                ctk.CTkLabel(r, text=f"{icon}  {name}", font=("Arial", 13, "bold")).pack(side="left", padx=15, pady=12)
                
                ctk.CTkButton(r, text=self.master.tr("delete"), fg_color="#dc2626", hover_color="#b91c1c", width=65, height=32, command=lambda p=f: self.confirm_delete(p)).pack(side="right", padx=5)
                ctk.CTkButton(r, text=self.master.tr("export"), fg_color="#0284c7", hover_color="#0369a1", width=75, height=32, command=lambda p=f, m=meta: self.export_item(p, m)).pack(side="right", padx=5)
                ctk.CTkButton(r, text=self.master.tr("preview"), fg_color="#10b981", hover_color="#059669", width=75, height=32, command=lambda p=f, m=meta: self.preview(p, m)).pack(side="right", padx=5)
            except Exception:
                ctk.CTkLabel(r, text=f"⚠️ {self.master.tr('corrupt_file')}", text_color="#ef4444").pack(side="left", padx=15, pady=12)
                ctk.CTkButton(r, text=self.master.tr("delete"), fg_color="#dc2626", width=65, height=32, command=lambda p=f: (FilesystemSecurity.secure_delete(p), self.refresh_list())).pack(side="right", padx=10)

    def confirm_delete(self, p: Path):
        if messagebox.askyesno(self.master.tr("confirm"), self.master.tr("confirm_delete")):
            FilesystemSecurity.secure_delete(p)
            self.refresh_list()

    def on_drop(self, files):
        if self.master.session.locked or self.is_busy:
            return
        self.import_paths([Path(f.decode('mbcs', errors='ignore') if isinstance(f, bytes) else str(f)) for f in files])

    def import_file(self):
        if self.is_busy: return
        self.master.session.is_modal_active = True
        srcs = filedialog.askopenfilenames()
        self.master.session.is_modal_active = False
        self.master.session.ping()
        if srcs:
            self.import_paths([Path(s) for s in srcs])

    def import_folder(self):
        if self.is_busy: return
        self.master.session.is_modal_active = True
        src = filedialog.askdirectory()
        self.master.session.is_modal_active = False
        self.master.session.ping()
        if src:
            self.import_paths([Path(src)])

    def import_paths(self, paths):
        if not self.master.vault.vault_dir or not self.master.vault.vault_dir.exists():
            messagebox.showerror(self.master.tr("error"), self.master.tr("vault_missing"))
            self.locate_vault_folder()
            return

        self.master.session.is_modal_active = True
        user_wants_shred = messagebox.askyesno(
            self.master.tr("confirm_shred_title"),
            self.master.tr("confirm_shred_msg")
        )
        self.master.session.is_modal_active = False
        self.master.session.ping()

        self.set_busy(True)

        def worker():
            for p in paths:
                try:
                    is_dir = p.is_dir()
                    target = p
                    tmp_zip = None

                    if is_dir:
                        tmp_zip = self.master.session.temp_dir / f"{uuid.uuid4().hex}.zip"
                        shutil.make_archive(str(tmp_zip.with_suffix('')), 'zip', str(p))
                        target = tmp_zip

                    self.master.vault.verify_quota(target.stat().st_size)
                    dest = self.master.vault.vault_dir / f"{uuid.uuid4().hex}.vault"
                    tmp_dest = dest.with_suffix('.tmp')
                    
                    self.engine.encrypt_file(
                        target, tmp_dest,
                        {"is_folder": is_dir, "orig_name": sanitize_filename(p.name)},
                        threading.Event(),
                        lambda c, t: self.master.workers.q.put({'type': TaskEvent.PROGRESS, 'val': c / t})
                    )
                    tmp_dest.replace(dest)

                    if is_dir and tmp_zip and tmp_zip.exists():
                        FilesystemSecurity.secure_delete(tmp_zip)

                    if user_wants_shred:
                        if is_dir:
                            FilesystemSecurity.secure_wipe_tree(p)
                        else:
                            FilesystemSecurity.secure_delete(p)

                except Exception as e:
                    self.master.workers.q.put({'type': TaskEvent.ERROR, 'err': str(e)})

            self.master.workers.q.put({'type': TaskEvent.DONE})

        self.master.workers.submit(worker)

    def preview(self, v_file: Path, meta: dict):
        self.set_busy(True)
        def worker():
            try:
                clean_name = sanitize_filename(meta.get('orig_name', 'file'))
                if meta.get('is_folder'):
                    uid = uuid.uuid4().hex[:6]
                    out_zip = self.master.session.temp_dir / f"{uid}.zip"
                    out_folder = self.master.session.temp_dir / f"{clean_name}_{uid}"
                    self.engine.decrypt_file(v_file, out_zip, threading.Event(), lambda c, t: None)
                    out_folder.mkdir(exist_ok=True)
                    with zipfile.ZipFile(out_zip, 'r') as z:
                        z.extractall(out_folder)
                    FilesystemSecurity.secure_delete(out_zip)
                    self.master.session.track_preview(out_folder)
                    open_file_externally(out_folder)
                else:
                    out = self.master.session.temp_dir / f"view_{uuid.uuid4().hex[:6]}_{clean_name}"
                    self.engine.decrypt_file(v_file, out, threading.Event(), lambda c, t: None)
                    self.master.session.track_preview(out)
                    open_file_externally(out)
            except Exception as e:
                self.master.workers.q.put({'type': TaskEvent.ERROR, 'err': str(e)})
            finally:
                self.master.workers.q.put({'type': TaskEvent.DONE})
        self.master.workers.submit(worker)

    def export_item(self, v_file: Path, meta: dict):
        if self.is_busy: return
        self.master.session.is_modal_active = True
        clean_name = sanitize_filename(meta.get('orig_name', 'restored_item'))
        
        if meta.get('is_folder'):
            target_dir = filedialog.askdirectory(title=self.master.tr("export"))
            self.master.session.is_modal_active = False
            self.master.session.ping()
            if not target_dir: return
            dest_path = Path(target_dir) / clean_name
        else:
            target_file = filedialog.asksaveasfilename(title=self.master.tr("export"), initialfile=clean_name)
            self.master.session.is_modal_active = False
            self.master.session.ping()
            if not target_file: return
            dest_path = Path(target_file)

        self.set_busy(True)
        def worker():
            try:
                if meta.get('is_folder'):
                    tmp_zip = self.master.session.temp_dir / f"{uuid.uuid4().hex}.zip"
                    self.engine.decrypt_file(v_file, tmp_zip, threading.Event(), lambda c, t: self.master.workers.q.put({'type': TaskEvent.PROGRESS, 'val': c / t}))
                    dest_path.mkdir(exist_ok=True)
                    with zipfile.ZipFile(tmp_zip, 'r') as z:
                        z.extractall(dest_path)
                    FilesystemSecurity.secure_delete(tmp_zip)
                else:
                    self.engine.decrypt_file(v_file, dest_path, threading.Event(), lambda c, t: self.master.workers.q.put({'type': TaskEvent.PROGRESS, 'val': c / t}))
                
                messagebox.showinfo(self.master.tr("success"), self.master.tr("export_success"))
            except Exception as e:
                self.master.workers.q.put({'type': TaskEvent.ERROR, 'err': str(e)})
            finally:
                self.master.workers.q.put({'type': TaskEvent.DONE})

        self.master.workers.submit(worker)

    def show_settings(self):
        SettingsWindow(self.master)

# =====================================================================
# 9. SETTINGS WINDOW (CLEANED FROM ADMIN TOOLS)
# =====================================================================
class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title(master.tr("settings"))
        self.geometry("450x450")
        self.minsize(400, 420)
        
        self.master.session.is_modal_active = True
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grab_set()

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(self.scroll, text=master.tr("settings"), font=("Arial", 22, "bold")).pack(pady=(5, 15))

        sf = ctk.CTkFrame(self.scroll, fg_color="#18181b", corner_radius=12)
        sf.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(sf, text=master.tr("lang"), font=("Arial", 13, "bold")).pack(pady=(12, 4))
        self.lang_var = ctk.StringVar(value=master.lang)
        self.lang_menu = ctk.CTkSegmentedButton(sf, values=["ar", "en"], variable=self.lang_var)
        self.lang_menu.pack(pady=4)

        ctk.CTkLabel(sf, text=master.tr("timeout"), font=("Arial", 12, "bold")).pack(pady=(10, 2))
        self.timeout_entry = SafeEntry(sf, width=140, justify="center")
        self.timeout_entry.insert(0, str(master.vault.config['settings'].get('timeout_sec', 300)))
        self.timeout_entry.pack(pady=4)

        ctk.CTkButton(sf, text=master.tr("locate_vault"), fg_color="#27272a", hover_color="#3f3f46", command=self.change_vault_location).pack(pady=10)
        ctk.CTkButton(sf, text=master.tr("save"), fg_color="#2563eb", hover_color="#1d4ed8", command=self.save_general).pack(pady=(4, 15))

        pf = ctk.CTkFrame(self.scroll, fg_color="#18181b", corner_radius=12)
        pf.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(pf, text=master.tr("change_pwd"), font=("Arial", 14, "bold"), text_color="#38bdf8").pack(pady=10)

        self.old_p = SafeEntry(pf, placeholder_text=master.tr("old_pwd"), show="*", width=340)
        self.old_p.pack(pady=4)
        self.new_p = SafeEntry(pf, placeholder_text=master.tr("new_pwd"), show="*", width=340)
        self.new_p.pack(pady=4)
        self.cnf_p = SafeEntry(pf, placeholder_text=master.tr("confirm_new_pwd"), show="*", width=340)
        self.cnf_p.pack(pady=4)

        ctk.CTkButton(pf, text=master.tr("change_pwd"), fg_color="#0284c7", hover_color="#0369a1", command=self.change_password).pack(pady=(8, 15))

    def on_close(self):
        self.master.session.is_modal_active = False
        self.master.session.ping()
        self.grab_release()
        self.destroy()

    def change_vault_location(self):
        d = filedialog.askdirectory(title=self.master.tr("locate_vault"))
        if d:
            self.master.vault.bind_location(Path(d))
            messagebox.showinfo(self.master.tr("success"), self.master.tr("save_success"))

    def save_general(self):
        new_lang = self.lang_var.get()
        try:
            val = int(self.timeout_entry.get().strip())
            new_timeout = max(5, val)
        except Exception:
            new_timeout = 300
        
        self.master.vault.config['settings']['timeout_sec'] = new_timeout
        self.master.session.timeout = new_timeout
        self.master.vault.config['settings']['lang'] = new_lang
        self.master.vault.atomic_save()
        self.master.lang = new_lang
        messagebox.showinfo(self.master.tr("success"), self.master.tr("save_success"))
        self.on_close()
        self.master.title(self.master.tr("title"))
        self.master.show_dashboard()

    def change_password(self):
        old_pwd = self.old_p.get()
        new_pwd = self.new_p.get()
        cnf_pwd = self.cnf_p.get()

        if new_pwd != cnf_pwd:
            messagebox.showerror(self.master.tr("error"), self.master.tr("pwd_mismatch"))
            return

        if not evaluate_entropy(new_pwd, self.master.lang)['valid']:
            messagebox.showerror(self.master.tr("error"), self.master.tr("entropy"))
            return

        try:
            salt = bytes.fromhex(self.master.vault.config['salt'])
            mk = unwrap_master_key(old_pwd, salt, self.master.vault.config['encrypted_mk'])
            
            new_salt = generate_salt(16)
            self.master.vault.config['salt'] = new_salt.hex()
            self.master.vault.config['encrypted_mk'] = wrap_master_key(new_pwd, new_salt, mk)
            self.master.vault.atomic_save()
            self.master.session.unlock(mk)
            messagebox.showinfo(self.master.tr("success"), self.master.tr("pwd_changed"))
            self.on_close()
        except AuthenticationError:
            messagebox.showerror(self.master.tr("error"), self.master.tr("err_auth"))

# =====================================================================
# 10. MAIN APPLICATION ORCHESTRATOR
# =====================================================================
class SecureVaultUI(ctk.CTk):
    def __init__(self, vault_mgr: VaultManager):
        super().__init__()
        self.vault = vault_mgr
        self.lang = self.vault.config['settings'].get('lang', 'ar')
        self.session = SessionState(self.vault.config['settings'].get('timeout_sec', 300))
        self.workers = WorkerManager(self.on_worker_event)

        self.title(self.tr("title"))
        self.geometry("1100x720")
        self.minsize(850, 580)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        self.bind_all("<Any-KeyPress>", lambda e: self.session.ping())
        self.bind_all("<Button-1>", lambda e: self.session.ping())
        self.bind_all("<MouseWheel>", lambda e: self.session.ping())
        self.bind_all("<Motion>", self.throttled_motion_ping)

        self.current_view = None
        self.poll_heartbeat()
        self.check_license_and_boot()

        ctk.CTkLabel(self, text="Protected Architecture © Ahmed Smaili", font=("Arial", 11), text_color="#52525b").grid(row=1, column=0, pady=5)

    def throttled_motion_ping(self, event=None):
        now = time.time()
        if now - self.session.last_ping > 1.5:
            self.session.ping()

    def tr(self, key):
        return TRANSLATIONS.get(self.lang, TRANSLATIONS["en"]).get(key, key)

    def toggle_language(self):
        self.lang = "en" if self.lang == "ar" else "ar"
        self.vault.config['settings']['lang'] = self.lang
        self.vault.atomic_save()
        self.title(self.tr("title"))
        self.check_license_and_boot()

    def check_license_and_boot(self):
        if not LicenseManager.check_license():
            self.switch(LicenseScreen, alert=self.tr("license_expired") if LICENSE_FILE.exists() else "")
        else:
            if not self.vault.config.get("encrypted_mk"):
                self.show_setup()
            else:
                self.show_login()

    def on_worker_event(self, ev):
        if ev['type'] == TaskEvent.PROGRESS and hasattr(self.current_view, 'prog'):
            self.current_view.prog.set(ev['val'])
        elif ev['type'] == TaskEvent.DONE:
            if hasattr(self.current_view, 'prog'): self.current_view.prog.set(0)
            if hasattr(self.current_view, 'set_busy'): self.current_view.set_busy(False)
            if hasattr(self.current_view, 'refresh_list'): self.current_view.refresh_list()
        elif ev['type'] == TaskEvent.ERROR:
            if hasattr(self.current_view, 'prog'): self.current_view.prog.set(0)
            if hasattr(self.current_view, 'set_busy'): self.current_view.set_busy(False)
            messagebox.showerror(self.tr("error"), ev.get('err', 'An unexpected error occurred.'))

    def poll_heartbeat(self):
        self.workers.poll()
        if self.session.check_security():
            for widget in self.winfo_children():
                if isinstance(widget, ctk.CTkToplevel):
                    try:
                        widget.grab_release()
                        widget.destroy()
                    except Exception:
                        pass
            self.show_login(self.tr("msg_locked"))
        self.after(200, self.poll_heartbeat)

    def switch(self, view_class, **kwargs):
        if self.current_view:
            self.current_view.destroy()
        self.current_view = view_class(self, **kwargs)
        self.current_view.grid(row=0, column=0, sticky="nsew")

    def show_setup(self): self.switch(SetupWizard)
    def show_login(self, alert=""): self.switch(LoginScreen, alert=alert)
    def show_dashboard(self): self.switch(Dashboard)

def main():
    try:
        app = SecureVaultUI(VaultManager())
        app.protocol("WM_DELETE_WINDOW", lambda: (app.session.lock(), app.destroy()))
        app.mainloop()
    except Exception as e:
        print(f"Fatal Startup Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()