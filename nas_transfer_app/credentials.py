import base64
import ctypes
from ctypes import wintypes

from .config import APP_NAME


try:
    import keyring
except ImportError:  # pragma: no cover - depends on installed environment
    keyring = None


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32


def _blob_from_bytes(data):
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _bytes_from_blob(blob):
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        kernel32.LocalFree(blob.pbData)


def _dpapi_encrypt(text):
    data = text.encode("utf-8")
    in_blob, _in_buffer = _blob_from_bytes(data)
    out_blob = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise OSError("Windows DPAPI encryption failed")

    return base64.b64encode(_bytes_from_blob(out_blob)).decode("ascii")


def _dpapi_decrypt(encoded):
    encrypted = base64.b64decode(encoded.encode("ascii"))
    in_blob, _in_buffer = _blob_from_bytes(encrypted)
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise OSError("Windows DPAPI decryption failed")

    return _bytes_from_blob(out_blob).decode("utf-8")


class CredentialStore:
    def __init__(self, config):
        self.config = config

    def _key(self, role, nas_name, username):
        return f"{role}:{nas_name}:{username}"

    def _get_secret_by_key(self, key):
        if keyring is not None:
            try:
                secret = keyring.get_password(APP_NAME, key)
                if secret:
                    return secret
            except Exception:
                pass

        encrypted = self.config.get("encrypted_credentials", {}).get(key)
        if not encrypted:
            return ""

        return _dpapi_decrypt(encrypted)

    def _save_secret_by_key(self, key, secret):
        if not key or not secret:
            return

        if keyring is not None:
            try:
                keyring.set_password(APP_NAME, key, secret)
                return
            except Exception:
                pass

        encrypted_credentials = self.config.setdefault("encrypted_credentials", {})
        encrypted_credentials[key] = _dpapi_encrypt(secret)

    def _delete_secret_by_key(self, key):
        if not key:
            return

        if keyring is not None:
            try:
                keyring.delete_password(APP_NAME, key)
            except Exception:
                pass

        encrypted_credentials = self.config.setdefault("encrypted_credentials", {})
        encrypted_credentials.pop(key, None)

    def get_password(self, role, nas_name, username):
        if not username:
            return ""

        return self._get_secret_by_key(self._key(role, nas_name, username))

    def save_password(self, role, nas_name, username, password):
        if not username or not password:
            return

        self._save_secret_by_key(self._key(role, nas_name, username), password)

    def delete_password(self, role, nas_name, username):
        if not username:
            return

        self._delete_secret_by_key(self._key(role, nas_name, username))

    def get_secret(self, name):
        return self._get_secret_by_key(f"secret:{name}")

    def save_secret(self, name, secret):
        self._save_secret_by_key(f"secret:{name}", secret)

    def delete_secret(self, name):
        self._delete_secret_by_key(f"secret:{name}")
