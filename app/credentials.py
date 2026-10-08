"""Local authenticated encryption; secrets never enter the analysis database."""
import os
import threading
from cryptography.fernet import Fernet
from dotenv import dotenv_values
from .storage import data_dir

NAMES = ('SHODAN_API_KEY', 'CENSYS_API_TOKEN', 'CENSYS_ORG_ID')
_lock = threading.RLock()

def path():
    return data_dir() / 'credentials.enc'

def _write(destination, content):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)
    os.replace(temporary, destination)
    if os.name != 'nt':
        os.chmod(destination, 0o600)

def _cipher():
    key = data_dir() / 'encryption.key'
    if not key.exists():
        if path().exists():
            raise ValueError('Encryption key missing. Restore the local key before using credentials.')
        _write(key, Fernet.generate_key())
    return Fernet(key.read_bytes())

def _read():
    with _lock:
        values = {}
        if path().exists():
            # A fixed-order, NUL-separated payload avoids plaintext JSON files.
            values = dict(zip(NAMES, _cipher().decrypt(path().read_bytes()).decode().split(chr(0))))
        legacy = data_dir() / '.env'
        if legacy.exists():
            values = {**{k:v for k,v in dotenv_values(legacy).items() if k in NAMES}, **values}
            _persist(values)
            legacy.unlink()
        return values

def _persist(values):
    payload = chr(0).join(values.get(name) or '' for name in NAMES).encode()
    _write(path(), _cipher().encrypt(payload))

def presence():
    try:
        saved = _read()
    except Exception:
        saved = {}
    return {name: bool(os.getenv(name) or saved.get(name)) for name in NAMES}

def activate():
    for name, value in _read().items():
        if value:
            os.environ.setdefault(name, value)

def save(updates):
    with _lock:
        if any(chr(0) in value for value in updates.values()):
            raise ValueError('Invalid credential value')
        current = _read()
        current.update({k:v for k,v in updates.items() if k in NAMES and v})
        _persist(current)
        for name, value in current.items():
            if value:
                os.environ[name] = value

def redact(text):
    for name in NAMES:
        value = os.getenv(name)
        if value:
            text = text.replace(value, '[REDACTED]')
    return text


def storage_status():
    try:
        _read()
        return 'Encrypted' if path().exists() else 'Not configured · encrypted on save'
    except Exception:
        return 'Locked · restore the original encryption key and credential file'


def sanitize(value):
    """Redact secret strings before persistence without changing numeric evidence."""
    if isinstance(value, str): return redact(value)
    if isinstance(value, dict): return {k:sanitize(v) for k,v in value.items()}
    if isinstance(value, (list, tuple)): return [sanitize(v) for v in value]
    return value
