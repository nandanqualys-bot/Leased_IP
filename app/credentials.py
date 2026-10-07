"""Optional provider settings stored outside the checkout and analysis database."""
import os
from pathlib import Path
from dotenv import dotenv_values
from .storage import data_dir

NAMES = ('SHODAN_API_KEY', 'CENSYS_API_TOKEN', 'CENSYS_ORG_ID')


def path():
    return data_dir() / '.env'


def presence():
    saved = dotenv_values(path()) if path().exists() else {}
    return {name: bool(os.getenv(name) or saved.get(name)) for name in NAMES}


def activate():
    if path().exists():
        for name, value in dotenv_values(path()).items():
            if name in NAMES and value:
                os.environ.setdefault(name, value)


def save(updates):
    """Blank entries preserve prior values. Never return or log the values."""
    destination = path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    current = dotenv_values(destination) if destination.exists() else {}
    for name, value in updates.items():
        if name in NAMES and value:
            current[name] = value
            os.environ[name] = value
    # Use quote escaping supported by python-dotenv; avoid writing comments or secrets to results.
    contents = ''.join(f'{name}={_quote(current[name])}\n' for name in NAMES if current.get(name))
    temporary = destination.with_name(destination.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(contents)
    os.replace(temporary, destination)
    if os.name != 'nt':
        os.chmod(destination, 0o600)


def _quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
