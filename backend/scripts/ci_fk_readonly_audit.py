"""R0.1 preflight on an authorized, offline, self-contained COPY only.
Never use on a live cabinet DB. No row identifiers or secret values emitted.
SQLCipher mode requires the application's compatible sqlcipher3 driver.
"""
import argparse
import getpass
import hashlib
import json
import os
import stat
import shutil
import tempfile
from pathlib import Path
import sqlite3
import sys


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def check_copy(path):
    if path.is_symlink() or not path.is_file() or any(p.is_symlink() for p in path.parents):
        raise RuntimeError('COPY_REQUIRED')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('COPY_LINK_COUNT_INVALID')
    if os.name == 'posix' and info.st_mode & 0o022:
        raise RuntimeError('COPY_PERMISSIONS_UNSAFE')
    if any(Path(str(path) + suffix).exists() or Path(str(path) + suffix).is_symlink()
           for suffix in ('-wal', '-shm', '-journal')):
        raise RuntimeError('COPY_HAS_SIDECARS')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_mode)


def audit(path, driver, key=None):
    # The caller must still establish a consistent, offline source snapshot.
    # Never apply immutable=1 directly to an externally supplied source.
    path = path.absolute()
    check_copy(path)
    original = identity(path.lstat())
    result = {'integrity_ok': False, 'fk_violations': None, 'unchanged': False}
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    with tempfile.TemporaryDirectory(prefix='.dc-fk-audit-', dir=path.parent) as directory:
        private = Path(directory)
        if os.name == 'posix':
            private.chmod(0o700)
        snapshot = private / 'snapshot.db'
        with os.fdopen(os.open(path, flags), 'rb') as source:
            if identity(os.fstat(source.fileno())) != original:
                raise RuntimeError('COPY_IDENTITY_CHANGED')
            with os.fdopen(os.open(snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), 0o600), 'wb') as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            before = sha256(snapshot)
            source.seek(0)
            h = hashlib.sha256()
            for block in iter(lambda: source.read(1024 * 1024), b''):
                h.update(block)
            check_copy(path)
            if h.hexdigest() != before or identity(os.fstat(source.fileno())) != original or identity(path.lstat()) != original:
                raise RuntimeError('COPY_CHANGED_DURING_STAGING')
        check_copy(snapshot)
        conn = None
        try:
            conn = driver.connect(snapshot.as_uri() + '?mode=ro&immutable=1', uri=True)
            if key is not None:
                conn.execute("PRAGMA key = '" + key.replace("'", "''") + "'")
                if not conn.execute('PRAGMA cipher_version').fetchone():
                    raise RuntimeError('SQLCIPHER_REQUIRED')
            conn.execute('PRAGMA query_only=ON')
            if conn.execute('PRAGMA query_only').fetchone() != (1,):
                raise RuntimeError('QUERY_ONLY_REQUIRED')
            conn.execute('PRAGMA foreign_keys=ON')
            if conn.execute('PRAGMA foreign_keys').fetchone() != (1,):
                raise RuntimeError('FK_REQUIRED')
            result['integrity_ok'] = conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
            result['fk_violations'] = sum(1 for _ in conn.execute('PRAGMA foreign_key_check'))
        finally:
            if conn is not None:
                conn.close()
            check_copy(snapshot)
            check_copy(path)
            if identity(path.lstat()) != original or sha256(path) != before or identity(path.lstat()) != original or sha256(snapshot) != before:
                raise RuntimeError('COPY_CHANGED_DURING_AUDIT')
            result['unchanged'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('copy', type=Path)
    parser.add_argument('--offline-copy', action='store_true', required=True)
    parser.add_argument('--synthetic-plaintext', action='store_true', help='Tests only; never for patient data')
    args = parser.parse_args()
    try:
        if args.synthetic_plaintext:
            driver, key = sqlite3, None
        else:
            from sqlcipher3 import dbapi2 as driver
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise RuntimeError('LOCAL_INTERACTIVE_TTY_REQUIRED')
            key = getpass.getpass('SQLCipher passphrase (local, hidden): ')
            if not key:
                raise RuntimeError('KEY_REQUIRED')
        result = audit(args.copy, driver, key)
        print(json.dumps(result, sort_keys=True))
        return 0 if result == {'integrity_ok': True, 'fk_violations': 0, 'unchanged': True} else 1
    except Exception:
        # Never expose raw SQLCipher/SQLite exceptions, paths or row values.
        print(json.dumps({'status': 'AUDIT_REFUSED_OR_FAILED'}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
