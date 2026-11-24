"""R0.1 preflight on an authorized, offline, self-contained COPY only.
Never use on a live cabinet DB. No row identifiers or secret values emitted.
SQLCipher mode requires the application's compatible sqlcipher3 driver.
"""
import argparse
import getpass
import hashlib
import json
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
    if any(Path(str(path) + suffix).exists() or Path(str(path) + suffix).is_symlink()
           for suffix in ('-wal', '-shm', '-journal')):
        raise RuntimeError('COPY_HAS_SIDECARS')


def audit(path, driver, key=None):
    path = path.absolute()
    check_copy(path)
    before = sha256(path)
    conn = None
    result = {'integrity_ok': False, 'fk_violations': None, 'unchanged': False}
    try:
        conn = driver.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
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
        # No details (table names, row IDs, messages) leave the process.
        result['integrity_ok'] = conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        result['fk_violations'] = sum(1 for _ in conn.execute('PRAGMA foreign_key_check'))
    finally:
        if conn is not None:
            conn.close()
        check_copy(path)
        result['unchanged'] = sha256(path) == before
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
