"""Shared durable-write helpers (stdlib only).

Extracted in M4 Round B so both ``mbcp.deletion`` and ``mbcp.attestation``
(key file + accept-list writes) can use them without a circular import.
``mbcp.deletion`` re-exports both names — existing references
(``deletion_module._atomic_write``, monkeypatches included) keep working.
"""

import os
import tempfile
from pathlib import Path


def _atomic_write(path, data):
    """Write ``data`` bytes to ``path`` atomically and durably."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory):
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
