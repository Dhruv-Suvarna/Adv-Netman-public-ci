"""Host-process exclusion for credential writes and governed device-lock acquisition.

NMAS uses a local SQLite database.  The lock directory follows that database's
canonical path, so workers using the same database share the same flock files.
The kernel releases a flock on process death; a durable credential journal still
blocks other writers until the interrupted operation is reconciled.  No database
transaction is held across network I/O.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat

from django.conf import settings
from django.db import connection
from django.db.models import Q

from ... import models


class DeviceBusy(Exception):
    def __init__(self, devices):
        super().__init__("DEVICE_LOCKED")
        self.devices = tuple(devices)


class DeviceMutex:
    def __init__(self, devices, *, bootstrap_transition=None):
        self.devices = tuple(sorted(set(devices)))
        self.bootstrap_transition = bootstrap_transition
        self._fds = []

    def __enter__(self):
        try:
            if connection.vendor != "sqlite":
                raise OSError("process exclusion requires the supported local SQLite database")
            name = str(connection.settings_dict["NAME"])
            if name == ":memory:" or name.startswith("file:memory"):
                database = Path(settings.BASE_DIR).resolve() / f".memory-{os.getpid()}.sqlite3"
            elif name.startswith("file:"):
                raise OSError("unverified SQLite URI")
            else:
                database = Path(name).resolve()
            database_key = hashlib.sha256(str(database).encode()).hexdigest()
            directory = database.parent / "var" / "device-locks" / database_key
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("unprotected device-lock directory")
            for device in self.devices:
                path = directory / (hashlib.sha256(device.encode()).hexdigest() + ".lock")
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                self._fds.append(fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise OSError("unprotected device-lock file")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            interrupted = models.BootstrapCredentialTransition.objects.filter(device__name__in=self.devices).filter(
                Q(state__in=(models.BootstrapCredentialState.REPLACEMENT_INSTALLED,
                             models.BootstrapCredentialState.REPLACEMENT_VERIFIED,
                             models.BootstrapCredentialState.REVOCATION_PENDING,
                             models.BootstrapCredentialState.RETIREMENT_PENDING,
                             models.BootstrapCredentialState.UNCERTAIN)) |
                (Q(state=models.BootstrapCredentialState.APPROVED) & ~Q(executed_by="")))
            if self.bootstrap_transition is not None:
                interrupted = interrupted.exclude(pk=self.bootstrap_transition)
            if interrupted.exists():
                raise DeviceBusy(self.devices)
            return self
        except (OSError, DeviceBusy):
            self.__exit__(None, None, None)
            raise DeviceBusy(self.devices) from None
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, _kind, _value, _traceback):
        while self._fds:
            os.close(self._fds.pop())  # closing also releases flock, including partial acquisition
