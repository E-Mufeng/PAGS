"""Windows handle boundary using existing pywin32 and documented Win32 APIs.

No direct syscall or new storage engine. Pin all directories without
write/delete sharing; open leaves without following reparse points; validate
the actual handle before IO. Create immutable records exclusively; no path reopen after validation.
Atomic replacement was rejected by the pilot and is not implemented here.
"""
from contextlib import contextmanager, ExitStack
import hashlib
import os
from pathlib import Path

import pywintypes
import win32con
import win32file
import win32event

PILOT = Path(__file__).resolve().parents[1]
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class BoundaryError(ValueError):
    pass


def absolute(path):
    raw = Path(path)
    if ".." in raw.parts:
        raise BoundaryError("parent traversal rejected")
    result = Path(os.path.abspath(raw))
    for component in result.parts[1:]:
        if ":" in component or component.endswith((" ", ".")):
            raise BoundaryError("ambiguous Windows name")
        if component.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}:
            raise BoundaryError("Windows device name")
    return result


def normalized(path):
    value = str(path)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def validate_handle(handle, expected, directory=False):
    info = win32file.GetFileInformationByHandle(handle)
    final = win32file.GetFinalPathNameByHandle(handle, 0)
    if normalized(final) != normalized(expected):
        raise BoundaryError("actual handle path differs from approved path")
    if info[0] & FILE_ATTRIBUTE_REPARSE_POINT:
        raise BoundaryError("reparse point rejected")
    if bool(info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise BoundaryError("unexpected file type")
    if not directory and info[7] != 1:
        raise BoundaryError("hardlinked file rejected")
    return info


@contextmanager
def writer_mutex(parent):
    # Existing kernel primitive, cross-process and automatically released on exit.
    name = "Local\\PAGS-" + hashlib.sha256(normalized(parent).encode()).hexdigest()
    mutex = win32event.CreateMutex(None, False, name)
    acquired = False
    try:
        result = win32event.WaitForSingleObject(mutex, 5000)
        acquired = result in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED)
        if not acquired:
            raise BoundaryError("atomic writer mutex timeout")
        yield
    finally:
        if acquired:
            win32event.ReleaseMutex(mutex)
        mutex.Close()


class SafeFiles:
    def __init__(self, scope):
        self.scope = absolute(scope)
        if not self.scope.is_relative_to(PILOT):
            raise BoundaryError("scope outside pilot")
        with self.pin(self.scope):
            pass

    def approved(self, path):
        result = absolute(path)
        if not result.is_relative_to(self.scope):
            raise BoundaryError("target outside approved scope")
        return result

    @contextmanager
    def pin(self, directory, create=False):
        directory = absolute(directory)
        if not directory.is_relative_to(PILOT):
            raise BoundaryError("directory outside pilot")
        with ExitStack() as stack:
            path = Path(directory.anchor)
            chain = [path]
            for part in directory.parts[1:]:
                path = path / part
                chain.append(path)
            for path in chain:
                if create and not path.exists():
                    try:
                        os.mkdir(path)
                    except FileExistsError:
                        pass
                try:
                    access = 0x20 | 0x80  # FILE_TRAVERSE | FILE_READ_ATTRIBUTES
                    handle = win32file.CreateFile(str(path), access,
                        win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING,
                        win32con.FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
                except pywintypes.error as error:
                    raise BoundaryError(f"directory handle rejected: {error.winerror}") from error
                stack.callback(handle.Close)
                validate_handle(handle, path, directory=True)
            yield handle

    def ensure_directory(self, path):
        target = self.approved(path)
        with self.pin(target, create=True):
            pass

    @contextmanager
    def open(self, path, writable=False, create=False):
        target = self.approved(path)
        with self.pin(target.parent):
            access = win32con.GENERIC_READ | (win32con.GENERIC_WRITE if writable else 0)
            share = win32con.FILE_SHARE_READ | (win32con.FILE_SHARE_WRITE if writable else 0)
            try:
                handle = win32file.CreateFile(str(target), access, share, None,
                    win32con.OPEN_ALWAYS if create else win32con.OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, None)
            except pywintypes.error as error:
                raise BoundaryError(f"file handle rejected: {error.winerror}") from error
            try:
                validate_handle(handle, target)
                yield handle
            finally:
                handle.Close()

    def read(self, path, maximum, after_open=None):
        with self.open(path) as handle:
            if after_open:
                after_open()
            info = validate_handle(handle, self.approved(path))
            size = (info[5] << 32) + info[6]
            if size > maximum:
                raise BoundaryError("file exceeds bounded read")
            _, data = win32file.ReadFile(handle, maximum + 1)
            if len(data) > maximum:
                raise BoundaryError("file grew beyond read limit")
            return data

    def create_new(self, path, data, after_pin=None):
        """Exclusive immutable creation, not atomic replacement.

        Readers of contexts/candidates must hold writer_mutex. A process crash
        can leave a partial record; subsequent parsing fails closed, never
        treating it as verified. No automatic repair or overwrite.
        """
        target = self.approved(path)
        if not isinstance(data, bytes):
            raise BoundaryError("write payload must be bytes")
        with writer_mutex(target.parent), self.pin(target.parent):
            if after_pin:
                after_pin()
            try:
                handle = win32file.CreateFile(str(target), win32con.GENERIC_WRITE,
                    0, None, win32con.CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, None)
            except pywintypes.error as error:
                raise BoundaryError(f"exclusive creation rejected: {error.winerror}") from error
            try:
                validate_handle(handle, target)
                win32file.WriteFile(handle, data)
                win32file.FlushFileBuffers(handle)
            finally:
                handle.Close()
