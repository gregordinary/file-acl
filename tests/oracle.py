"""The reference oracle the comparison tests drive.

It answers questions about the reference implementations, the kernel and
libacl, by asking them: the kernel through the extended-attribute system calls
Python exposes, and libacl through ctypes. The tests run it as a child process,
inside a user namespace where a test needs one, and speak a line protocol over
its standard input and output.

A request is one line of tab-separated fields: an operation and its arguments.
Bytes (paths, attribute values, list texts) are hexadecimal, so a field never
holds a tab or a line end. Each request has one answer line:

    ok[<TAB>field...]     the question was answered
    err<TAB>WORD          the reference refused, WORD naming how (an errno
                          name such as EINVAL, or a word the operation defines)
    fail<TAB>message      the oracle itself could not answer; a test stops

Operations:

    ping                  ok
    libacl                ok, or err with the reason libacl cannot be loaded
    acls DIR              ok where a file in DIR holds a POSIX access control
                          list the kernel stores; err ERRNO where it does not
    check TEXT            libacl's verdict on a list's text: ok valid where
                          acl_from_text reads it and acl_check passes it;
                          ok invalid CODE where acl_check refuses it, CODE its
                          answer in hexadecimal; err unread where
                          acl_from_text refuses the text
    read TEXT             the list libacl's acl_from_text reads from TEXT, with
                          acl_check's verdict: ok valid VALUE, or ok invalid
                          CODE VALUE, VALUE its version-2 attribute value in
                          the order libacl holds it and CODE acl_check's
                          answer in hexadecimal; err unread where
                          acl_from_text refuses the text
    accounts DIR PASSWD GROUP
                          writes PASSWD and GROUP, and an nsswitch.conf
                          reading both from files alone, to DIR and mounts
                          them over /etc/passwd, /etc/group and
                          /etc/nsswitch.conf, so names resolve through them
                          alone. Only an oracle running in user and mount
                          namespaces of its own may do it, before it has
                          looked up any name: ok, or err with what mount said
    calcmask TEXT         the list libacl reads from TEXT after acl_calc_mask:
                          ok VALUE, its version-2 attribute value; err unread
                          where acl_from_text refuses the text
    equivmode TEXT        libacl's acl_equiv_mode on the list TEXT: ok
                          ANSWER MODE, ANSWER 0 where a mode is equivalent and
                          1 where not, MODE the permission bits in octal;
                          err unread where acl_from_text refuses the text
    frommode MODE         the list libacl's acl_from_mode makes of the octal
                          MODE: ok VALUE, its version-2 attribute value
    make DIR KIND         a new file in DIR: ok PATH, or err ERRNO where the
                          kernel refuses to make it. KIND is file (empty,
                          mode 0640), dir (mode 0750), fifo (mode 0640),
                          socket (bound and closed, mode 0640), chardev (a
                          character device numbered 0:0, mode 0640), or
                          symlink (to a name that does not exist)
    set PATH NAME VALUE   sets the extended attribute NAME of PATH to VALUE,
                          without following a symbolic link: ok, or err ERRNO
    get PATH NAME         the value of the extended attribute NAME of PATH,
                          without following a symbolic link: ok VALUE, or err
                          ERRNO (ENODATA where it has none)
    mode PATH             the permission bits, set-user-ID, set-group-ID and
                          sticky bits of PATH, without following a symbolic
                          link: ok MODE, in octal
    chmod PATH MODE       sets the mode of PATH to the octal MODE: ok, or err
                          ERRNO
    chown PATH UID GID    sets the owner and group of PATH: ok, or err ERRNO
    access PATH UID GID GROUPS
                          what access(2) grants a process with user UID,
                          group GID and the comma-separated supplementary
                          GROUPS (- for none) on PATH: ok PERMS, as rwx with
                          a - for each permission refused. The process
                          changes to PATH's directory before taking those
                          ids, so it needs search permission on that
                          directory alone
    tmpfs DIR             mounts a new tmpfs on DIR, which only an oracle
                          running in a user and mount namespace of its own
                          may do: ok, or err with what mount said
    run DIR ARGV          runs the program ARGV names, its arguments
                          separated by NULs, in DIR, inside the oracle's
                          namespaces and with its account database, so a tar
                          extracts and archives as a process there does: ok
                          STATUS ERRORS, its exit status and its standard
                          error; err with the reason it could not be started
"""

import ctypes
import ctypes.util
import errno
import itertools
import os
import socket
import stat
import struct
import subprocess
import sys

UNDEFINED_ID = 0xFFFFFFFF
ACCESS = "system.posix_acl_access"

_libacl = None


def load_libacl():
    """libacl, loaded on first use, or an OSError saying why it cannot be."""
    global _libacl
    if _libacl is None:
        lib = ctypes.CDLL(ctypes.util.find_library("acl") or "libacl.so.1", use_errno=True)
        lib.acl_from_text.restype = ctypes.c_void_p
        lib.acl_from_text.argtypes = [ctypes.c_char_p]
        lib.acl_check.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        lib.acl_free.argtypes = [ctypes.c_void_p]
        lib.acl_error.restype = ctypes.c_char_p
        lib.acl_error.argtypes = [ctypes.c_int]
        lib.acl_calc_mask.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.acl_equiv_mode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        lib.acl_from_mode.restype = ctypes.c_void_p
        lib.acl_from_mode.argtypes = [ctypes.c_uint]
        lib.acl_to_any_text.restype = ctypes.c_void_p
        lib.acl_to_any_text.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char, ctypes.c_int]
        _libacl = lib
    return _libacl


def errno_name(err):
    return errno.errorcode.get(err.errno, str(err.errno))


def value(entries):
    """The version-2 attribute value of (tag, perm, id) entries."""
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in entries)


# acl_to_any_text's option for numeric ids rather than names (TEXT_NUMERIC_IDS),
# found by trying each bit.
TEXT_NUMERIC_IDS = 0x08

TAG_NAMES = {"user": (0x01, 0x02), "group": (0x04, 0x08), "mask": (0x10, None), "other": (0x20, None)}


def binary(lib, acl):
    """The version-2 attribute value of a libacl list, in the order libacl
    holds it, read from its own long text with numeric ids."""
    text = lib.acl_to_any_text(acl, None, ord("\n"), TEXT_NUMERIC_IDS)
    if not text:
        raise OSError(ctypes.get_errno(), "acl_to_any_text failed")
    try:
        lines = ctypes.string_at(text).decode().split("\n")
    finally:
        lib.acl_free(ctypes.c_void_p(text))
    entries = []
    # libacl appends an `#effective:` comment, after a tab, to some entries.
    for line in filter(None, (line.split("\t")[0] for line in lines)):
        tag, qualifier, perms = line.split(":")
        obj, named = TAG_NAMES[tag]
        perm = sum(bit for letter, bit in zip(perms, (4, 2, 1)) if letter != "-")
        if qualifier:
            entries.append((named, perm, int(qualifier)))
        else:
            entries.append((obj, perm, UNDEFINED_ID))
    return value(entries)


def op_read(text):
    lib = load_libacl()
    acl = lib.acl_from_text(text)
    if not acl:
        return ["err", "unread"]
    try:
        last = ctypes.c_int(-1)
        code = lib.acl_check(acl, ctypes.byref(last))
        held = binary(lib, acl).hex()
    finally:
        lib.acl_free(acl)
    if code < 0:
        return ["fail", "acl_check failed: errno %d" % ctypes.get_errno()]
    if code == 0:
        return ["ok", "valid", held]
    return ["ok", "invalid", "%#x" % code, held]


def op_accounts(directory, passwd, group):
    files = {
        b"passwd": passwd,
        b"group": group,
        b"nsswitch.conf": b"passwd: files\ngroup: files\n",
    }
    for name, body in files.items():
        with open(os.path.join(directory, name), "wb") as f:
            f.write(body)
    for name in files:
        done = subprocess.run(
            ["mount", "--bind", os.path.join(directory, name), b"/etc/" + name],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        if done.returncode != 0:
            said = done.stderr.decode(errors="replace").strip() or "exit status %d" % done.returncode
            return ["err", said]
    return ["ok"]


def op_calcmask(text):
    lib = load_libacl()
    acl = ctypes.c_void_p(lib.acl_from_text(text))
    if not acl:
        return ["err", "unread"]
    try:
        if lib.acl_calc_mask(ctypes.byref(acl)) != 0:
            return ["fail", "acl_calc_mask failed: errno %d" % ctypes.get_errno()]
        return ["ok", binary(lib, acl).hex()]
    finally:
        lib.acl_free(acl)


def op_equivmode(text):
    lib = load_libacl()
    acl = lib.acl_from_text(text)
    if not acl:
        return ["err", "unread"]
    try:
        mode = ctypes.c_uint(0)
        answer = lib.acl_equiv_mode(acl, ctypes.byref(mode))
    finally:
        lib.acl_free(acl)
    if answer < 0:
        return ["fail", "acl_equiv_mode failed: errno %d" % ctypes.get_errno()]
    return ["ok", str(answer), "%o" % mode.value]


def op_frommode(mode):
    lib = load_libacl()
    acl = lib.acl_from_mode(int(mode, 8))
    if not acl:
        return ["fail", "acl_from_mode failed: errno %d" % ctypes.get_errno()]
    try:
        return ["ok", binary(lib, acl).hex()]
    finally:
        lib.acl_free(acl)


def op_ping():
    return ["ok"]


def op_libacl():
    try:
        load_libacl()
    except OSError as err:
        return ["err", str(err)]
    return ["ok"]


def op_acls(directory):
    # The owner, the owning group, a mask and everyone else: a list the kernel
    # stores, naming no id a user namespace might not map.
    stated = value([(0x01, 6, UNDEFINED_ID), (0x04, 4, UNDEFINED_ID), (0x10, 4, UNDEFINED_ID), (0x20, 0, UNDEFINED_ID)])
    path = os.path.join(directory, b".acl-probe-%d" % os.getpid())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    os.close(fd)
    try:
        os.setxattr(path, ACCESS, stated)
        held = os.getxattr(path, ACCESS)
    except OSError as err:
        return ["err", errno_name(err)]
    finally:
        os.unlink(path)
    if held != stated:
        return ["fail", "the kernel stored %s for %s" % (held.hex(), stated.hex())]
    return ["ok"]


def op_check(text):
    lib = load_libacl()
    acl = lib.acl_from_text(text)
    if not acl:
        return ["err", "unread"]
    try:
        last = ctypes.c_int(-1)
        code = lib.acl_check(acl, ctypes.byref(last))
    finally:
        lib.acl_free(acl)
    if code < 0:
        return ["fail", "acl_check failed: errno %d" % ctypes.get_errno()]
    if code == 0:
        return ["ok", "valid"]
    return ["ok", "invalid", "%#x" % code]


# Names for the files `make` creates, unique for the oracle's lifetime.
_made = itertools.count()


def op_make(directory, kind):
    name = b"made-%d-%d" % (os.getpid(), next(_made))
    path = os.path.join(directory, name)
    if kind == "file":
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640))
    elif kind == "dir":
        os.mkdir(path, 0o750)
    elif kind == "fifo":
        os.mkfifo(path, 0o640)
        os.chmod(path, 0o640)
    elif kind == "socket":
        # Bound by a name relative to its directory: a socket's path is
        # limited to 107 bytes, and the tests' directories are deep.
        here = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        os.chdir(directory)
        try:
            bound = socket.socket(socket.AF_UNIX)
            bound.bind(name)
            bound.close()
        finally:
            os.fchdir(here)
            os.close(here)
        os.chmod(path, 0o640)
    elif kind == "chardev":
        # Making a device needs privilege, except a character device
        # numbered 0:0, which Linux 5.8 and later let any user make.
        try:
            os.mknod(path, stat.S_IFCHR | 0o640, os.makedev(0, 0))
        except OSError as err:
            return ["err", errno.errorcode.get(err.errno, str(err.errno))]
        os.chmod(path, 0o640)
    elif kind == "symlink":
        os.symlink(b"made-nowhere", path)
    else:
        return ["fail", "no kind %r" % kind]
    return ["ok", path.hex()]


def op_set(path, name, data):
    try:
        os.setxattr(path, name, data, follow_symlinks=False)
    except OSError as err:
        return ["err", errno_name(err)]
    return ["ok"]


def op_get(path, name):
    try:
        held = os.getxattr(path, name, follow_symlinks=False)
    except OSError as err:
        return ["err", errno_name(err)]
    return ["ok", held.hex()]


def op_mode(path):
    return ["ok", "%o" % stat.S_IMODE(os.lstat(path).st_mode)]


def op_chmod(path, mode):
    try:
        os.chmod(path, int(mode, 8))
    except OSError as err:
        return ["err", errno_name(err)]
    return ["ok"]


def op_chown(path, uid, gid):
    try:
        os.chown(path, int(uid), int(gid), follow_symlinks=False)
    except OSError as err:
        return ["err", errno_name(err)]
    return ["ok"]


def op_access(path, uid, gid, groups):
    """access(2)'s answers for a process with these ids, asked in a child
    that takes them, so the oracle keeps its own."""
    supplementary = [] if groups == "-" else [int(g) for g in groups.split(",")]
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        # The child answers and exits whatever happens: returning, it would
        # read the tests' requests beside the oracle, and hold the pipe open
        # that the oracle waits on.
        answer = "!the child stopped"
        try:
            os.close(read)
            os.chdir(os.path.dirname(path) or b".")
            os.setgroups(supplementary)
            os.setgid(int(gid))
            os.setuid(int(uid))
            name = os.path.basename(path)
            answer = "".join(
                letter if os.access(name, flag) else "-"
                for letter, flag in (("r", os.R_OK), ("w", os.W_OK), ("x", os.X_OK))
            )
        except OSError as err:
            answer = "!" + errno_name(err)
        except Exception as err:
            answer = "!%s: %s" % (type(err).__name__, err)
        finally:
            try:
                os.write(write, answer.encode())
            finally:
                os._exit(0)
    os.close(write)
    answer = b""
    while chunk := os.read(read, 64):
        answer += chunk
    os.close(read)
    os.waitpid(pid, 0)
    if answer.startswith(b"!"):
        return ["fail", "the child asking access(2) failed: %s" % answer[1:].decode()]
    return ["ok", answer.decode()]


def op_tmpfs(directory):
    done = subprocess.run(
        ["mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", directory],
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )
    if done.returncode != 0:
        said = done.stderr.decode(errors="replace").strip() or "exit status %d" % done.returncode
        return ["err", said]
    return ["ok"]


def op_run(directory, argv):
    try:
        done = subprocess.run(
            argv.split(b"\0"),
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except OSError as err:
        return ["err", str(err)]
    return ["ok", str(done.returncode), done.stderr.hex()]


OPERATIONS = {
    "ping": (op_ping, ""),
    "libacl": (op_libacl, ""),
    "acls": (op_acls, "b"),
    "check": (op_check, "b"),
    "read": (op_read, "b"),
    "accounts": (op_accounts, "bbb"),
    "calcmask": (op_calcmask, "b"),
    "equivmode": (op_equivmode, "b"),
    "frommode": (op_frommode, "s"),
    "make": (op_make, "bs"),
    "set": (op_set, "bbb"),
    "get": (op_get, "bb"),
    "mode": (op_mode, "b"),
    "chmod": (op_chmod, "bs"),
    "chown": (op_chown, "bss"),
    "access": (op_access, "bsss"),
    "tmpfs": (op_tmpfs, "b"),
    "run": (op_run, "bb"),
}


def answer(line):
    fields = line.rstrip("\n").split("\t")
    name, args = fields[0], fields[1:]
    if name not in OPERATIONS:
        return ["fail", "no operation %r" % name]
    function, kinds = OPERATIONS[name]
    if len(args) != len(kinds):
        return ["fail", "%s takes %d fields, given %d" % (name, len(kinds), len(args))]
    try:
        decoded = [bytes.fromhex(a) if k == "b" else a for a, k in zip(args, kinds)]
    except ValueError as err:
        return ["fail", "a field is not hexadecimal: %s" % err]
    try:
        return function(*decoded)
    except Exception as err:  # Reported, not raised: the test names it.
        return ["fail", "%s: %s" % (type(err).__name__, err)]


def main():
    for line in sys.stdin:
        # A message may quote anything; its tabs and line ends would split it.
        fields = [f.replace("\t", " ").replace("\n", " ") for f in answer(line)]
        sys.stdout.write("\t".join(fields) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
