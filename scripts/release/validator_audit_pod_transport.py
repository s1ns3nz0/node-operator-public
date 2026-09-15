#!/usr/bin/env python3
"""Internal S3 reader through an already-authorized, identity-pinned Pod.

The lifecycle caller owns the fixed kubeconfig, image/PodIdentity authority,
and Pod cleanup. UID checks detect replacement, not a compromised container.
This transport never creates Pods or uses workstation AWS credentials. The
optional call hook is trusted test infrastructure, not an external input.
Downloads target disposable caller-owned scratch files, not final evidence;
failed writes may leave partial scratch that the caller must delete.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_BYTES = 8 * 1024 * 1024

class TransportError(subprocess.SubprocessError):
    """Fail closed as an unavailable subprocess transport to archive callers."""
    pass

# Object identifiers are positional arguments, never shell source. The range
# also bounds remote disk consumption independently of the caller's HEAD.
# The inclusive endpoint deliberately requests one sentinel byte above the cap.
GET_SCRIPT = '''set -eu
umask 077
tmp=$(mktemp /tmp/validator-audit-object.XXXXXXXX)
cleanup() { rc=$?; trap - EXIT HUP INT TERM; rm -f -- "$tmp" || rc=70; exit "$rc"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
aws s3api get-object --bucket "$1" --key "$2" --version-id "$3" --region "$4" --range bytes=0-8388608 --no-cli-pager "$tmp" >/dev/null
[ "$(wc -c < "$tmp")" -le 8388608 ] || exit 65
cat -- "$tmp"
'''

class PodAWSTransport:
    def __init__(self, namespace, name, uid, bucket, prefix, region, call=None):
        if (namespace != "validator-observability"
                or not re.fullmatch(r"validator-audit-reader-[a-z0-9-]{1,32}", name)
                or not re.fullmatch(r"[a-zA-Z0-9-]{1,64}", uid)
                or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket)
                or prefix != "validator/"
                or not re.fullmatch(r"[a-z]{2}-[a-z0-9-]+-[0-9]+", region)):
            raise TransportError("invalid reader identity")
        self.namespace, self.name, self.uid = namespace, name, uid
        self.bucket, self.prefix, self.region, self.call = bucket, prefix, region, call

    def _run(self, command):
        try:
            data = self.call(command) if self.call else subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=True, timeout=45).stdout
            if not isinstance(data, bytes) or len(data) > MAX_BYTES:
                raise TransportError("reader response exceeded bound")
            return data
        except (OSError, subprocess.SubprocessError) as error:
            raise TransportError("reader command failed") from error

    def _exec(self, command):
        base = ["kubectl", "-n", self.namespace]
        actual = self._run([*base, "get", "pod", self.name, "-o", "jsonpath={.metadata.uid}"])
        if actual != self.uid.encode():
            raise TransportError("reader Pod identity changed")
        result = self._run([*base, "exec", self.name, "-c", "reader", "--", *command])
        actual = self._run([*base, "get", "pod", self.name, "-o", "jsonpath={.metadata.uid}"])
        if actual != self.uid.encode():
            raise TransportError("reader Pod identity changed during command")
        return result

    def __call__(self, args):
        if not isinstance(args, (list, tuple)) or not all(isinstance(arg, str) and "\x00" not in arg for arg in args):
            raise TransportError("invalid AWS argument type")
        if len(args) < 2 or args[0] != "s3api" or args[1] not in ("list-objects-v2", "head-object", "get-object"):
            raise TransportError("AWS operation is not allowed")
        operation = args[1]
        options, output = {}, None
        index = 2
        while index < len(args):
            flag = args[index]
            if operation == "get-object" and index == len(args) - 1 and not flag.startswith("--"):
                output = Path(flag); break
            if flag in options or not flag.startswith("--"):
                raise TransportError("invalid AWS argument")
            if flag in ("--no-cli-pager", "--no-paginate"):
                options[flag] = True; index += 1
            else:
                if index + 1 >= len(args): raise TransportError("missing AWS argument")
                options[flag] = args[index + 1]; index += 2
        allowed = {"--bucket", "--region", "--no-cli-pager", "--output"}
        allowed |= {"--prefix", "--max-keys", "--continuation-token", "--no-paginate"} if operation == "list-objects-v2" else {"--key"}
        if operation in ("get-object", "head-object"): allowed.add("--version-id")
        if (set(options) - allowed or options.get("--bucket") != self.bucket
                or options.get("--region") != self.region or options.get("--output", "json") != "json"):
            raise TransportError("AWS request escaped reader scope")
        if operation == "list-objects-v2":
            if options.get("--prefix") != self.prefix or options.get("--max-keys") != "64" or options.get("--no-paginate") is not True:
                raise TransportError("unbounded archive listing")
            token = options.get("--continuation-token")
            if token is not None and (not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                raise TransportError("invalid archive continuation token")
        else:
            key = options.get("--key")
            if not isinstance(key, str) or not key.startswith(self.prefix) or len(key.encode()) > 1024:
                raise TransportError("object escaped reader prefix")
        if operation == "head-object" and "--version-id" in options:
            version = options["--version-id"]
            if not isinstance(version, str) or not version or version == "null" or len(version) > 1024: raise TransportError("invalid object version")
        if operation != "get-object":
            return self._exec(["aws", *args])
        version = options.get("--version-id")
        if not isinstance(version, str) or not version or version == "null" or len(version) > 1024 or output is None or not output.is_absolute():
            raise TransportError("versioned download is required")
        try:
            before = output.lstat()
            if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid():
                raise TransportError("unsafe local download target")
            data = self._exec(["sh", "-c", GET_SCRIPT, "validator-audit-get", self.bucket, key, version, self.region])
            fd = os.open(output, os.O_WRONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "wb") as stream:
                actual = os.fstat(stream.fileno())
                if ((actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)
                        or stat.S_IMODE(actual.st_mode) != 0o600 or actual.st_uid != os.geteuid()):
                    raise TransportError("download target changed")
                stream.truncate(0); stream.write(data); stream.flush(); os.fsync(stream.fileno())
                after = output.lstat()
                if ((after.st_dev, after.st_ino) != (actual.st_dev, actual.st_ino)
                        or not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode) != 0o600):
                    raise TransportError("download target changed during write")
        except OSError as error:
            raise TransportError("download failed") from error
        return b"{}"
