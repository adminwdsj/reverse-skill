#!/usr/bin/env python3
"""Control Xiaomi/Mi TV Assistant's local Airkan HTTP service.

The CLI supports discovery, six-character on-screen pairing, signed APK
installation, installed-app queries, and package launching without ADB.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import random
import socket
import stat
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    CRYPTO_IMPORT_ERROR: Exception | None = None
except ImportError as error:
    hashes = serialization = asym_padding = rsa = None
    Cipher = algorithms = modes = PKCS7 = None
    CRYPTO_IMPORT_ERROR = error

AUTH_SUCCESS = 60000
INVALID_SERIAL = 60007
INSTALL_SUCCESS = 200
EMPTY_APK = 1010
HMAC_SECRET = b"3e4f2550-0818-4665-9bfb-edbe9b15f586"
MULTIPART_BOUNDARY = "--------httpPostFromPhone"
DEFAULT_CONTROL_PORT = 6095
DEFAULT_INSTALL_PORT = 9095
DEFAULT_TIMEOUT = 15


def default_state_path() -> Path:
    override = os.environ.get("MITV_AIRKAN_STATE")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "mitv-airkan" / "state.json"
    return Path.home() / ".config" / "mitv-airkan" / "state.json"


def pending_path(state_path: Path) -> Path:
    return state_path.with_name(f"{state_path.stem}.pending{state_path.suffix}")


def require_crypto() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Python dependency 'cryptography' is missing. Run the repository "
            "bootstrap for capability 'python-cryptography'."
        ) from CRYPTO_IMPORT_ERROR


def custom_b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii").replace("=", "$")


def custom_b64decode(value: str) -> bytes:
    return base64.b64decode(value.replace("$", "="))


def make_magic(rng: random.Random | None = None) -> int:
    source = rng or random.SystemRandom()
    first, second, third, fourth = [source.randrange(10) for _ in range(4)]
    fifth = source.randrange(1, 10)
    score = (second % 2) + (third % 3) + (fourth % 4) + (fifth % 5)
    if score in (2, 4, 6, 8, 10):
        lead = 2
    elif score in (3, 5, 7):
        lead = score
    elif score == 9:
        lead = 3
    else:
        lead = 1
    return int(f"{lead}{fifth}{fourth}{third}{second}{first}")


def derive_cbc_material(verify_text: str) -> tuple[str, str]:
    if not verify_text:
        raise ValueError("verification text is empty")
    source = verify_text.encode()
    expanded = bytearray(1024)
    for index in range(1000):
        expanded[index] = source[index % len(source)]
    digest = bytes(expanded)
    for _ in range(10000):
        digest = hmac.new(HMAC_SECRET, digest, hashlib.sha256).digest()
    material = custom_b64encode(digest)
    midpoint = len(material) // 2
    return material[:midpoint][:16], material[midpoint:][:16]


def aes_cbc_decrypt(encoded: str, key: str, iv: str) -> str:
    require_crypto()
    decryptor = Cipher(
        algorithms.AES(key.encode()), modes.CBC(iv.encode())
    ).decryptor()
    padded = decryptor.update(custom_b64decode(encoded)) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode()


def raw_rsa_encrypt(text: str, public_key_text: str) -> str:
    require_crypto()
    public_key = serialization.load_der_public_key(custom_b64decode(public_key_text))
    numbers = public_key.public_numbers()
    modulus_size = (numbers.n.bit_length() + 7) // 8
    raw = text.encode()
    if len(raw) >= modulus_size:
        raise ValueError(
            f"raw RSA input is {len(raw)} bytes; modulus is {modulus_size} bytes"
        )
    value = int.from_bytes(raw, "big")
    encrypted = pow(value, numbers.e, numbers.n).to_bytes(modulus_size, "big")
    return custom_b64encode(encrypted)


def signed_query(device_id: str, encrypted: str, magic: int | None = None) -> str:
    return (
        f"device_id={urllib.parse.quote(device_id, safe='')}"
        f"&magic={magic if magic is not None else make_magic()}"
        "&tail=0"
        f"&encrypt={urllib.parse.quote(encrypted, safe='')}"
    )


def generate_identity() -> dict[str, str]:
    require_crypto()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_text = custom_b64encode(private_der)
    public_text = custom_b64encode(public_der)
    return {
        "private_key": private_text,
        "public_key": public_text,
        "device_id": hashlib.md5(public_text.encode()).hexdigest(),
    }


def secure_write_json(path: Path, data: dict[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.write("\n")
        try:
            temp_path.chmod(0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temp_path.exists():
            temp_path.unlink()


def load_json(path: Path) -> dict[str, Any]:
    with path.expanduser().open(encoding="utf-8") as source:
        return json.load(source)


def decode_json(body: bytes) -> dict[str, Any]:
    text = body.decode(errors="replace").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    return value if isinstance(value, dict) else {"value": value}


def http_request(
    host: str,
    port: int,
    path: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def json_request(
    host: str,
    port: int,
    path: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, Any]]:
    status, _, payload = http_request(host, port, path, method, body, headers, timeout)
    return status, decode_json(payload)


def resolve_host(args: argparse.Namespace, state: dict[str, Any] | None = None) -> str:
    host = getattr(args, "host", None) or (state or {}).get("host")
    if not host:
        raise ValueError("TV host is required; pass --host or pair first")
    return str(host)


def command_auth_request(args: argparse.Namespace) -> dict[str, Any]:
    identity = generate_identity()
    query = urllib.parse.urlencode({"device_id": identity["device_id"]})
    status, response = json_request(
        args.host, args.control_port, f"/requestAuth?{query}", timeout=args.timeout
    )
    if status != 200 or response.get("code") != AUTH_SUCCESS:
        raise RuntimeError(f"requestAuth failed: HTTP {status}, response={response}")
    response_data = response.get("resp_data") or {}
    if response_data.get("device_id") != identity["device_id"]:
        raise RuntimeError("requestAuth returned a different device_id")
    pending = {
        **identity,
        "host": args.host,
        "control_port": args.control_port,
        "install_port": args.install_port,
        "request_auth": response_data,
    }
    target = pending_path(args.state)
    secure_write_json(target, pending)
    return {
        "status": "verification-required",
        "tv_id": response_data.get("tv_id"),
        "version_code": response_data.get("versionCode"),
        "pending_state": str(target),
        "instruction": "Enter the six-character code shown on the TV with auth-complete.",
    }


def command_auth_complete(args: argparse.Namespace) -> dict[str, Any]:
    if len(args.code) != 6:
        raise ValueError("verification code must contain exactly six characters")
    pending_file = pending_path(args.state)
    pending = load_json(pending_file)
    host = resolve_host(args, pending)
    response_data = pending["request_auth"]
    verify_text = args.code + str(response_data.get("verify_code_additional") or "")
    cbc_key, cbc_iv = derive_cbc_material(verify_text)
    decrypted = aes_cbc_decrypt(response_data["public_key"], cbc_key, cbc_iv)
    if not decrypted.startswith("airkan"):
        raise RuntimeError("verification code was rejected: decrypted prefix is invalid")
    wrapped_key = decrypted[6:]
    if len(wrapped_key.encode()) <= 16:
        raise RuntimeError("requestAuth payload did not contain a TV public key")
    tv_public_key = wrapped_key.encode()[16:].decode()
    serialization.load_der_public_key(custom_b64decode(tv_public_key))
    plaintext = (
        f"airkandevicePublicKey={pending['public_key']}&serial_num=1"
    )
    encrypted = raw_rsa_encrypt(plaintext, tv_public_key)
    path = f"/completeAuth?{signed_query(pending['device_id'], encrypted)}"
    status, response = json_request(
        host,
        int(pending.get("control_port", args.control_port)),
        path,
        timeout=args.timeout,
    )
    if status != 200 or response.get("code") != AUTH_SUCCESS:
        raise RuntimeError(f"completeAuth failed: HTTP {status}, response={response}")
    state = {
        "host": host,
        "control_port": int(pending.get("control_port", args.control_port)),
        "install_port": int(pending.get("install_port", args.install_port)),
        "device_id": pending["device_id"],
        "tv_id": (response.get("resp_data") or {}).get("tv_id")
        or response_data.get("tv_id"),
        "tv_public_key": tv_public_key,
        "private_key": pending["private_key"],
        "public_key": pending["public_key"],
        "serial_num": 1,
        "cbc_key": cbc_key,
        "cbc_iv": cbc_iv,
    }
    secure_write_json(args.state, state)
    try:
        pending_file.unlink()
    except FileNotFoundError:
        pass
    return {
        "status": "paired",
        "host": host,
        "tv_id": state["tv_id"],
        "state": str(args.state),
    }


def build_signed_install_query(state: dict[str, Any], serial_num: int) -> str:
    encrypted = raw_rsa_encrypt(
        f"airkanserial_num={serial_num}", state["tv_public_key"]
    )
    return signed_query(state["device_id"], encrypted)


def is_invalid_serial(status: int, response: dict[str, Any]) -> bool:
    return response.get("code") == INVALID_SERIAL or (
        status == 400 and "invalid serial" in str(response).lower()
    )


def sync_serial(
    state_path: Path,
    state: dict[str, Any],
    start: int | None,
    attempts: int,
    timeout: int,
) -> dict[str, Any]:
    host = state["host"]
    port = int(state.get("install_port", DEFAULT_INSTALL_PORT))
    guess = start if start is not None else int(state.get("serial_num", 1)) + 1
    history: list[dict[str, Any]] = []
    for _ in range(attempts):
        query = build_signed_install_query(state, guess)
        status, response = json_request(
            host,
            port,
            f"/phoneAppInstallV2?{query}",
            method="POST",
            body=b"",
            headers={"Content-Length": "0", "Connection": "close"},
            timeout=timeout,
        )
        history.append({"serial_num": guess, "http_status": status, "response": response})
        if is_invalid_serial(status, response):
            guess += 1
            continue
        if status == 200 and response.get("data_status") == EMPTY_APK:
            state["serial_num"] = guess
            secure_write_json(state_path, state)
            return {
                "status": "synchronized",
                "serial_num": guess,
                "attempts": len(history),
            }
        raise RuntimeError(
            f"serial synchronization stopped at {guess}: HTTP {status}, response={response}"
        )
    raise RuntimeError(
        f"serial synchronization did not converge after {attempts} attempts; "
        f"last guess was {guess - 1}"
    )


def command_sync_serial(args: argparse.Namespace) -> dict[str, Any]:
    state = load_json(args.state)
    state["host"] = resolve_host(args, state)
    state.setdefault("install_port", args.install_port)
    secure_write_json(args.state, state)
    return sync_serial(args.state, state, args.start, args.max_attempts, args.timeout)


def stream_apk_upload(
    host: str,
    port: int,
    path: str,
    apk: Path,
    timeout: int,
) -> tuple[int, dict[str, Any]]:
    filename = apk.name
    prefix = (
        f"--{MULTIPART_BOUNDARY}\r\n"
        f'Content-Disposition: form-data;name="Filedata"; filename="{filename}"\r\n'
        "\r\n"
    ).encode()
    suffix = f"\r\n--{MULTIPART_BOUNDARY}--\r\n".encode()
    content_length = len(prefix) + apk.stat().st_size + len(suffix)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.putrequest("POST", path, skip_accept_encoding=True)
        connection.putheader("Connection", "Keep-Alive")
        connection.putheader("Accept", "text/*")
        connection.putheader("FileName", str(apk.resolve()))
        connection.putheader(
            "Content-Type", f"multipart/form-data; boundary={MULTIPART_BOUNDARY}"
        )
        connection.putheader("Content-Length", str(content_length))
        connection.endheaders()
        connection.send(prefix)
        with apk.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                connection.send(chunk)
        connection.send(suffix)
        response = connection.getresponse()
        return response.status, decode_json(response.read())
    finally:
        connection.close()


def command_install(args: argparse.Namespace) -> dict[str, Any]:
    apk = args.apk.expanduser().resolve()
    if not apk.is_file():
        raise FileNotFoundError(apk)
    if apk.suffix.lower() != ".apk":
        raise ValueError("installer accepts a single .apk file, not an APK bundle")
    state = load_json(args.state)
    state["host"] = resolve_host(args, state)
    state.setdefault("install_port", args.install_port)
    secure_write_json(args.state, state)
    if not args.no_sync:
        sync_serial(args.state, state, args.sync_start, args.max_attempts, args.timeout)
        state = load_json(args.state)
    serial_num = args.serial if args.serial is not None else int(state["serial_num"]) + 1
    query = build_signed_install_query(state, serial_num)
    previous_serial = int(state["serial_num"])
    state["serial_num"] = serial_num
    secure_write_json(args.state, state)
    try:
        status, response = stream_apk_upload(
            resolve_host(args, state),
            int(state.get("install_port", args.install_port)),
            f"/phoneAppInstallV2?{query}",
            apk,
            args.upload_timeout,
        )
    except Exception:
        raise
    if is_invalid_serial(status, response):
        state["serial_num"] = previous_serial
        secure_write_json(args.state, state)
        raise RuntimeError(f"APK upload rejected the serial number: {response}")
    if status != 200 or response.get("data_status") != INSTALL_SUCCESS:
        raise RuntimeError(f"APK upload failed: HTTP {status}, response={response}")
    return {
        "status": "accepted",
        "apk": str(apk),
        "bytes": apk.stat().st_size,
        "serial_num": serial_num,
        "response": response,
    }


def fetch_apps(host: str, port: int, timeout: int) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"action": "getinstalledapp", "count": 999, "changeIcon": 1}
    )
    status, response = json_request(
        host, port, f"/controller?{query}", timeout=timeout
    )
    if status != 200 or response.get("status") != 0:
        raise RuntimeError(f"getinstalledapp failed: HTTP {status}, response={response}")
    data = response.get("data") or {}
    apps = data.get("AppInfo") or []
    return apps if isinstance(apps, list) else []


def command_apps(args: argparse.Namespace) -> dict[str, Any]:
    state = load_json(args.state) if args.state.exists() else {}
    host = resolve_host(args, state)
    apps = fetch_apps(host, args.control_port or int(state.get("control_port", 6095)), args.timeout)
    if args.filter:
        needle = args.filter.lower()
        apps = [
            app
            for app in apps
            if needle
            in f"{app.get('PackageName', '')} {app.get('AppName', '')}".lower()
        ]
    return {"host": host, "count": len(apps), "apps": apps}


def command_launch(args: argparse.Namespace) -> dict[str, Any]:
    state = load_json(args.state) if args.state.exists() else {}
    host = resolve_host(args, state)
    port = args.control_port or int(state.get("control_port", 6095))
    query = urllib.parse.urlencode(
        {
            "action": "startapp",
            "type": "packagename",
            "packagename": args.package,
        }
    )
    status, response = json_request(host, port, f"/controller?{query}", timeout=args.timeout)
    if status != 200 or response.get("status") != 0:
        raise RuntimeError(f"startapp failed: HTTP {status}, response={response}")
    return {"status": "launched", "package": args.package, "response": response}


def command_info(args: argparse.Namespace) -> dict[str, Any]:
    state = load_json(args.state) if args.state.exists() else {}
    host = resolve_host(args, state)
    port = args.control_port or int(state.get("control_port", 6095))
    alive_status, alive = json_request(host, port, "/request?action=isalive", timeout=args.timeout)
    system_status, system = json_request(
        host, port, "/controller?action=getsysteminfo", timeout=args.timeout
    )
    return {
        "host": host,
        "isalive_http": alive_status,
        "isalive": alive,
        "system_http": system_status,
        "system": system,
    }


def local_cidr() -> ipaddress.IPv4Network:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        address = probe.getsockname()[0]
    finally:
        probe.close()
    return ipaddress.ip_network(f"{address}/24", strict=False)


def probe_tv(address: str, port: int, timeout: float) -> dict[str, Any] | None:
    try:
        status, response = json_request(
            address, port, "/request?action=isalive", timeout=max(1, int(timeout))
        )
    except (OSError, TimeoutError, http.client.HTTPException):
        return None
    if status == 200 and response.get("status") == 0:
        return {"host": address, "port": port, "response": response}
    return None


def command_discover(args: argparse.Namespace) -> dict[str, Any]:
    network = ipaddress.ip_network(args.cidr, strict=False) if args.cidr else local_cidr()
    hosts = [str(address) for address in network.hosts()]
    if len(hosts) > args.max_hosts:
        raise ValueError(
            f"CIDR contains {len(hosts)} hosts; increase --max-hosts explicitly"
        )
    found: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(probe_tv, host, args.control_port, args.probe_timeout)
            for host in hosts
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    found.sort(key=lambda item: ipaddress.ip_address(item["host"]))
    return {"cidr": str(network), "count": len(found), "devices": found}


def command_doctor(args: argparse.Namespace) -> dict[str, Any]:
    checks: dict[str, Any] = {
        "python": {
            "ok": sys.version_info >= (3, 9),
            "version": sys.version.split()[0],
        },
        "cryptography": {
            "ok": CRYPTO_IMPORT_ERROR is None,
            "error": str(CRYPTO_IMPORT_ERROR) if CRYPTO_IMPORT_ERROR else None,
        },
        "state": {"path": str(args.state), "exists": args.state.exists()},
    }
    if args.state.exists():
        mode = stat.S_IMODE(args.state.stat().st_mode)
        checks["state"].update({"mode": oct(mode), "private": mode & 0o077 == 0})
        try:
            state = load_json(args.state)
            host = state.get("host")
            if host:
                checks["tv"] = {
                    "host": host,
                    "control_port_open": probe_port(host, int(state.get("control_port", 6095))),
                    "install_port_open": probe_port(host, int(state.get("install_port", 9095))),
                }
        except Exception as error:
            checks["state"]["load_error"] = str(error)
    ok = all(
        item.get("ok", True) and item.get("private", True)
        for item in checks.values()
        if isinstance(item, dict)
    )
    return {"ok": ok, "checks": checks}


def probe_port(host: str, port: int) -> bool:
    connection = socket.socket()
    connection.settimeout(2)
    try:
        return connection.connect_ex((host, port)) == 0
    finally:
        connection.close()


def add_common(parser: argparse.ArgumentParser, include_host: bool = True) -> None:
    if include_host:
        parser.add_argument("--host", help="TV IPv4 address or hostname")
    parser.add_argument("--state", type=Path, default=default_state_path())
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mitv-airkan")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="scan a local CIDR for Mi TV Assistant")
    discover.add_argument("--cidr", help="CIDR to scan; defaults to the active IPv4 /24")
    discover.add_argument("--control-port", type=int, default=DEFAULT_CONTROL_PORT)
    discover.add_argument("--probe-timeout", type=float, default=1.5)
    discover.add_argument("--workers", type=int, default=64)
    discover.add_argument("--max-hosts", type=int, default=1024)
    discover.set_defaults(handler=command_discover)

    auth_request = subparsers.add_parser("auth-request", help="request an on-screen code")
    auth_request.add_argument("--host", required=True)
    auth_request.add_argument("--state", type=Path, default=default_state_path())
    auth_request.add_argument("--control-port", type=int, default=DEFAULT_CONTROL_PORT)
    auth_request.add_argument("--install-port", type=int, default=DEFAULT_INSTALL_PORT)
    auth_request.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    auth_request.set_defaults(handler=command_auth_request)

    auth_complete = subparsers.add_parser("auth-complete", help="complete pairing with TV code")
    add_common(auth_complete)
    auth_complete.add_argument("--code", required=True)
    auth_complete.add_argument("--control-port", type=int, default=DEFAULT_CONTROL_PORT)
    auth_complete.add_argument("--install-port", type=int, default=DEFAULT_INSTALL_PORT)
    auth_complete.set_defaults(handler=command_auth_complete)

    sync = subparsers.add_parser("sync-serial", help="pre-synchronize signed request serial")
    add_common(sync)
    sync.add_argument("--install-port", type=int, default=DEFAULT_INSTALL_PORT)
    sync.add_argument("--start", type=int)
    sync.add_argument("--max-attempts", type=int, default=32)
    sync.set_defaults(handler=command_sync_serial)

    install = subparsers.add_parser("install", help="upload and install an APK")
    add_common(install)
    install.add_argument("apk", type=Path)
    install.add_argument("--install-port", type=int, default=DEFAULT_INSTALL_PORT)
    install.add_argument("--serial", type=int)
    install.add_argument("--sync-start", type=int)
    install.add_argument("--max-attempts", type=int, default=32)
    install.add_argument("--no-sync", action="store_true")
    install.add_argument("--upload-timeout", type=int, default=900)
    install.set_defaults(handler=command_install)

    apps = subparsers.add_parser("apps", help="list installed applications")
    add_common(apps)
    apps.add_argument("--control-port", type=int)
    apps.add_argument("--filter")
    apps.set_defaults(handler=command_apps)

    launch = subparsers.add_parser("launch", help="launch an installed package")
    add_common(launch)
    launch.add_argument("package")
    launch.add_argument("--control-port", type=int)
    launch.set_defaults(handler=command_launch)

    info = subparsers.add_parser("info", help="read TV Assistant system information")
    add_common(info)
    info.add_argument("--control-port", type=int)
    info.set_defaults(handler=command_info)

    doctor = subparsers.add_parser("doctor", help="check dependency, state, and TV health")
    doctor.add_argument("--state", type=Path, default=default_state_path())
    doctor.set_defaults(handler=command_doctor)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = args.handler(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted"}), file=sys.stderr)
        return 130
    except Exception as error:
        print(
            json.dumps(
                {"error": type(error).__name__, "message": str(error)},
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
