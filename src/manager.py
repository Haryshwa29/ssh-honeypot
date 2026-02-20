#!/usr/bin/env python3
"""
Docker-backed SSH Honeypot Manager (Writable + Full Command Logging)

- Manager IS the SSH server (Paramiko), so it can log credentials + commands.
- Spawns a writable Docker container per SSH session.
- Executes each entered command inside the container via `docker exec`.
- Writes per-session logs: metadata.json, session.jsonl, transcript.txt
- Supports input echo + backspace (so attacker can see what they type).
- Graceful Ctrl+C shutdown (no traceback spam).

Run:
  python src/manager.py

Connect from Kali:
  ssh anyuser@<UBUNTU_HONEYNET_IP> -p 2222
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple

import paramiko


# =========================
# Config
# =========================
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222

DOCKER_IMAGE = os.environ.get("HONEYPOT_IMAGE", "honeypot-ssh:latest")
DOCKER_NETWORK = os.environ.get("HONEYPOT_DOCKER_NETWORK", "")  # e.g. "honeynet" if you want to force a network
LOG_ROOT = Path(os.environ.get("HONEYPOT_LOG_DIR", "logs/sessions"))

# Resource limits (safe defaults)
MEM_LIMIT = os.environ.get("HONEYPOT_MEM_LIMIT", "256m")
PIDS_LIMIT = int(os.environ.get("HONEYPOT_PIDS_LIMIT", "256"))
CPU_QUOTA = int(os.environ.get("HONEYPOT_CPU_QUOTA", "50000"))  # 50% of a CPU

# Execution timeout for each command
EXEC_TIMEOUT = int(os.environ.get("HONEYPOT_EXEC_TIMEOUT", "30"))

# Banner
BANNER = "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux)\r\n"


# =========================
# Utilities
# =========================
def utc_ts() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sh(args, timeout=20) -> subprocess.CompletedProcess:
    """Run a command (no shell=True), capture stdout/stderr."""
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def ensure_host_key() -> paramiko.RSAKey:
    """
    Persistent host key so clients don't get a "host key changed" every run.
    (They will only get it once when you switch from the old system to this new manager.)
    """
    key_path = Path("host_key_rsa.pem")
    if key_path.exists():
        return paramiko.RSAKey(filename=str(key_path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    os.chmod(key_path, 0o600)
    return key


def mkdir_session(ip: str) -> Path:
    sess_id = f"sess-{uuid.uuid4().hex[:6]}"
    folder = LOG_ROOT / f"{utc_ts().replace(':','-')}_{ip}_{sess_id}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False))


def append_jsonl(path: Path, obj) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def append_text(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(text)


# =========================
# Docker control
# =========================
def docker_run_container() -> str:
    """
    Start a per-session container (writable by default).
    We keep it alive with sleep, then exec commands into it.
    """
    cmd = [
        "docker", "run", "-d",
        "--rm",
        "--memory", MEM_LIMIT,
        "--pids-limit", str(PIDS_LIMIT),
        "--cpu-quota", str(CPU_QUOTA),
        "--security-opt", "no-new-privileges",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
    ]

    if DOCKER_NETWORK.strip():
        cmd += ["--network", DOCKER_NETWORK.strip()]

    cmd += [DOCKER_IMAGE, "sleep", "infinity"]

    cp = sh(cmd, timeout=30)
    if cp.returncode != 0:
        raise RuntimeError(f"Docker run failed:\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}")
    return cp.stdout.strip()


def docker_exec(container_id: str, bash_cmd: str, timeout=EXEC_TIMEOUT) -> Tuple[int, str, str]:
    cp = sh(["docker", "exec", "-i", container_id, "bash", "-lc", bash_cmd], timeout=timeout)
    return cp.returncode, cp.stdout, cp.stderr


def docker_stop(container_id: str) -> None:
    sh(["docker", "stop", "-t", "1", container_id], timeout=10)


# =========================
# Paramiko Server
# =========================
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, session_dir: Path):
        self.client_ip = client_ip
        self.session_dir = session_dir
        self.event = threading.Event()
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    def check_auth_password(self, username, password):
        # Honeypot behavior: accept any password but log it.
        self.username = username
        self.password = password
        append_jsonl(self.session_dir / "session.jsonl", {
            "ts": utc_ts(),
            "type": "auth_password",
            "src_ip": self.client_ip,
            "username": username,
            "password": password,
        })
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# =========================
# Interactive line editor (echo + backspace)
# =========================
def recv_line(chan: paramiko.Channel, transcript_path: Path) -> Optional[str]:
    """
    Read one command line from the SSH channel.
    - Echoes typed characters back to the client (so user can see typing).
    - Handles backspace.
    - Returns a completed line without trailing newline.
    - Returns None if connection closed.
    """
    buf_chars = []
    while True:
        data = chan.recv(1)
        if not data:
            return None

        ch = data.decode("utf-8", errors="ignore")
        append_text(transcript_path, ch)

        # Handle Enter (CR or LF)
        if ch == "\r" or ch == "\n":
            # Normalize to CRLF for client display
            chan.send("\r\n")
            return "".join(buf_chars)

        # Handle backspace (DEL or BS)
        if ch in ("\x7f", "\b"):
            if buf_chars:
                buf_chars.pop()
                # Move cursor back, erase char, move back again
                chan.send("\b \b")
            continue

        # Ignore other control chars
        if ord(ch) < 32:
            continue

        # Normal char: store + echo
        buf_chars.append(ch)
        chan.send(ch)


# =========================
# Session handler
# =========================
def handle_client(client_sock: socket.socket, client_addr, host_key: paramiko.PKey):
    client_ip = client_addr[0]
    session_dir = mkdir_session(client_ip)

    jsonl_path = session_dir / "session.jsonl"
    transcript_path = session_dir / "transcript.txt"
    meta_path = session_dir / "metadata.json"

    meta = {
        "ts_start": utc_ts(),
        "src_ip": client_ip,
        "listen": f"{LISTEN_HOST}:{LISTEN_PORT}",
        "docker_image": DOCKER_IMAGE,
        "docker_network": DOCKER_NETWORK.strip() or "default",
        "session_dir": str(session_dir),
    }
    write_json(meta_path, meta)

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)

    server = HoneypotServer(client_ip=client_ip, session_dir=session_dir)

    try:
        transport.start_server(server=server)
    except Exception as e:
        append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "error", "where": "start_server", "error": str(e)})
        transport.close()
        return

    chan = transport.accept(20)
    if chan is None:
        append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "error", "where": "accept", "error": "no channel"})
        transport.close()
        return

    # Wait until client requests shell
    server.event.wait(10)

    # Start per-session container (writable)
    try:
        container_id = docker_run_container()
    except Exception as e:
        append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "error", "where": "docker_run", "error": str(e)})
        chan.send("\r\n[honeypot] backend unavailable\r\n")
        chan.close()
        transport.close()
        return

    append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "container_started", "container_id": container_id})

    # Shell state
    cwd = "/"
    prompt_user = "honeypot"
    prompt_host = container_id[:12]

    def send_prompt():
        chan.send(f"{prompt_user}@{prompt_host}:{cwd}$ ")

    # Send banner
    chan.send("\r\n" + BANNER + "\r\n")
    send_prompt()

    try:
        while True:
            line = recv_line(chan, transcript_path)
            if line is None:
                break

            cmdline = line.strip()

            append_jsonl(jsonl_path, {
                "ts": utc_ts(),
                "type": "command",
                "container_id": container_id,
                "cwd": cwd,
                "cmd": cmdline,
            })

            if cmdline in ("exit", "logout", "quit"):
                chan.send("logout\r\n")
                break

            if cmdline == "":
                send_prompt()
                continue

            # Handle cd ourselves to keep prompt consistent
            if cmdline == "cd" or cmdline.startswith("cd "):
                target = cmdline[2:].strip() if cmdline != "cd" else ""
                if target in ("", "~"):
                    cwd = "/"
                    send_prompt()
                    continue

                test_cmd = f'cd "{cwd}" && cd "{target}" && pwd'
                rc, out, err = docker_exec(container_id, test_cmd, timeout=10)
                if rc == 0 and out.strip():
                    cwd = out.strip().splitlines()[-1]
                else:
                    chan.send(f"bash: cd: {target}: No such file or directory\r\n")
                send_prompt()
                continue

            # Execute command at cwd
            exec_cmd = f'cd "{cwd}" && {cmdline}'

            start = time.time()
            rc, out, err = docker_exec(container_id, exec_cmd, timeout=EXEC_TIMEOUT)
            dur_ms = int((time.time() - start) * 1000)

            append_jsonl(jsonl_path, {
                "ts": utc_ts(),
                "type": "command_result",
                "container_id": container_id,
                "cwd": cwd,
                "cmd": cmdline,
                "rc": rc,
                "duration_ms": dur_ms,
                "stdout_len": len(out),
                "stderr_len": len(err),
            })

            # Send output back (normalize newlines)
            if out:
                chan.send(out.replace("\n", "\r\n"))
                if not out.endswith("\n"):
                    chan.send("\r\n")
            if err:
                chan.send(err.replace("\n", "\r\n"))
                if not err.endswith("\n"):
                    chan.send("\r\n")

            send_prompt()

    except Exception as e:
        append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "error", "where": "session_loop", "error": str(e)})
    finally:
        append_jsonl(jsonl_path, {"ts": utc_ts(), "type": "session_end"})
        try:
            docker_stop(container_id)
        except Exception:
            pass
        try:
            chan.close()
        except Exception:
            pass
        transport.close()
        meta["ts_end"] = utc_ts()
        write_json(meta_path, meta)


# =========================
# Main listener
# =========================
def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    host_key = ensure_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(200)
    sock.settimeout(1.0)  # important so Ctrl+C exits cleanly without a traceback

    print(f"[+] Honeypot SSH manager listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[+] Docker image: {DOCKER_IMAGE}")
    print(f"[+] Docker network: {DOCKER_NETWORK.strip() or 'default'}")
    print(f"[+] Logs directory: {LOG_ROOT.resolve()}")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(target=handle_client, args=(client, addr, host_key), daemon=True)
            t.start()

    except KeyboardInterrupt:
        print("\n[!] Ctrl+C received. Shutting down cleanly...")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[+] Listener stopped.")


if __name__ == "__main__":
    main()
