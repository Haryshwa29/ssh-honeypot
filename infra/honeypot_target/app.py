import socket, threading, datetime, os

LOGDIR = "/sessions"
os.makedirs(LOGDIR, exist_ok=True)

BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"

def log(line: str):
    ts = datetime.datetime.utcnow().isoformat()
    with open(os.path.join(LOGDIR, "creds.log"), "a") as f:
        f.write(f"[{ts}] {line}\n")

def handle(c, addr):
    try:
        c.sendall(BANNER)
        c.sendall(b"login: ")
        user = recvline(c)
        c.sendall(b"Password: ")
        pw = recvline(c)
        log(f"{addr[0]} user={user} pass={pw}")
        c.sendall(b"Permission denied, please try again.\r\n")
    except Exception as e:
        log(f"{addr[0]} error={e}")
    finally:
        try: c.close()
        except: pass

def recvline(c):
    data = b""
    while True:
        b = c.recv(1)
        if not b or b in b"\r\n":
            break
        data += b
        if len(data) > 200:
            break
    return data.decode(errors="ignore").strip()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 2222))
    s.listen(100)
    while True:
        c, addr = s.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()

if __name__ == "__main__":
    main()
