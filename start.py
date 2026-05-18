"""
ThreatCommand — One-click startup script
Run: python start.py

Starts Flask + ngrok, prints the public URL, and keeps everything alive.
Ctrl+C to stop.
"""
import os, sys, time, subprocess, signal, pathlib

ROOT = pathlib.Path(__file__).parent

# ── 1. Kill anything on port 5001 ────────────────────────────────────────────
def kill_port(port=5001):
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                pid = line.strip().split()[-1]
                subprocess.run(["taskkill", "/F", "/PID", pid],
                               capture_output=True)
                print(f"  Killed process {pid} on port {port}")
    except Exception:
        pass

# ── 2. Start Flask ────────────────────────────────────────────────────────────
def start_flask():
    env = os.environ.copy()
    env["FLASK_ENV"] = "production"
    env["PYTHONUNBUFFERED"] = "1"
    log = open(ROOT / "server.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "run.py"],
        env=env, cwd=ROOT,
        stdout=log, stderr=log
    )
    return proc

# ── 3. Wait for Flask to be ready ────────────────────────────────────────────
def wait_for_flask(timeout=30):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://localhost:5001/", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False

# ── 4. Start ngrok ────────────────────────────────────────────────────────────
def start_ngrok():
    ngrok_exe = pathlib.Path.home() / "AppData/Local/ngrok/ngrok.exe"
    if not ngrok_exe.exists():
        # Fallback: try pyngrok
        from pyngrok import ngrok
        tunnel = ngrok.connect(5001, "http")
        return None, tunnel.public_url

    proc = subprocess.Popen(
        [str(ngrok_exe), "http", "5001", "--log=stdout"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    # Get URL from ngrok local API
    import urllib.request, json
    try:
        r = urllib.request.urlopen("http://localhost:4040/api/tunnels", timeout=5)
        data = json.loads(r.read())
        for t in data.get("tunnels", []):
            if "https" in t["public_url"]:
                return proc, t["public_url"]
    except Exception:
        pass
    return proc, None


# ── Main ──────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("  ThreatCommand — Starting up")
print("="*60)

print("\n[1/3] Clearing port 5001...")
kill_port(5001)
time.sleep(1)

print("[2/3] Starting Flask server...")
flask_proc = start_flask()
print("      Waiting for app to be ready...", end="", flush=True)
if wait_for_flask():
    print(" ready!")
else:
    print(" TIMEOUT — check server.log")
    sys.exit(1)

print("[3/3] Starting ngrok tunnel...")
ngrok_proc, public_url = start_ngrok()

print()
print("="*60)
if public_url:
    print(f"  LIVE URL: {public_url}")
    print(f"  Admin login: {public_url}/auth/login")
    print(f"    Email: admin@threatcommand.local")
    print(f"    Pass:  changeme")
else:
    print("  Local:  http://localhost:5001")
    print("  ngrok URL not found — check ngrok dashboard")
print("="*60)
print("\nCtrl+C to stop.\n")

# Keep alive
try:
    while True:
        time.sleep(5)
        # Check Flask is still up
        if flask_proc.poll() is not None:
            print("Flask crashed — restarting...")
            flask_proc = start_flask()
            wait_for_flask()
            print("Flask restarted.")
except KeyboardInterrupt:
    print("\nShutting down...")
    flask_proc.terminate()
    if ngrok_proc:
        ngrok_proc.terminate()
    print("Done.")
