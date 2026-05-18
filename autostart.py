"""
ThreatCommand — Windows autostart setup.
Run once as admin: python autostart.py
Creates Task Scheduler tasks so Flask + tunnel start on login.
"""
import subprocess, sys, pathlib, os

ROOT = pathlib.Path(__file__).parent.resolve()
PYTHON = sys.executable

# ─── Task 1: Flask server ────────────────────────────────────────────────────
FLASK_TASK = "ThreatCommand-Flask"
flask_cmd = f'"{PYTHON}" "{ROOT / "run.py"}"'

flask_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{PYTHON}</Command>
      <Arguments>"{ROOT / "run.py"}"</Arguments>
      <WorkingDirectory>{ROOT}</WorkingDirectory>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <Hidden>true</Hidden>
  </Settings>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>"""

# ─── Task 2: Tunnel ────────────────────────────────────────────────────────
TUNNEL_TASK = "ThreatCommand-Tunnel"
NGROK = pathlib.Path.home() / "AppData/Local/ngrok/ngrok.exe"

tunnel_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5S</Delay>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{NGROK}</Command>
      <Arguments>http 5001</Arguments>
      <WorkingDirectory>{ROOT}</WorkingDirectory>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT30S</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <Hidden>true</Hidden>
  </Settings>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>"""


def register_task(name, xml):
    xml_path = pathlib.Path(os.environ["TEMP"]) / f"{name}.xml"
    xml_path.write_text(xml, encoding="utf-16")
    # Delete if exists
    subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                   capture_output=True)
    result = subprocess.run(
        ["schtasks", "/Create", "/TN", name, "/XML", str(xml_path)],
        capture_output=True, text=True
    )
    xml_path.unlink(missing_ok=True)
    if result.returncode == 0:
        print(f"  OK {name} registered")
    else:
        print(f"  FAIL {name}: {result.stderr.strip()}")
    return result.returncode == 0


if __name__ == "__main__":
    print("\nRegistering ThreatCommand startup tasks...\n")
    register_task(FLASK_TASK, flask_xml)
    register_task(TUNNEL_TASK, tunnel_xml)
    print("\nDone. ThreatCommand will start automatically on next login.")
    print("To start now without rebooting, run: python start.py")
