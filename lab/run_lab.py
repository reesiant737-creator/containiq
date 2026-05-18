"""
ThreatCommand Attack Lab Runner
============================
Simulates realistic cyberattack scenarios against your ThreatCommand instance.
Alerts fire in sequence so you can watch cases appear in real time.

Usage:
    python lab/run_lab.py                  # run all 3 labs
    python lab/run_lab.py --lab 1          # run only Lab 1
    python lab/run_lab.py --url http://... # point at hosted instance
    python lab/run_lab.py --key mykey      # use custom API key

Then open: http://localhost:5001/cases
"""
import sys, os, time, argparse
import requests

sys.path.insert(0, os.path.dirname(__file__))
from scenarios import lab1_phishing, lab2_ransomware, lab3_oauth_abuse

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_URL = "http://localhost:5001"
DEFAULT_KEY = "threatcommand-lab-key"

LABS = [lab1_phishing, lab2_ransomware, lab3_oauth_abuse]

# ── Colors ────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"


def banner():
    print(f"""
{BLUE}{BOLD}======================================================
          ThreatCommand Attack Lab Simulator
     Watch real incidents appear as they fire
======================================================{RESET}
""")


def check_server(base_url, api_key):
    try:
        r = requests.get(f"{base_url}/api/v1/health", timeout=5)
        data = r.json()
        if data.get("status") == "ok":
            print(f"{GREEN}[OK] ThreatCommand is running at {base_url}{RESET}")
            return True
    except Exception:
        pass
    print(f"{RED}[FAIL] Cannot reach ThreatCommand at {base_url}{RESET}")
    print(f"  Make sure it's running: {BOLD}python run.py{RESET}")
    return False


def fire_alert(base_url, api_key, alert_data):
    try:
        r = requests.post(
            f"{base_url}/api/v1/alerts",
            json=alert_data,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=10,
        )
        data = r.json()
        if r.status_code == 201:
            return data.get("case_id"), data.get("severity"), data.get("entities_extracted", 0)
        elif r.status_code == 200 and data.get("status") == "duplicate":
            return data.get("case_id"), "duplicate", 0
        else:
            return None, None, 0
    except Exception as e:
        return None, None, 0


def run_scenario(module, base_url, api_key):
    print(f"\n{BOLD}{YELLOW}{'='*54}{RESET}")
    print(f"{BOLD}{YELLOW}  {module.NAME}{RESET}")
    print(f"{BOLD}{YELLOW}{'='*54}{RESET}")

    created_cases = []

    for i, step in enumerate(module.STEPS):
        delay = step["delay"] if i > 0 else 0

        if delay > 0:
            print(f"\n{DIM}  [WAIT]  Waiting {delay}s (attacker moving laterally…){RESET}")
            for remaining in range(delay, 0, -1):
                print(f"\r{DIM}  [WAIT]  Next alert in {remaining}s…{RESET}", end="", flush=True)
                time.sleep(1)
            print()

        print(f"\n{CYAN}  -> {step['description']}{RESET}")

        case_id, severity, entity_count = fire_alert(base_url, api_key, step["alert"])

        if case_id and severity != "duplicate":
            sev_color = RED if severity in ("critical",) else YELLOW if severity == "high" else RESET
            print(f"  {GREEN}[OK] Case #{case_id} created{RESET}  "
                  f"severity={sev_color}{severity.upper()}{RESET}  "
                  f"entities={entity_count}")
            print(f"  {DIM}  -> View: {base_url}/cases/{case_id}{RESET}")
            created_cases.append(case_id)
        elif severity == "duplicate":
            print(f"  {YELLOW}[WARN] Duplicate — Case #{case_id} already exists{RESET}")
        else:
            print(f"  {RED}[FAIL] Alert failed — check server logs{RESET}")

    return created_cases


def print_summary(all_cases, base_url):
    print(f"\n{BOLD}{GREEN}{'='*54}{RESET}")
    print(f"{BOLD}{GREEN}  Lab Complete -- {len(all_cases)} cases created{RESET}")
    print(f"{BOLD}{GREEN}{'='*54}{RESET}")
    print(f"\n  {BOLD}Open ThreatCommand to investigate:{RESET}")
    print(f"  {BLUE}{base_url}/cases{RESET}\n")
    print(f"  {BOLD}Try these next steps in ThreatCommand:{RESET}")
    steps = [
        "Click a CRITICAL case -> AI Analyze",
        "Run a Playbook on the ransomware case",
        "Generate an Incident Report",
        "Check the Metrics dashboard for MTTR",
        "Review the immutable Audit Trail",
    ]
    for s in steps:
        print(f"  {CYAN}  * {s}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(description="ThreatCommand Attack Lab Runner")
    parser.add_argument("--url", default=DEFAULT_URL, help="ThreatCommand base URL")
    parser.add_argument("--key", default=DEFAULT_KEY, help="Ingest API key")
    parser.add_argument("--lab", type=int, choices=[1, 2, 3], help="Run only one lab (1, 2, or 3)")
    args = parser.parse_args()

    banner()

    if not check_server(args.url, args.key):
        sys.exit(1)

    labs_to_run = [LABS[args.lab - 1]] if args.lab else LABS

    print(f"\n{BOLD}Running {len(labs_to_run)} scenario(s)…{RESET}")
    print(f"{DIM}Keep ThreatCommand open at {args.url}/cases to watch cases appear live.{RESET}\n")

    input(f"  {BOLD}Press ENTER to start the lab…{RESET}")

    all_cases = []
    for lab in labs_to_run:
        cases = run_scenario(lab, args.url, args.key)
        all_cases.extend(cases)
        if lab != labs_to_run[-1]:
            print(f"\n{DIM}  Pausing 5s before next scenario…{RESET}")
            time.sleep(5)

    print_summary(all_cases, args.url)


if __name__ == "__main__":
    main()
