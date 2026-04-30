"""
Lab 2 — Ransomware Execution + Lateral Movement
Simulates a CrowdStrike detection escalating across the network.
"""

NAME = "Lab 2: Ransomware Execution + Lateral Movement"
STEPS = [
    {
        "delay": 0,
        "description": "CrowdStrike detects ransomware execution on workstation",
        "alert": {
            "title": "Ransomware Execution Detected — DESKTOP-4A2X",
            "severity": "critical",
            "source": "crowdstrike",
            "host": "DESKTOP-4A2X",
            "user": "jsmith",
            "src_ip": "10.0.1.44",
            "sha256": "4d1740485713a2ab3a4f5822a01f645ff13dca5e87e4c0f8bb9e0c43b5e98a12",
            "description": "LockBit 3.0 variant detected. File encryption started in C:\\Users\\jsmith\\Documents. Process: svchost32.exe (PID 4821). 847 files encrypted in 90 seconds.",
        }
    },
    {
        "delay": 12,
        "description": "Lateral movement detected — ransomware spreading to file server",
        "alert": {
            "title": "Lateral Movement — SMB Propagation from DESKTOP-4A2X",
            "severity": "critical",
            "source": "crowdstrike",
            "host": "FILESERVER-01",
            "src_ip": "10.0.1.44",
            "dest_ip": "10.0.1.10",
            "user": "jsmith",
            "description": "Ransomware propagating via SMB from DESKTOP-4A2X (10.0.1.44) to FILESERVER-01 (10.0.1.10). Network share \\\\FILESERVER-01\\Finance targeted. 2,341 files at risk.",
        }
    },
    {
        "delay": 10,
        "description": "C2 beacon detected — ransomware phoning home",
        "alert": {
            "title": "C2 Communication Detected — LockBit Beacon",
            "severity": "critical",
            "source": "crowdstrike",
            "host": "DESKTOP-4A2X",
            "src_ip": "10.0.1.44",
            "domain": "lockbit-c2-panel.onion.ws",
            "description": "Outbound C2 beacon to known LockBit infrastructure. Exfiltration of 1.2GB detected before encryption. Ransom note dropped: README-HOW-TO-DECRYPT.txt",
        }
    },
    {
        "delay": 8,
        "description": "Second workstation hit — ransomware spreading",
        "alert": {
            "title": "Ransomware Execution Detected — DESKTOP-7B9Z",
            "severity": "critical",
            "source": "crowdstrike",
            "host": "DESKTOP-7B9Z",
            "src_ip": "10.0.1.67",
            "sha256": "4d1740485713a2ab3a4f5822a01f645ff13dca5e87e4c0f8bb9e0c43b5e98a12",
            "description": "Same ransomware variant now executing on DESKTOP-7B9Z. Propagated via compromised admin credentials from DESKTOP-4A2X. Network isolation required immediately.",
        }
    },
]
