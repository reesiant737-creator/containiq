"""
Lab 1 — Phishing / Suspicious Inbox Forwarding Rule
Simulates a Microsoft Sentinel alert firing on CEO email compromise.
"""
import time
import requests

NAME = "Lab 1: Phishing / Inbox Forwarding"
STEPS = [
    {
        "delay": 0,
        "description": "Sentinel fires: suspicious inbox forwarding rule detected on CEO account",
        "alert": {
            "title": "Suspicious Inbox Forwarding Rule Detected",
            "severity": "high",
            "source": "microsoft_sentinel",
            "user": "ceo@acmecorp.com",
            "src_ip": "185.220.101.45",
            "domain": "evil-exfil.ru",
            "description": "Inbox forwarding rule created to external address after login from TOR exit node. Rule forwards all mail matching 'invoice' or 'wire' to attacker-controlled domain.",
        }
    },
    {
        "delay": 8,
        "description": "Second alert: same IP attempts access to SharePoint finance folder",
        "alert": {
            "title": "Unauthorized SharePoint Access Attempt — Finance Documents",
            "severity": "high",
            "source": "microsoft_sentinel",
            "user": "ceo@acmecorp.com",
            "src_ip": "185.220.101.45",
            "domain": "acmecorp.sharepoint.com",
            "description": "User accessed /sites/Finance/Confidential from known TOR exit node 185.220.101.45. 47 files viewed in 3 minutes.",
        }
    },
    {
        "delay": 10,
        "description": "Third alert: MFA bypass attempt detected",
        "alert": {
            "title": "MFA Fatigue Attack Detected — CEO Account",
            "severity": "critical",
            "source": "microsoft_sentinel",
            "user": "ceo@acmecorp.com",
            "src_ip": "185.220.101.45",
            "description": "23 MFA push notifications sent to user in 4 minutes. Possible MFA fatigue/push-bombing attack in progress. One approval detected.",
        }
    },
]
