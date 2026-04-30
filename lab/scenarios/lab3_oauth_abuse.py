"""
Lab 3 — OAuth Abuse / Admin Account Takeover
Simulates a Splunk alert chain on a cloud admin compromise.
"""

NAME = "Lab 3: OAuth Abuse / Admin Account Takeover"
STEPS = [
    {
        "delay": 0,
        "description": "Splunk detects suspicious OAuth app granted admin consent",
        "alert": {
            "title": "Suspicious OAuth Application Granted Admin Consent",
            "severity": "high",
            "source": "splunk",
            "user": "itadmin@acmecorp.com",
            "src_ip": "91.108.4.52",
            "domain": "malicious-app.azurewebsites.net",
            "description": "OAuth application 'AcmeHR Sync Tool' granted Global Administrator consent by itadmin@acmecorp.com from IP 91.108.4.52 (Russia). App permissions: Mail.ReadWrite, User.ReadWrite.All, Directory.ReadWrite.All.",
        }
    },
    {
        "delay": 10,
        "description": "New admin account created via compromised OAuth app",
        "alert": {
            "title": "Unauthorized Admin Account Creation via OAuth",
            "severity": "critical",
            "source": "splunk",
            "user": "svc-backup-acme@acmecorp.com",
            "src_ip": "91.108.4.52",
            "description": "New Global Administrator account svc-backup-acme@acmecorp.com created via OAuth app token. Account not created through normal provisioning process. Possible backdoor admin account.",
        }
    },
    {
        "delay": 8,
        "description": "Attacker enumerating Azure AD — reconnaissance in progress",
        "alert": {
            "title": "Azure AD Mass Enumeration — Backdoor Account",
            "severity": "high",
            "source": "splunk",
            "user": "svc-backup-acme@acmecorp.com",
            "src_ip": "91.108.4.52",
            "description": "Backdoor admin account performing mass user enumeration. 847 user objects queried in 2 minutes via MS Graph API. Conditional Access policies being read. Likely preparing for broader attack.",
        }
    },
    {
        "delay": 12,
        "description": "Attacker disabling MFA for target accounts",
        "alert": {
            "title": "MFA Disabled for 12 Accounts — Possible Pre-Attack Staging",
            "severity": "critical",
            "source": "splunk",
            "user": "svc-backup-acme@acmecorp.com",
            "src_ip": "91.108.4.52",
            "description": "MFA authentication methods removed for 12 high-value accounts including CFO, CTO, and 3 IT admins. Performed via MS Graph API using backdoor admin token. Accounts now vulnerable to password spray.",
        }
    },
]
