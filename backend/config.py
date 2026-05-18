import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///containiq.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = "claude-sonnet-4-6"

    # Threat intel feed settings
    THREAT_FEED_ENABLED = os.environ.get("THREAT_FEED_ENABLED", "true").lower() == "true"
    THREAT_FEED_HOUR = int(os.environ.get("THREAT_FEED_HOUR", "6"))  # 6 AM daily

    # External intel APIs (optional - features degrade gracefully without keys)
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

    # Audit / security
    AUDIT_LOG_IMMUTABLE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Playbook engine
    MAX_BLAST_RADIUS_DEFAULT = 10  # max hosts a playbook can touch without extra approval
    DRY_RUN_DEFAULT = True         # always dry-run first unless overridden

    # Stripe billing
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    STRIPE_PRO_PRICE_ID = os.environ.get("STRIPE_PRO_PRICE_ID", "")  # price_xxx from Stripe dashboard
    STRIPE_PRO_PRICE_DISPLAY = os.environ.get("STRIPE_PRO_PRICE_DISPLAY", "$99/month")


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
