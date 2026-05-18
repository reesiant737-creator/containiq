import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_cors import CORS
from .config import config_map

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def create_app(env=None):
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )

    env = env or os.environ.get("FLASK_ENV", "default")
    app.config.from_object(config_map[env])

    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    from .models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from .routes.landing import landing_bp
    from .routes.billing import billing_bp
    from .routes.auth import auth_bp
    from .routes.cases import cases_bp
    from .routes.playbooks import playbooks_bp
    from .routes.reports import reports_bp
    from .routes.ai import ai_bp
    from .routes.threat_feed import threat_feed_bp
    from .routes.patches import patches_bp
    from .routes.ingest import ingest_bp
    from .routes.metrics import metrics_bp

    app.register_blueprint(landing_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(playbooks_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(threat_feed_bp)
    app.register_blueprint(patches_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(metrics_bp)

    # Start the daily threat intel scheduler
    if app.config.get("THREAT_FEED_ENABLED"):
        from .services.threat_intel import start_scheduler
        start_scheduler(app)

    with app.app_context():
        db.create_all()
        _migrate_billing_columns()
        _seed_defaults()
        if os.environ.get("DEMO_MODE", "").lower() == "true":
            _seed_demo_if_empty()

    # CLI commands
    @app.cli.command("seed-demo")
    def seed_demo_cmd():
        """Seed realistic demo data for screenshots and portfolio demos."""
        with app.app_context():
            from .services.demo_seeder import seed_demo_data
            seed_demo_data()

    @app.cli.command("generate-patch")
    def generate_patch_cmd():
        """Manually trigger weekly patch generation for all orgs."""
        with app.app_context():
            from .models.org import Org
            from .services.patch_manager import PatchManager
            for org in Org.query.all():
                mgr = PatchManager(org.id)
                patch = mgr.generate_weekly_patch()
                print(f"Org {org.id}: patch {patch.version} — {patch.status}")

    return app


def _seed_demo_if_empty():
    from .models.case import Case
    if Case.query.count() == 0:
        try:
            from .services.demo_seeder import seed_demo_data
            seed_demo_data()
            print("[DEMO] Auto-seeded demo data on first boot.")
        except Exception as e:
            print(f"[DEMO] Auto-seed failed: {e}")


def _migrate_billing_columns():
    """Safely add billing columns to existing orgs table — idempotent."""
    from sqlalchemy import text
    cols = {
        "plan":                    "VARCHAR(32) DEFAULT 'free'",
        "plan_status":             "VARCHAR(32) DEFAULT 'active'",
        "stripe_customer_id":      "VARCHAR(128)",
        "stripe_subscription_id":  "VARCHAR(128)",
        "plan_expires_at":         "DATETIME",
    }
    with db.engine.connect() as conn:
        existing = [row[1] for row in conn.execute(text("PRAGMA table_info(orgs)"))]
        for col, typedef in cols.items():
            if col not in existing:
                conn.execute(text(f"ALTER TABLE orgs ADD COLUMN {col} {typedef}"))
        conn.commit()


def _seed_defaults():
    from .models.org import Org
    from .models.user import User
    from .models.playbook import Playbook
    import json, pathlib

    if not Org.query.first():
        org = Org(name="Default Org", slug="default")
        db.session.add(org)
        db.session.flush()

        admin = User(
            org_id=org.id,
            email="admin@threatcommand.local",
            role="admin",
            display_name="Admin",
        )
        admin.set_password("changeme")
        db.session.add(admin)

        # Load playbooks from content/
        content_root = pathlib.Path(__file__).parent.parent / "content" / "playbooks"
        for pb_file in sorted(content_root.rglob("*.json")):
            with open(pb_file) as f:
                data = json.load(f)
            pack = pb_file.parent.name
            pb = Playbook(
                org_id=org.id,
                name=data["name"],
                description=data["description"],
                pack=pack,
                version="1.0",
                content=data,
                status="active",
                created_by=1,
            )
            db.session.add(pb)

        db.session.commit()
