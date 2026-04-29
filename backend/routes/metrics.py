from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
from ..models.case import Case
from ..app import db

metrics_bp = Blueprint("metrics", __name__, url_prefix="/metrics")


def _mttr_hours(case) -> float | None:
    if case.closed_at and case.created_at:
        delta = case.closed_at - case.created_at.replace(tzinfo=timezone.utc if case.created_at.tzinfo is None else None)
        return max(delta.total_seconds() / 3600, 0)
    return None


def _percentile(sorted_values: list, p: float) -> float:
    if not sorted_values:
        return 0
    idx = int(len(sorted_values) * p / 100)
    idx = min(idx, len(sorted_values) - 1)
    return round(sorted_values[idx], 1)


def _compute_metrics(org_id: int) -> dict:
    closed = Case.query.filter_by(org_id=org_id).filter(
        Case.status.in_(["closed", "false_positive"])
    ).filter(Case.closed_at.isnot(None)).all()

    all_hours = []
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "informational": []}

    for c in closed:
        h = _mttr_hours(c)
        if h is not None:
            all_hours.append(h)
            if c.severity in by_severity:
                by_severity[c.severity].append(h)

    all_hours.sort()

    def stats(hours):
        if not hours:
            return {"avg": None, "p50": None, "p95": None, "count": 0}
        avg = round(sum(hours) / len(hours), 1)
        s = sorted(hours)
        return {"avg": avg, "p50": _percentile(s, 50), "p95": _percentile(s, 95), "count": len(hours)}

    severity_stats = {sev: stats(hrs) for sev, hrs in by_severity.items()}

    # 8-week trend: avg MTTR per week
    now = datetime.now(timezone.utc)
    trend = []
    for i in range(7, -1, -1):
        week_end = now - timedelta(weeks=i)
        week_start = week_end - timedelta(weeks=1)
        week_cases = [
            c for c in closed
            if c.closed_at and week_start <= c.closed_at.replace(
                tzinfo=timezone.utc if c.closed_at.tzinfo is None else None
            ) < week_end
        ]
        week_hours = [h for c in week_cases for h in [_mttr_hours(c)] if h is not None]
        trend.append({
            "week": week_end.strftime("W%V %b %d"),
            "avg_mttr": round(sum(week_hours) / len(week_hours), 1) if week_hours else None,
            "count": len(week_hours),
        })

    # Open cases with no activity in 24h (SLA breach candidates)
    yesterday = now - timedelta(hours=24)
    stale_open = Case.query.filter_by(org_id=org_id).filter(
        Case.status.in_(["open", "investigating"]),
        Case.updated_at < yesterday,
    ).count()

    # Fastest and slowest resolutions
    fastest = min(closed, key=lambda c: _mttr_hours(c) or float("inf"), default=None)
    slowest = max(closed, key=lambda c: _mttr_hours(c) or 0, default=None)

    return {
        "overall": stats(all_hours),
        "by_severity": severity_stats,
        "trend": trend,
        "stale_open": stale_open,
        "total_closed": len(closed),
        "fastest": {"id": fastest.id, "title": fastest.title, "hours": round(_mttr_hours(fastest), 1)} if fastest and _mttr_hours(fastest) is not None else None,
        "slowest": {"id": slowest.id, "title": slowest.title, "hours": round(_mttr_hours(slowest), 1)} if slowest and _mttr_hours(slowest) is not None else None,
    }


@metrics_bp.route("/")
@login_required
def mttr_dashboard():
    metrics = _compute_metrics(current_user.org_id)
    return render_template("metrics/dashboard.html", metrics=metrics)


@metrics_bp.route("/api/data")
@login_required
def metrics_api():
    return jsonify(_compute_metrics(current_user.org_id))
