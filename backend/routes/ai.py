from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from ..models.case import Case
from ..services.ai_analyst import AIAnalyst
from ..services.audit_service import audit

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


def _get_client():
    """Return an Anthropic client if ANTHROPIC_API_KEY is configured, else None."""
    import anthropic
    key = current_app.config.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    return anthropic.Anthropic(api_key=key)


@ai_bp.route("/analyze/<int:case_id>", methods=["POST"])
@login_required
def analyze_case(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    analyst = AIAnalyst()
    result = analyst.analyze_case(case)
    audit("ai.case_analysis", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="case", resource_id=str(case_id), case_id=case_id)
    return jsonify(result)


@ai_bp.route("/hunt-queries/<int:case_id>", methods=["POST"])
@login_required
def hunt_queries(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    question = request.json.get("question", "")
    siem = request.json.get("siem", "splunk")
    analyst = AIAnalyst()
    result = analyst.generate_hunt_queries(case, question, siem)
    audit("ai.hunt_queries", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="case", resource_id=str(case_id), case_id=case_id,
          payload={"siem": siem, "question": question[:100]})
    return jsonify(result)


@ai_bp.route("/ask/<int:case_id>", methods=["POST"])
@login_required
def ask_analyst(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    question = request.json.get("question", "").strip()
    if not question:
        return jsonify({"error": "question required"}), 400
    analyst = AIAnalyst()
    result = analyst.ask(case, question)
    return jsonify(result)


@ai_bp.route("/triage-rationale/<int:case_id>", methods=["POST"])
@login_required
def triage_rationale(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    analyst = AIAnalyst()
    result = analyst.explain_severity(case)
    return jsonify(result)


@ai_bp.route("/playbook-recommend/<int:case_id>", methods=["POST"])
@login_required
def recommend_playbook(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    from ..models.playbook import Playbook
    playbooks = Playbook.query.filter_by(org_id=current_user.org_id, status="active").all()
    analyst = AIAnalyst()
    result = analyst.recommend_playbook(case, playbooks)
    return jsonify(result)


@ai_bp.route("/natural-search", methods=["POST"])
@login_required
def natural_search():
    """
    Natural language case/threat search.
    POST body: {"query": "show me all phishing cases from last week with critical severity"}
    Returns structured results + AI explanation.
    """
    from ..models.case import Case, Entity
    from ..models.threat import ThreatFeed
    from datetime import datetime, timezone, timedelta
    import json

    data = request.get_json() or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400

    client = _get_client()
    if not client:
        return jsonify({"error": "AI not configured"}), 503

    # Ask Claude to parse the query into structured filters
    parse_prompt = f"""You are a security analyst assistant. Parse this natural language search query into structured filters for a SOC case database.

Query: "{query}"

Return ONLY valid JSON (no markdown, no explanation) with these optional fields:
{{
  "severity": ["critical","high","medium","low"] or null,
  "status": ["open","investigating","contained","closed","false_positive"] or null,
  "source": string or null,
  "days_back": integer (how many days to look back, default 30) or null,
  "entity_value": string (IP, domain, hash to search for) or null,
  "title_contains": string or null,
  "explanation": "one sentence explaining what you're searching for"
}}

Examples:
- "critical cases from last week" → {{"severity":["critical"],"days_back":7,"explanation":"Critical severity cases from the past 7 days"}}
- "phishing cases" → {{"title_contains":"phish","explanation":"Cases related to phishing"}}
- "open cases with IP 1.2.3.4" → {{"status":["open","investigating"],"entity_value":"1.2.3.4","explanation":"Open cases involving IP address 1.2.3.4"}}"""

    try:
        resp = client.messages.create(
            model=current_app.config.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            max_tokens=512,
            messages=[{"role": "user", "content": parse_prompt}]
        )
        filters = json.loads(resp.content[0].text.strip())
    except Exception as e:
        filters = {"explanation": f"Searching for: {query}", "days_back": 30}

    # Build SQLAlchemy query
    q = Case.query.filter_by(org_id=current_user.org_id)

    if filters.get("severity"):
        q = q.filter(Case.severity.in_(filters["severity"]))
    if filters.get("status"):
        q = q.filter(Case.status.in_(filters["status"]))
    if filters.get("source"):
        q = q.filter(Case.source.ilike(f"%{filters['source']}%"))
    if filters.get("title_contains"):
        q = q.filter(Case.title.ilike(f"%{filters['title_contains']}%"))
    if filters.get("days_back"):
        cutoff = datetime.now(timezone.utc) - timedelta(days=filters["days_back"])
        q = q.filter(Case.created_at >= cutoff)

    # Entity search
    entity_case_ids = []
    if filters.get("entity_value"):
        entities = Entity.query.filter(
            Entity.value.ilike(f"%{filters['entity_value']}%")
        ).all()
        entity_case_ids = [e.case_id for e in entities]
        if entity_case_ids:
            q = q.filter(Case.id.in_(entity_case_ids))
        else:
            # No matching entities found
            return jsonify({
                "results": [],
                "total": 0,
                "explanation": filters.get("explanation", query),
                "filters_applied": filters,
                "message": f"No cases found with entity matching '{filters['entity_value']}'"
            })

    cases = q.order_by(Case.created_at.desc()).limit(20).all()

    return jsonify({
        "results": [{
            "id": c.id,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "source": c.source,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "url": f"/cases/{c.id}",
            "entity_count": len(c.entities) if c.entities else 0,
        } for c in cases],
        "total": len(cases),
        "explanation": filters.get("explanation", query),
        "filters_applied": {k: v for k, v in filters.items() if k != "explanation" and v is not None},
    })
