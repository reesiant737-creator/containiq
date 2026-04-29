from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from ..models.case import Case
from ..services.ai_analyst import AIAnalyst
from ..services.audit_service import audit

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


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
