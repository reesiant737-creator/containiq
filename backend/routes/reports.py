from flask import Blueprint, render_template, request, jsonify, send_file, flash
from flask_login import login_required, current_user
from ..models.case import Case
from ..services.report_generator import ReportGenerator
from ..services.nist_mapper import NistMapper
from ..services.audit_service import audit
import io

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def reports_home():
    cases = Case.query.filter_by(org_id=current_user.org_id).order_by(
        Case.created_at.desc()
    ).limit(50).all()
    return render_template("reports/generate.html", cases=cases)


@reports_bp.route("/generate/<int:case_id>", methods=["POST"])
@login_required
def generate_report(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    report_type = request.form.get("report_type", "incident")

    gen = ReportGenerator(case, current_user)

    if report_type == "incident":
        content = gen.incident_report()
        audit("report.incident_generated", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="case", resource_id=str(case_id), case_id=case_id)
        return jsonify({"type": "incident", "content": content})

    elif report_type == "audit_packet":
        content = gen.audit_packet()
        audit("report.audit_packet_generated", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="case", resource_id=str(case_id), case_id=case_id)
        return jsonify({"type": "audit_packet", "content": content})

    elif report_type == "nist":
        mapper = NistMapper(case)
        mapping = mapper.generate_mapping()
        audit("report.nist_mapping_generated", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="case", resource_id=str(case_id), case_id=case_id)
        return jsonify({"type": "nist", "content": mapping})

    elif report_type == "pdf":
        pdf_bytes = gen.export_pdf()
        audit("report.pdf_exported", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="case", resource_id=str(case_id), case_id=case_id)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"threatcommand-case-{case_id}.pdf",
        )

    return jsonify({"error": "unknown report type"}), 400


@reports_bp.route("/nist-framework")
@login_required
def nist_framework():
    """NIST CSF coverage overview across all cases."""
    cases = Case.query.filter_by(org_id=current_user.org_id).all()
    mapper = NistMapper(None)
    coverage = mapper.org_coverage(cases)
    return render_template("reports/nist_framework.html", coverage=coverage)
