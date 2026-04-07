from __future__ import annotations

from hids.service import HIDSService

try:
    from flask import Flask, jsonify, request
except ImportError:  # pragma: no cover
    Flask = None
    jsonify = None
    request = None


def create_app(service: HIDSService):
    if Flask is None or jsonify is None or request is None:
        raise RuntimeError("Flask is not installed. Install it to use the API mode.")

    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify(service.get_health())

    @app.get("/summary")
    def summary():
        return jsonify(service.get_summary())

    @app.get("/alerts")
    def alerts():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        return jsonify(service.get_latest_alerts(limit=limit))

    @app.get("/explained-alerts")
    def explained_alerts():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        redact_sensitive = (request.args.get("redact", "") or "").strip().lower() in {"1", "true", "yes"}
        return jsonify(service.get_explained_latest_alerts(limit=limit, redact_sensitive=redact_sensitive))

    @app.get("/history")
    def history():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        return jsonify(service.get_recent_scans(limit=limit))

    @app.get("/alert-history")
    def alert_history():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        risk_label = request.args.get("risk_label") or None
        reason = request.args.get("reason") or None
        return jsonify(service.get_alert_history(limit=limit, risk_label=risk_label, reason=reason))

    @app.get("/explained-alert-history")
    def explained_alert_history():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        risk_label = request.args.get("risk_label") or None
        reason = request.args.get("reason") or None
        redact_sensitive = (request.args.get("redact", "") or "").strip().lower() in {"1", "true", "yes"}
        return jsonify(
            service.get_explained_alert_history(
                limit=limit,
                risk_label=risk_label,
                reason=reason,
                redact_sensitive=redact_sensitive,
            )
        )

    @app.get("/alert-groups")
    def alert_groups():
        raw_limit = request.args.get("limit", "")
        limit = int(raw_limit) if raw_limit.isdigit() else None
        risk_label = request.args.get("risk_label") or None
        reason = request.args.get("reason") or None
        return jsonify(service.get_alert_groups(limit=limit, risk_label=risk_label, reason=reason))

    @app.get("/safe-share-report")
    def safe_share_report():
        return jsonify({"report_markdown": service.create_safe_share_report()})

    return app
