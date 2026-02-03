"""
API endpoints for scheduled reports management.
"""

from flask import Blueprint, request, jsonify, session, send_file
from app.models import ScheduledReport, Organization, User
from app import db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('reports_api', __name__)


def login_required(f):
    """Decorator to require login for API endpoints"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin access"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        user = User.query.get(session['user_id'])
        if not user or user.role not in ['org_admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return decorated_function


@bp.route('/api/reports/scheduled', methods=['GET'])
@login_required
def get_scheduled_reports():
    """Get all scheduled reports for the current organization"""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization not found'}), 400

    reports = ScheduledReport.query.filter_by(organization_id=org_id).all()
    return jsonify([r.to_dict() for r in reports])


@bp.route('/api/reports/scheduled/<int:report_id>', methods=['GET'])
@login_required
def get_scheduled_report(report_id):
    """Get a specific scheduled report"""
    org_id = session.get('organization_id')
    report = ScheduledReport.query.filter_by(id=report_id, organization_id=org_id).first()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    return jsonify(report.to_dict())


@bp.route('/api/reports/scheduled', methods=['POST'])
@admin_required
def create_scheduled_report():
    """Create a new scheduled report"""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization not found'}), 400

    data = request.get_json()

    # Validate required fields
    if not data.get('name'):
        return jsonify({'error': 'Report name is required'}), 400
    if not data.get('recipients') and not data.get('send_to_managers') and not data.get('send_to_admins'):
        return jsonify({'error': 'At least one recipient method is required'}), 400

    # Validate frequency
    frequency = data.get('frequency', 'weekly')
    if frequency not in ScheduledReport.FREQUENCY_CHOICES:
        return jsonify({'error': f'Invalid frequency. Must be one of: {ScheduledReport.FREQUENCY_CHOICES}'}), 400

    # Validate day_of_week for weekly
    if frequency == 'weekly':
        day_of_week = data.get('day_of_week', 0)
        if not isinstance(day_of_week, int) or day_of_week < 0 or day_of_week > 6:
            return jsonify({'error': 'day_of_week must be 0-6 for weekly reports'}), 400
    else:
        day_of_week = None

    # Validate day_of_month for monthly
    if frequency == 'monthly':
        day_of_month = data.get('day_of_month', 1)
        if not isinstance(day_of_month, int) or day_of_month < 1 or day_of_month > 28:
            return jsonify({'error': 'day_of_month must be 1-28 for monthly reports'}), 400
    else:
        day_of_month = None

    # Validate time_of_day
    time_of_day = data.get('time_of_day', '09:00')
    try:
        datetime.strptime(time_of_day, '%H:%M')
    except ValueError:
        return jsonify({'error': 'time_of_day must be in HH:MM format'}), 400

    # Validate report_type
    report_type = data.get('report_type', 'summary')
    if report_type not in ScheduledReport.REPORT_TYPE_CHOICES:
        return jsonify({'error': f'Invalid report_type. Must be one of: {ScheduledReport.REPORT_TYPE_CHOICES}'}), 400

    try:
        report = ScheduledReport(
            organization_id=org_id,
            name=data['name'],
            description=data.get('description'),
            frequency=frequency,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            time_of_day=time_of_day,
            report_type=report_type,
            include_acknowledged=data.get('include_acknowledged', True),
            include_pending=data.get('include_pending', True),
            include_trends=data.get('include_trends', True),
            priority_filter=data.get('priority_filter'),
            recipients=data.get('recipients', ''),
            send_to_managers=data.get('send_to_managers', False),
            send_to_admins=data.get('send_to_admins', True),
            enabled=data.get('enabled', True),
            created_by=session.get('user_id')
        )

        # Calculate next run time
        report.calculate_next_run()

        db.session.add(report)
        db.session.commit()

        logger.info(f"Created scheduled report '{report.name}' for org {org_id}")

        return jsonify({
            'success': True,
            'message': 'Scheduled report created',
            'report': report.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.exception("Error creating scheduled report")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/scheduled/<int:report_id>', methods=['PUT'])
@admin_required
def update_scheduled_report(report_id):
    """Update a scheduled report"""
    org_id = session.get('organization_id')
    report = ScheduledReport.query.filter_by(id=report_id, organization_id=org_id).first()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    data = request.get_json()

    try:
        # Update fields
        if 'name' in data:
            report.name = data['name']
        if 'description' in data:
            report.description = data['description']
        if 'frequency' in data:
            if data['frequency'] not in ScheduledReport.FREQUENCY_CHOICES:
                return jsonify({'error': f'Invalid frequency'}), 400
            report.frequency = data['frequency']
        if 'day_of_week' in data:
            report.day_of_week = data['day_of_week']
        if 'day_of_month' in data:
            report.day_of_month = data['day_of_month']
        if 'time_of_day' in data:
            try:
                datetime.strptime(data['time_of_day'], '%H:%M')
                report.time_of_day = data['time_of_day']
            except ValueError:
                return jsonify({'error': 'time_of_day must be in HH:MM format'}), 400
        if 'report_type' in data:
            if data['report_type'] not in ScheduledReport.REPORT_TYPE_CHOICES:
                return jsonify({'error': f'Invalid report_type'}), 400
            report.report_type = data['report_type']
        if 'include_acknowledged' in data:
            report.include_acknowledged = data['include_acknowledged']
        if 'include_pending' in data:
            report.include_pending = data['include_pending']
        if 'include_trends' in data:
            report.include_trends = data['include_trends']
        if 'priority_filter' in data:
            report.priority_filter = data['priority_filter']
        if 'recipients' in data:
            report.recipients = data['recipients']
        if 'send_to_managers' in data:
            report.send_to_managers = data['send_to_managers']
        if 'send_to_admins' in data:
            report.send_to_admins = data['send_to_admins']
        if 'enabled' in data:
            report.enabled = data['enabled']

        # Recalculate next run
        report.calculate_next_run()

        db.session.commit()

        logger.info(f"Updated scheduled report '{report.name}'")

        return jsonify({
            'success': True,
            'message': 'Scheduled report updated',
            'report': report.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Error updating scheduled report")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/scheduled/<int:report_id>', methods=['DELETE'])
@admin_required
def delete_scheduled_report(report_id):
    """Delete a scheduled report"""
    org_id = session.get('organization_id')
    report = ScheduledReport.query.filter_by(id=report_id, organization_id=org_id).first()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    try:
        name = report.name
        db.session.delete(report)
        db.session.commit()

        logger.info(f"Deleted scheduled report '{name}'")

        return jsonify({
            'success': True,
            'message': 'Scheduled report deleted'
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting scheduled report")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/scheduled/<int:report_id>/toggle', methods=['POST'])
@admin_required
def toggle_scheduled_report(report_id):
    """Toggle enabled/disabled status of a scheduled report"""
    org_id = session.get('organization_id')
    report = ScheduledReport.query.filter_by(id=report_id, organization_id=org_id).first()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    try:
        report.enabled = not report.enabled
        if report.enabled:
            report.calculate_next_run()
        db.session.commit()

        status = 'enabled' if report.enabled else 'disabled'
        logger.info(f"Scheduled report '{report.name}' {status}")

        return jsonify({
            'success': True,
            'message': f'Scheduled report {status}',
            'enabled': report.enabled,
            'next_run': report.next_run.isoformat() if report.next_run else None
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Error toggling scheduled report")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/scheduled/<int:report_id>/send-now', methods=['POST'])
@admin_required
def send_report_now(report_id):
    """Manually trigger a scheduled report to send immediately"""
    org_id = session.get('organization_id')
    report = ScheduledReport.query.filter_by(id=report_id, organization_id=org_id).first()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    try:
        from app.reports import VulnerabilityReportGenerator
        from app.email_alerts import EmailAlertManager

        # Generate the report
        generator = VulnerabilityReportGenerator(organization_id=org_id)

        if report.report_type == 'summary':
            pdf_buffer = generator.generate_monthly_report()
        else:
            # Full report with current date range
            from datetime import datetime, timedelta
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            pdf_buffer = generator.generate_custom_report(
                start_date=start_date,
                end_date=end_date,
                include_acknowledged=report.include_acknowledged,
                include_pending=report.include_pending
            )

        # Get recipients
        recipients = report.get_recipient_emails()
        if not recipients:
            return jsonify({
                'success': False,
                'message': 'No recipients configured for this report'
            }), 400

        # Send email with attachment
        org = Organization.query.get(org_id)
        org_name = org.display_name if org else 'Unknown'

        result = EmailAlertManager.send_scheduled_report(
            recipients=recipients,
            report_name=report.name,
            org_name=org_name,
            pdf_buffer=pdf_buffer
        )

        # Update report status
        report.last_sent = datetime.utcnow()
        report.last_status = 'success' if result.get('success') else 'failed'
        db.session.commit()

        if result.get('success'):
            return jsonify({
                'success': True,
                'message': f'Report sent to {len(recipients)} recipient(s)',
                'recipients': recipients
            })
        else:
            return jsonify({
                'success': False,
                'message': result.get('error', 'Failed to send report')
            }), 500

    except Exception as e:
        logger.exception("Error sending report manually")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/download', methods=['POST'])
@login_required
def download_report():
    """Generate and download a report immediately"""
    from app.reports import VulnerabilityReportGenerator
    from datetime import datetime, timedelta

    org_id = session.get('organization_id')
    data = request.get_json() or {}

    report_type = data.get('report_type', 'monthly')
    include_acknowledged = data.get('include_acknowledged', True)
    include_pending = data.get('include_pending', True)

    try:
        generator = VulnerabilityReportGenerator(organization_id=org_id)

        if report_type == 'monthly':
            year = data.get('year')
            month = data.get('month')
            pdf_buffer = generator.generate_monthly_report(year=year, month=month)
            filename = f"vulnerability_report_{datetime.now().strftime('%Y_%m')}.pdf"

        elif report_type == 'custom':
            start_date = datetime.fromisoformat(data['start_date'])
            end_date = datetime.fromisoformat(data['end_date'])
            pdf_buffer = generator.generate_custom_report(
                start_date=start_date,
                end_date=end_date,
                include_acknowledged=include_acknowledged,
                include_pending=include_pending
            )
            filename = f"vulnerability_report_{start_date.strftime('%Y%m%d')}-{end_date.strftime('%Y%m%d')}.pdf"

        elif report_type == 'selected':
            match_ids = data.get('match_ids', [])
            if not match_ids:
                return jsonify({'error': 'No vulnerabilities selected'}), 400
            pdf_buffer = generator.generate_selected_report(match_ids)
            filename = f"selected_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        else:
            # Default to last 30 days
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            pdf_buffer = generator.generate_custom_report(
                start_date=start_date,
                end_date=end_date,
                include_acknowledged=include_acknowledged,
                include_pending=include_pending
            )
            filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d')}.pdf"

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        logger.exception("Error generating report")
        return jsonify({'error': str(e)}), 500
