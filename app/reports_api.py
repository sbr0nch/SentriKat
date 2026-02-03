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


# ============================================================================
# CISA BOD 22-01 Compliance Report
# ============================================================================

@bp.route('/api/reports/compliance/bod-22-01', methods=['GET'])
@login_required
def generate_compliance_report():
    """
    Generate CISA BOD 22-01 compliance report.

    CISA Binding Operational Directive 22-01 requires federal agencies to:
    1. Remediate known exploited vulnerabilities (KEV) by their due dates
    2. Report compliance status

    This report shows:
    - Total KEV vulnerabilities applicable to your products
    - Remediation status (acknowledged vs pending)
    - Overdue vulnerabilities
    - Compliance percentage
    - Timeline analysis

    Query Parameters:
        format: 'json' or 'pdf' (default: json)
        organization_id: Filter by organization (admin only)
    """
    from app.licensing import requires_professional, get_license
    from app.models import Vulnerability, VulnerabilityMatch, Product, Organization
    from sqlalchemy import func
    from datetime import date, timedelta
    from io import BytesIO

    # Check professional license
    license_info = get_license()
    if not license_info or not license_info.is_professional():
        return jsonify({
            'error': 'CISA BOD 22-01 Compliance Reports require a Professional license',
            'feature': 'compliance_reports'
        }), 403

    output_format = request.args.get('format', 'json').lower()
    org_id = request.args.get('organization_id', type=int)

    user = User.query.get(session.get('user_id'))
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Determine organization scope
    if user.role == 'super_admin' and org_id:
        org_filter = [org_id]
    elif user.role == 'super_admin':
        org_filter = None  # All organizations
    else:
        org_filter = [m.organization_id for m in user.org_memberships.all()]

    today = date.today()

    # Build query for matches
    matches_query = db.session.query(
        VulnerabilityMatch,
        Vulnerability,
        Product
    ).join(
        Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id
    ).join(
        Product, VulnerabilityMatch.product_id == Product.id
    )

    if org_filter:
        matches_query = matches_query.filter(Product.organization_id.in_(org_filter))

    matches = matches_query.all()

    # Calculate metrics
    total_matches = len(matches)
    acknowledged = sum(1 for m, v, p in matches if m.acknowledged)
    pending = total_matches - acknowledged

    # Overdue analysis
    overdue = []
    due_soon = []  # Due within 7 days
    on_track = []

    for match, vuln, product in matches:
        if match.acknowledged:
            continue

        if vuln.due_date:
            if vuln.due_date < today:
                overdue.append({
                    'cve_id': vuln.cve_id,
                    'product': f"{product.vendor} {product.product_name}",
                    'due_date': vuln.due_date.isoformat(),
                    'days_overdue': (today - vuln.due_date).days,
                    'severity': vuln.severity,
                    'known_ransomware': vuln.known_ransomware
                })
            elif vuln.due_date <= today + timedelta(days=7):
                due_soon.append({
                    'cve_id': vuln.cve_id,
                    'product': f"{product.vendor} {product.product_name}",
                    'due_date': vuln.due_date.isoformat(),
                    'days_remaining': (vuln.due_date - today).days,
                    'severity': vuln.severity
                })
            else:
                on_track.append({
                    'cve_id': vuln.cve_id,
                    'product': f"{product.vendor} {product.product_name}",
                    'due_date': vuln.due_date.isoformat()
                })

    # Severity breakdown for pending
    severity_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    for match, vuln, product in matches:
        if not match.acknowledged:
            sev = vuln.severity or 'UNKNOWN'
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    # Ransomware exposure
    ransomware_exposure = sum(
        1 for m, v, p in matches
        if not m.acknowledged and v.known_ransomware
    )

    # Calculate compliance percentage
    compliance_percent = round((acknowledged / total_matches * 100), 1) if total_matches > 0 else 100.0

    # Build report data
    report = {
        'report_type': 'CISA BOD 22-01 Compliance',
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'report_period': {
            'as_of_date': today.isoformat()
        },
        'summary': {
            'total_kev_matches': total_matches,
            'remediated': acknowledged,
            'pending_remediation': pending,
            'compliance_percentage': compliance_percent,
            'overdue_count': len(overdue),
            'due_within_7_days': len(due_soon),
            'ransomware_exposure': ransomware_exposure
        },
        'compliance_status': 'COMPLIANT' if len(overdue) == 0 and compliance_percent >= 95 else 'NON-COMPLIANT',
        'severity_breakdown': severity_breakdown,
        'overdue_vulnerabilities': sorted(overdue, key=lambda x: x['days_overdue'], reverse=True)[:20],
        'due_soon': sorted(due_soon, key=lambda x: x['days_remaining'])[:10],
        'recommendations': []
    }

    # Add recommendations
    if len(overdue) > 0:
        report['recommendations'].append(
            f"URGENT: {len(overdue)} vulnerabilities are past their CISA due date. "
            "Immediate remediation required per BOD 22-01."
        )
    if ransomware_exposure > 0:
        report['recommendations'].append(
            f"HIGH RISK: {ransomware_exposure} unpatched vulnerabilities are known to be "
            "used in ransomware campaigns. Prioritize these for immediate remediation."
        )
    if len(due_soon) > 0:
        report['recommendations'].append(
            f"ATTENTION: {len(due_soon)} vulnerabilities have due dates within the next 7 days."
        )
    if severity_breakdown.get('CRITICAL', 0) > 0:
        report['recommendations'].append(
            f"CRITICAL: {severity_breakdown['CRITICAL']} critical severity vulnerabilities "
            "require immediate attention."
        )

    if output_format == 'json':
        return jsonify(report)

    # Generate PDF
    elif output_format == 'pdf':
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle(
                'Title',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=20
            )
            story.append(Paragraph("CISA BOD 22-01 Compliance Report", title_style))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
            story.append(Spacer(1, 20))

            # Compliance Status
            status_color = colors.green if report['compliance_status'] == 'COMPLIANT' else colors.red
            status_style = ParagraphStyle(
                'Status',
                parent=styles['Heading2'],
                textColor=status_color
            )
            story.append(Paragraph(f"Status: {report['compliance_status']}", status_style))
            story.append(Paragraph(f"Compliance: {compliance_percent}%", styles['Normal']))
            story.append(Spacer(1, 20))

            # Summary table
            summary_data = [
                ['Metric', 'Value'],
                ['Total KEV Matches', str(total_matches)],
                ['Remediated', str(acknowledged)],
                ['Pending', str(pending)],
                ['Overdue', str(len(overdue))],
                ['Due Within 7 Days', str(len(due_soon))],
                ['Ransomware Exposure', str(ransomware_exposure)]
            ]
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))

            # Recommendations
            if report['recommendations']:
                story.append(Paragraph("Recommendations:", styles['Heading2']))
                for rec in report['recommendations']:
                    story.append(Paragraph(f"• {rec}", styles['Normal']))
                story.append(Spacer(1, 20))

            # Overdue vulnerabilities
            if overdue:
                story.append(Paragraph("Overdue Vulnerabilities (Top 10):", styles['Heading2']))
                overdue_data = [['CVE ID', 'Product', 'Days Overdue', 'Severity']]
                for item in overdue[:10]:
                    overdue_data.append([
                        item['cve_id'],
                        item['product'][:30],
                        str(item['days_overdue']),
                        item['severity'] or 'N/A'
                    ])
                overdue_table = Table(overdue_data, colWidths=[1.5*inch, 2.5*inch, 1*inch, 1*inch])
                overdue_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                ]))
                story.append(overdue_table)

            doc.build(story)
            buffer.seek(0)

            filename = f"bod_22_01_compliance_{today.strftime('%Y%m%d')}.pdf"
            return send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )

        except ImportError:
            return jsonify({'error': 'PDF generation requires reportlab library'}), 500
        except Exception as e:
            logger.exception("Error generating compliance PDF")
            return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Invalid format. Use json or pdf'}), 400
