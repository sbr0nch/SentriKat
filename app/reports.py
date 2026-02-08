"""
PDF Report Generation for SentriKat
Generates vulnerability reports in PDF format
"""

from io import BytesIO
from datetime import datetime, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from app.models import VulnerabilityMatch, Product, Vulnerability, Organization
from app import db
from sqlalchemy import func
from sqlalchemy.orm import selectinload


class VulnerabilityReportGenerator:
    """Generates PDF vulnerability reports"""

    # Color scheme
    COLORS = {
        'primary': colors.HexColor('#1e40af'),
        'primary_light': colors.HexColor('#3b82f6'),
        'critical': colors.HexColor('#dc2626'),
        'high': colors.HexColor('#ea580c'),
        'medium': colors.HexColor('#ca8a04'),
        'low': colors.HexColor('#059669'),
        'success': colors.HexColor('#10b981'),
        'gray': colors.HexColor('#6b7280'),
        'light_gray': colors.HexColor('#f3f4f6'),
        'white': colors.white,
        'black': colors.HexColor('#111827'),
    }

    def __init__(self, organization_id=None):
        self.organization_id = organization_id
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.COLORS['primary'],
            spaceAfter=20,
            alignment=TA_CENTER,
        ))

        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.COLORS['primary'],
            spaceBefore=20,
            spaceAfter=10,
            borderPadding=5,
        ))

        # Subsection header
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=self.COLORS['gray'],
            spaceBefore=15,
            spaceAfter=8,
        ))

        # Normal text
        self.styles.add(ParagraphStyle(
            name='ReportBody',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['black'],
            spaceAfter=6,
        ))

        # Small text
        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=self.COLORS['gray'],
        ))

        # Center aligned
        self.styles.add(ParagraphStyle(
            name='CenterText',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
        ))

    def _get_priority_color(self, priority):
        """Get color for priority level"""
        priority_colors = {
            'critical': self.COLORS['critical'],
            'high': self.COLORS['high'],
            'medium': self.COLORS['medium'],
            'low': self.COLORS['low'],
        }
        return priority_colors.get(priority.lower() if priority else 'low', self.COLORS['gray'])

    def _get_stats(self, start_date, end_date):
        """Get vulnerability statistics for the date range"""
        # Build base query without eager loading to avoid column mapping issues
        query = db.session.query(VulnerabilityMatch)

        if self.organization_id:
            # Filter by organization using scalar_subquery for proper IN() usage
            from app.models import product_organizations
            org_product_ids = db.session.query(product_organizations.c.product_id).filter(
                product_organizations.c.organization_id == self.organization_id
            ).scalar_subquery()
            query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))

        all_matches = query.all()

        stats = {
            'total': len(all_matches),
            'acknowledged': sum(1 for m in all_matches if m.acknowledged),
            'unacknowledged': sum(1 for m in all_matches if not m.acknowledged),
            'critical': sum(1 for m in all_matches if m.calculate_effective_priority() == 'critical'),
            'high': sum(1 for m in all_matches if m.calculate_effective_priority() == 'high'),
            'medium': sum(1 for m in all_matches if m.calculate_effective_priority() == 'medium'),
            'low': sum(1 for m in all_matches if m.calculate_effective_priority() == 'low'),
            'ransomware': sum(1 for m in all_matches if m.vulnerability and m.vulnerability.known_ransomware),
        }

        return stats, all_matches

    def _create_header(self, elements, title, subtitle):
        """Create report header"""
        # Title
        elements.append(Paragraph(title, self.styles['ReportTitle']))
        elements.append(Paragraph(subtitle, self.styles['CenterText']))
        elements.append(Spacer(1, 20))

    def _create_summary_table(self, elements, stats):
        """Create summary statistics table"""
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))

        # Summary data
        summary_data = [
            ['Total Vulnerabilities', str(stats['total'])],
            ['Acknowledged', str(stats['acknowledged'])],
            ['Pending Action', str(stats['unacknowledged'])],
            ['Known Ransomware', str(stats['ransomware'])],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_gray']),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['black']),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['gray']),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

    def _create_priority_breakdown(self, elements, stats):
        """Create priority breakdown table"""
        elements.append(Paragraph("Priority Breakdown", self.styles['SectionHeader']))

        priority_data = [
            ['Priority', 'Count', 'Percentage'],
            ['Critical', str(stats['critical']), f"{(stats['critical']/max(stats['total'],1)*100):.1f}%"],
            ['High', str(stats['high']), f"{(stats['high']/max(stats['total'],1)*100):.1f}%"],
            ['Medium', str(stats['medium']), f"{(stats['medium']/max(stats['total'],1)*100):.1f}%"],
            ['Low', str(stats['low']), f"{(stats['low']/max(stats['total'],1)*100):.1f}%"],
        ]

        priority_table = Table(priority_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        priority_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['white']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            # Data rows
            ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['white']),
            ('TEXTCOLOR', (0, 1), (-1, -1), self.COLORS['black']),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['gray']),
            # Priority colors
            ('TEXTCOLOR', (0, 1), (0, 1), self.COLORS['critical']),
            ('TEXTCOLOR', (0, 2), (0, 2), self.COLORS['high']),
            ('TEXTCOLOR', (0, 3), (0, 3), self.COLORS['medium']),
            ('TEXTCOLOR', (0, 4), (0, 4), self.COLORS['low']),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        elements.append(priority_table)
        elements.append(Spacer(1, 20))

    def _create_vulnerability_list(self, elements, matches, title, max_items=50):
        """Create a table of vulnerabilities"""
        if not matches:
            elements.append(Paragraph(f"No {title.lower()} found.", self.styles['ReportBody']))
            return

        elements.append(Paragraph(title, self.styles['SectionHeader']))

        # Limit items
        display_matches = matches[:max_items]
        if len(matches) > max_items:
            elements.append(Paragraph(
                f"Showing {max_items} of {len(matches)} items",
                self.styles['SmallText']
            ))

        # Table header
        table_data = [['CVE ID', 'Product', 'Priority', 'Severity', 'Status']]

        for match in display_matches:
            vuln = match.vulnerability
            product = match.product

            status = 'Acknowledged' if match.acknowledged else 'Pending'
            priority = match.calculate_effective_priority() or 'N/A'
            severity = vuln.severity if vuln else 'N/A'

            table_data.append([
                vuln.cve_id if vuln else 'N/A',
                f"{product.vendor} {product.product_name}"[:30] if product else 'N/A',
                priority.upper() if priority else 'N/A',
                severity or 'N/A',
                status,
            ])

        vuln_table = Table(table_data, colWidths=[1.2*inch, 2*inch, 0.8*inch, 0.8*inch, 1*inch])

        # Build style
        style_commands = [
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['white']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            # Data
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['gray']),
        ]

        # Alternate row colors
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                style_commands.append(('BACKGROUND', (0, i), (-1, i), self.COLORS['light_gray']))
            else:
                style_commands.append(('BACKGROUND', (0, i), (-1, i), self.COLORS['white']))

            # Priority colors
            match = display_matches[i-1]
            priority = match.calculate_effective_priority()
            if priority:
                color = self._get_priority_color(priority)
                style_commands.append(('TEXTCOLOR', (2, i), (2, i), color))
                style_commands.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))

            # Status colors
            if match.acknowledged:
                style_commands.append(('TEXTCOLOR', (4, i), (4, i), self.COLORS['success']))
            else:
                style_commands.append(('TEXTCOLOR', (4, i), (4, i), self.COLORS['high']))

        vuln_table.setStyle(TableStyle(style_commands))
        elements.append(vuln_table)
        elements.append(Spacer(1, 15))

    def _create_footer(self, elements, generated_at):
        """Create report footer"""
        elements.append(Spacer(1, 30))
        elements.append(Paragraph(
            f"Report generated on {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['SmallText']
        ))
        elements.append(Paragraph(
            "SentriKat - Enterprise Vulnerability Management",
            self.styles['SmallText']
        ))

    def generate_monthly_report(self, year=None, month=None):
        """
        Generate a monthly vulnerability report

        Args:
            year: Report year (default: current year)
            month: Report month (default: current month)

        Returns:
            BytesIO: PDF file buffer
        """
        now = datetime.now()
        year = year or now.year
        month = month or now.month

        # Calculate date range
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = datetime(year, month + 1, 1) - timedelta(days=1)

        # Get organization name
        org_name = "All Organizations"
        if self.organization_id:
            org = Organization.query.get(self.organization_id)
            if org:
                org_name = org.display_name

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        elements = []

        # Header
        month_name = start_date.strftime('%B %Y')
        self._create_header(
            elements,
            f"Vulnerability Report",
            f"{month_name} | {org_name}"
        )

        # Get statistics
        stats, all_matches = self._get_stats(start_date, end_date)

        # Summary
        self._create_summary_table(elements, stats)

        # Priority breakdown
        self._create_priority_breakdown(elements, stats)

        # Unacknowledged vulnerabilities (pending action)
        pending = [m for m in all_matches if not m.acknowledged]
        pending_sorted = sorted(pending, key=lambda m: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
        ))
        self._create_vulnerability_list(elements, pending_sorted, "Pending Action Items")

        # Page break before acknowledged section if there are many pending
        if len(pending) > 30:
            elements.append(PageBreak())

        # Acknowledged vulnerabilities
        acknowledged = [m for m in all_matches if m.acknowledged]
        acknowledged_sorted = sorted(acknowledged, key=lambda m: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
        ))
        self._create_vulnerability_list(elements, acknowledged_sorted, "Acknowledged Vulnerabilities")

        # Footer
        self._create_footer(elements, now)

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        return buffer

    def generate_custom_report(self, start_date, end_date, include_acknowledged=True, include_pending=True):
        """
        Generate a custom date range vulnerability report

        Args:
            start_date: Report start date
            end_date: Report end date
            include_acknowledged: Include acknowledged vulnerabilities
            include_pending: Include pending vulnerabilities

        Returns:
            BytesIO: PDF file buffer
        """
        # Get organization name
        org_name = "All Organizations"
        if self.organization_id:
            org = Organization.query.get(self.organization_id)
            if org:
                org_name = org.display_name

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        elements = []

        # Header
        date_range = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        self._create_header(
            elements,
            f"Vulnerability Report",
            f"{date_range} | {org_name}"
        )

        # Get statistics
        stats, all_matches = self._get_stats(start_date, end_date)

        # Summary
        self._create_summary_table(elements, stats)

        # Priority breakdown
        self._create_priority_breakdown(elements, stats)

        # Pending vulnerabilities
        if include_pending:
            pending = [m for m in all_matches if not m.acknowledged]
            pending_sorted = sorted(pending, key=lambda m: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
            ))
            self._create_vulnerability_list(elements, pending_sorted, "Pending Action Items")

        # Acknowledged vulnerabilities
        if include_acknowledged:
            if include_pending and len([m for m in all_matches if not m.acknowledged]) > 30:
                elements.append(PageBreak())

            acknowledged = [m for m in all_matches if m.acknowledged]
            acknowledged_sorted = sorted(acknowledged, key=lambda m: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
            ))
            self._create_vulnerability_list(elements, acknowledged_sorted, "Acknowledged Vulnerabilities")

        # Footer
        self._create_footer(elements, datetime.now())

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        return buffer

    def generate_selected_report(self, match_ids):
        """
        Generate a report for specifically selected vulnerability matches

        Args:
            match_ids: List of VulnerabilityMatch IDs to include

        Returns:
            BytesIO: PDF file buffer
        """
        # Get organization name
        org_name = "All Organizations"
        if self.organization_id:
            org = Organization.query.get(self.organization_id)
            if org:
                org_name = org.display_name

        # Get the selected matches with eager loading to avoid N+1 queries
        # Note: Product.organizations is a dynamic relationship and can't be eager loaded
        matches = VulnerabilityMatch.query.options(
            selectinload(VulnerabilityMatch.vulnerability),
            selectinload(VulnerabilityMatch.product)
        ).filter(
            VulnerabilityMatch.id.in_(match_ids)
        ).all()

        if not matches:
            # Create empty report
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            elements = []
            self._create_header(elements, "Selected Vulnerabilities Report", org_name)
            elements.append(Paragraph("No vulnerabilities found with the specified IDs.", self.styles['ReportBody']))
            doc.build(elements)
            buffer.seek(0)
            return buffer

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        elements = []

        # Header
        self._create_header(
            elements,
            f"Selected Vulnerabilities Report",
            f"{len(matches)} Selected Items | {org_name}"
        )

        # Calculate stats for selected matches
        stats = {
            'total': len(matches),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'acknowledged': 0,
            'pending': 0,
            'ransomware': 0
        }

        for m in matches:
            priority = m.calculate_effective_priority()
            if priority in stats:
                stats[priority] += 1
            if m.acknowledged:
                stats['acknowledged'] += 1
            else:
                stats['pending'] += 1
            if m.vulnerability and m.vulnerability.known_ransomware:
                stats['ransomware'] += 1

        # Summary
        self._create_summary_table(elements, stats)

        # Priority breakdown
        self._create_priority_breakdown(elements, stats)

        # Pending vulnerabilities
        pending = [m for m in matches if not m.acknowledged]
        pending_sorted = sorted(pending, key=lambda m: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
        ))
        if pending_sorted:
            self._create_vulnerability_list(elements, pending_sorted, "Pending Action Items")

        # Acknowledged vulnerabilities
        acknowledged = [m for m in matches if m.acknowledged]
        acknowledged_sorted = sorted(acknowledged, key=lambda m: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(m.calculate_effective_priority() or 'low', 4)
        ))
        if acknowledged_sorted:
            if pending_sorted and len(pending_sorted) > 20:
                elements.append(PageBreak())
            self._create_vulnerability_list(elements, acknowledged_sorted, "Acknowledged Vulnerabilities")

        # Footer
        self._create_footer(elements, datetime.now())

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        return buffer
