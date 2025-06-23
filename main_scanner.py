import os
import importlib.util
import requests
import urllib.parse
import re
from urllib.parse import urljoin
from datetime import datetime
import time

class RateLimitedSession(requests.Session):
    def __init__(self, delay=0.2):
        super().__init__()
        self.delay = delay
        self._last_request_time = None

    def request(self, *args, **kwargs):
        now = time.time()
        if self._last_request_time is not None:
            elapsed = now - self._last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        response = super().request(*args, **kwargs)
        self._last_request_time = time.time()
        return response

class Scanner:
    def __init__(self, target_url, timeout=30, generate_pdf=False, delay=0.2):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.generate_pdf = generate_pdf
        self.delay = delay
        self.session = RateLimitedSession(delay=delay)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.scan_start_time = datetime.now()
        self.scan_end_time = None
        # Untuk plugin
        self.urllib = urllib
        self.re = re
        self.urljoin = urljoin

    def log_vulnerability(self, vuln_type, severity, description, evidence=None, cwe=None):
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'cwe': cwe,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        print(f"[RESULT][{severity}] {vuln_type}: {description}")
        if evidence:
            print(f"  Evidence: {evidence}")

    def run_plugins(self, plugin_dir='vuln_plugins', selected_plugins=None):
        print(f"\n[INFO] Loading plugins from: {plugin_dir}")
        for fname in os.listdir(plugin_dir):
            if fname.endswith('.py') and not fname.startswith('__'):
                plugin_name = fname[:-3]
                if selected_plugins is not None and plugin_name not in selected_plugins:
                    continue
                path = os.path.join(plugin_dir, fname)
                spec = importlib.util.spec_from_file_location(plugin_name, path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, 'scan'):
                    print(f"[INFO] Running plugin: {fname}")
                    mod.scan(self)
        self.scan_end_time = datetime.now()
        if self.generate_pdf:
            self.generate_pdf_report()

    def generate_pdf_report(self):
        """Generate PDF report of scan results"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            # Create reports directory if it doesn't exist
            reports_dir = 'reports'
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
            
            # Create PDF filename in reports directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = os.path.join(reports_dir, f"vulnerability_scan_report_{timestamp}.pdf")
            
            # Create PDF document
            doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
            story = []
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkred
            )
            
            normal_style = styles['Normal']
            
            # Title
            story.append(Paragraph("LAPORAN PEMINDAIAN KERENTANAN WEB", title_style))
            story.append(Spacer(1, 20))
            
            # Scan Information
            story.append(Paragraph("INFORMASI PEMINDAIAN", heading_style))
            scan_info_data = [
                ['Target URL', self.target_url],
                ['Waktu Mulai', self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")],
                ['Waktu Selesai', self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")],
                ['Durasi', str(self.scan_end_time - self.scan_start_time)],
                ['Total Kerentanan', str(len(self.vulnerabilities))]
            ]
            
            scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
            scan_info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(scan_info_table)
            story.append(Spacer(1, 20))
            
            # Vulnerability Summary
            if self.vulnerabilities:
                story.append(Paragraph("RINGKASAN KERENTANAN", heading_style))
                
                # Count vulnerabilities by severity
                severity_counts = {}
                for vuln in self.vulnerabilities:
                    severity = vuln['severity']
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                summary_data = [['Tingkat Keparahan', 'Jumlah']]
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                    count = severity_counts.get(severity, 0)
                    summary_data.append([severity, str(count)])
                
                summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(summary_table)
                story.append(Spacer(1, 20))
                
                # Detailed Vulnerabilities
                story.append(Paragraph("DETAIL KERENTANAN", heading_style))
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    # Vulnerability header
                    vuln_header = f"{i}. {vuln['type']} - {vuln['severity']}"
                    story.append(Paragraph(vuln_header, styles['Heading3']))
                    
                    # Vulnerability details
                    details_data = [
                        ['Deskripsi', vuln['description']],
                        ['CWE', vuln.get('cwe', 'N/A')],
                        ['Waktu Deteksi', vuln.get('timestamp', 'N/A')]
                    ]
                    
                    if vuln.get('evidence'):
                        details_data.append(['Bukti', vuln['evidence']])
                    
                    details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
                    details_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(details_table)
                    story.append(Spacer(1, 12))
            else:
                story.append(Paragraph("TIDAK ADA KERENTANAN DITEMUKAN", heading_style))
                story.append(Paragraph("Pemindaian selesai dan tidak menemukan kerentanan yang signifikan.", normal_style))
            
            # Recommendations
            story.append(Spacer(1, 20))
            story.append(Paragraph("REKOMENDASI KEAMANAN", heading_style))
            
            recommendations = [
                "• Lakukan patch segera untuk kerentanan Critical dan High",
                "• Implementasikan validasi input yang ketat",
                "• Gunakan HTTPS untuk semua komunikasi",
                "• Tambahkan header keamanan (HSTS, CSP, X-Frame-Options)",
                "• Lakukan audit keamanan secara berkala",
                "• Update software dan library ke versi terbaru",
                "• Implementasikan logging dan monitoring yang baik"
            ]
            
            for rec in recommendations:
                story.append(Paragraph(rec, normal_style))
            
            # Footer
            story.append(Spacer(1, 30))
            footer_text = f"Laporan ini dibuat pada {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} oleh Scanner Kerentanan Web Modular"
            story.append(Paragraph(footer_text, ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=10,
                alignment=TA_CENTER,
                textColor=colors.grey
            )))
            
            # Build PDF
            doc.build(story)
            print(f"\n[SUCCESS] Report PDF berhasil dibuat: {pdf_filename}")
            
        except ImportError:
            print("\n[ERROR] Library reportlab tidak ditemukan. Install dengan: pip install reportlab")
        except Exception as e:
            print(f"\n[ERROR] Gagal membuat report PDF: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Scanner Kerentanan Web Modular')
    parser.add_argument('target', help='URL target untuk di-scan')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout request (default: 30)')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report PDF')
    parser.add_argument('-p', '--plugin', type=str, help='Jalankan plugin tertentu saja (pisahkan dengan koma, contoh: xss,sqli,csrf)')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay (detik) antar request ke target (default: 0.2)')
    args = parser.parse_args()
    
    selected_plugins = None
    if args.plugin:
        selected_plugins = [p.strip().lower() for p in args.plugin.split(',') if p.strip()]
    
    scanner = Scanner(target_url=args.target, timeout=args.timeout, generate_pdf=args.report, delay=args.delay)
    scanner.run_plugins(selected_plugins=selected_plugins)
    
    print("\n[SUMMARY] Kerentanan yang ditemukan:")
    for v in scanner.vulnerabilities:
        print(f"- [{v['severity']}] {v['type']}: {v['description']}")
    
    if scanner.generate_pdf:
        print(f"\n[INFO] Report PDF telah dibuat untuk analisis lebih lanjut.") 