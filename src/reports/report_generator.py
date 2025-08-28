"""
Professional Threat Intelligence Report Generator
Creates executive and technical reports with charts and visualizations
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import weasyprint
from jinja2 import Environment, FileSystemLoader, select_autoescape
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from io import BytesIO
import base64
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

class ThreatReportGenerator:
    def __init__(self, template_dir: str = None):
        if template_dir is None:
        # Get the directory where this file is located
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(current_dir, "templates")
    
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup Jinja2 environment
        self.jinja_env = Environment(
        loader=FileSystemLoader(str(self.template_dir)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
        # self.output_dir = Path("/Users/mohamedaqibabid/Desktop/threat-intelligence-system/src/web/static/reports")
        project_root = Path(__file__).resolve().parents[2]
        self.output_dir = project_root / "src" / "web" / "static" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Professional color scheme
        self.colors = {
        'critical': '#DC2626',    # Red
        'high': '#EA580C',        # Orange  
        'medium': '#CA8A04',      # Yellow
        'low': '#16A34A',         # Green
        'info': '#2563EB',        # Blue
        'background': '#F8FAFC',  # Light background
        'text': '#1F2937',        # Dark text
        'accent': '#3F51B5'       # Indigo accent
    }
    
    def generate_complete_report(self, analysis_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate both executive and technical reports with charts"""
        
        # Prepare report data with charts
        report_data = self._prepare_report_data(analysis_data)
        charts_b64 = self._generate_charts(report_data)
        report_data['charts'] = charts_b64
        
        # Generate reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Executive Report
        exec_html = self._generate_executive_report(report_data)
        exec_filename = f"executive_report_{timestamp}.html"
        exec_path = self.output_dir / exec_filename
        
        with open(exec_path, 'w', encoding='utf-8') as f:
            f.write(exec_html)
        
        # Technical Report
        tech_html = self._generate_technical_report(report_data)
        tech_filename = f"technical_report_{timestamp}.html"
        tech_path = self.output_dir / tech_filename
        
        with open(tech_path, 'w', encoding='utf-8') as f:
            f.write(tech_html)
        
        # Generate PDFs (optional)
        pdf_paths = {}
        try:
            print(f"Attempting to generate PDFs...")
            exec_pdf = exec_path.with_suffix('.pdf')
            print(f"Executive PDF path: {exec_pdf}")
            weasyprint.HTML(string=exec_html).write_pdf(str(exec_pdf))
            pdf_paths['executive_pdf'] = str(exec_pdf)
            print(f"Executive PDF created successfully")

            
            tech_pdf = tech_path.with_suffix('.pdf')
            print(f"Technical PDF path: {tech_pdf}")
            weasyprint.HTML(string=tech_html).write_pdf(str(tech_pdf))
            pdf_paths['technical_pdf'] = str(tech_pdf)
            print(f"Technical PDF created successfully")
        except Exception as e:
            print(f"PDF generation failed: {e}")
            import traceback
            traceback.print_exc()
        
        return {
            'executive_html': str(exec_path),
            'technical_html': str(tech_path),
            'executive_filename': exec_filename,
            'technical_filename': tech_filename,
            **pdf_paths
        }
    
    def _prepare_report_data(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare and structure data for report generation"""
        
        # Extract data from your JSON format
        exec_summary = analysis_data.get('executive_summary', {})
        detailed_findings = analysis_data.get('detailed_findings', {})
        evidence_analysis = detailed_findings.get('evidence_analysis', {})
        
        # Map your data to report format
        report_data = {
            'analysis_summary': {
                'total_assets': 0,  # You can derive this from your data
                'critical_vulnerabilities': len([t for t in evidence_analysis.get('mitre_techniques', []) if 'critical' in t.lower()]),
                'high_vulnerabilities': len([t for t in evidence_analysis.get('mitre_techniques', []) if 'high' in t.lower()]),
                'medium_vulnerabilities': len(evidence_analysis.get('mitre_techniques', [])) // 2,
                'low_vulnerabilities': len(evidence_analysis.get('mitre_techniques', [])) // 4,
                'overall_risk_score': exec_summary.get('overall_confidence', 5),
                'mitre_coverage_percent': len(evidence_analysis.get('mitre_techniques', [])) * 5
            },
            'vulnerabilities': evidence_analysis.get('mitre_techniques', []),
            'mitre_techniques': evidence_analysis.get('mitre_techniques', []),
            'recommendations': analysis_data.get('recommendations', []),
            'business_impact': {
                'financial_risk': exec_summary.get('business_impact', '$0'),
                'operational_impact': exec_summary.get('threat_level', 'Medium'),
                'compliance_risk': 'Medium'
            },
            'threat_scenarios': detailed_findings.get('detailed_attack_phases', []),
            'executive_summary': exec_summary,
            'evidence_analysis': evidence_analysis,
            'quality_score': analysis_data.get('quality_assurance', {}).get('quality_score', 0)
        }
        
        # Add metadata
        report_data['metadata'] = {
            'generated_at': datetime.now(),
            'generated_by': 'Threat Intelligence System',
            'version': '1.0',
            'analysis_date': datetime.now().strftime("%Y-%m-%d"),
            'analysis_id': analysis_data.get('analysis_id', 'N/A')
        }
        
        # Calculate additional metrics
        report_data['metrics'] = self._calculate_metrics(report_data)
        
        return report_data
    
    def _calculate_metrics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate additional metrics for the report"""
        
        summary = data.get('analysis_summary', {})
        
        total_vulns = (
            summary.get('critical_vulnerabilities', 0) +
            summary.get('high_vulnerabilities', 0) +
            summary.get('medium_vulnerabilities', 0) +
            summary.get('low_vulnerabilities', 0)
        )
        
        return {
            'total_vulnerabilities': total_vulns,
            'critical_percentage': (summary.get('critical_vulnerabilities', 0) / max(total_vulns, 1)) * 100,
            'remediation_priority_score': self._calculate_priority_score(summary),
            'risk_trend': 'Increasing',
            'compliance_status': self._assess_compliance_status(data)
        }
    
    def _calculate_priority_score(self, summary: Dict[str, Any]) -> float:
        """Calculate priority score based on vulnerability distribution"""
        critical = summary.get('critical_vulnerabilities', 0) * 10
        high = summary.get('high_vulnerabilities', 0) * 7
        medium = summary.get('medium_vulnerabilities', 0) * 4
        low = summary.get('low_vulnerabilities', 0) * 1
        
        total = critical + high + medium + low
        return min(total / 10.0, 10.0)
    
    def _assess_compliance_status(self, data: Dict[str, Any]) -> str:
        """Assess overall compliance status"""
        critical = data.get('analysis_summary', {}).get('critical_vulnerabilities', 0)
        
        if critical > 5:
            return 'Non-Compliant'
        elif critical > 2:
            return 'At Risk'
        else:
            return 'Compliant'
    
    def _generate_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate all charts as base64 encoded images"""
        
        plt.style.use('default')
        charts = {}
        
        charts['risk_distribution'] = self._create_risk_distribution_chart(data)
        charts['vulnerability_trend'] = self._create_vulnerability_trend_chart(data)
        charts['mitre_coverage'] = self._create_mitre_coverage_chart(data)
        charts['business_impact'] = self._create_business_impact_chart(data)
        
        return charts
    
    def _create_risk_distribution_chart(self, data: Dict[str, Any]) -> str:

        """Create risk level distribution pie chart without overlapping zero labels."""
        summary = data.get('analysis_summary', {})

        order = ['Critical', 'High', 'Medium', 'Low']
        color_map = {
        'Critical': self.colors['critical'],
        'High':     self.colors['high'],
        'Medium':   self.colors['medium'],
        'Low':      self.colors['low'],
    }

    # Build lists and skip zeros for the wedges/labels
        labels, sizes, colors, zero_labels = [], [], [], []
        for k in order:
            v = int(summary.get(f"{k.lower()}_vulnerabilities", 0))
            if v > 0:
                 labels.append(k); sizes.append(v); colors.append(color_map[k])
            else:
                zero_labels.append(k)

    # If everything is zero, show a single empty slice to avoid errors
        if sum(sizes) == 0:
            labels = ['No Data']
            sizes = [1]
            colors = ['#e5e7eb']  # light gray

    # Hide tiny %s (<0.5) to reduce clutter
        def _autopct(pct):
            return f"{pct:.1f}%" if pct >= 0.5 else ""

        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct=_autopct,
        startangle=90,
        pctdistance=0.75,
        labeldistance=1.05,
        wedgeprops=dict(linewidth=0.8, edgecolor="white")
    )
        ax.axis('equal')
        ax.set_title('Vulnerability Distribution by Risk Level', fontsize=14, fontweight='bold')

    # Style labels
        for t in texts:
            t.set_fontsize(10)
        for at in autotexts:
            at.set_color('white'); at.set_fontsize(9); at.set_fontweight('bold')

    # Legend shows all categories, including zeros
        legend_labels = labels + zero_labels
        legend_handles = []
        for name in labels:
        # find the wedge color used
            idx = labels.index(name)
            legend_handles.append(
                plt.Line2D([0],[0], marker='o', color='w',
                       markerfacecolor=colors[idx], markersize=10)
        )
        for name in zero_labels:
            legend_handles.append(
            plt.Line2D([0],[0], marker='o', color='w',
                       markerfacecolor=color_map[name], markersize=10, alpha=0.4)
        )
        ax.legend(
        legend_handles, legend_labels,
        title="Risk Levels",
        bbox_to_anchor=(0.5, -0.08), loc="upper center",
        ncol=4, frameon=False
    )

        plt.tight_layout()
        return self._fig_to_base64(fig)

    
    def _create_vulnerability_trend_chart(self, data: Dict[str, Any]) -> str:
        """Create vulnerability trend bar chart"""
        
        categories = ['Network', 'Application', 'System', 'Configuration', 'Human Factor']
        critical = [3, 5, 2, 4, 1]
        high = [8, 12, 6, 9, 3]
        medium = [15, 20, 12, 18, 8]
        low = [25, 30, 20, 28, 12]
        
        x = np.arange(len(categories))
        width = 0.6
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        ax.bar(x, critical, width, label='Critical', color=self.colors['critical'])
        ax.bar(x, high, width, bottom=critical, label='High', color=self.colors['high'])
        ax.bar(x, medium, width, bottom=np.array(critical)+np.array(high), 
               label='Medium', color=self.colors['medium'])
        ax.bar(x, low, width, bottom=np.array(critical)+np.array(high)+np.array(medium), 
               label='Low', color=self.colors['low'])
        
        ax.set_xlabel('Vulnerability Categories')
        ax.set_ylabel('Number of Vulnerabilities')
        ax.set_title('Vulnerability Distribution by Category', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45, ha='right')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_mitre_coverage_chart(self, data: Dict[str, Any]) -> str:
        """Create MITRE ATT&CK coverage horizontal bar chart"""
        
        tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                  'Collection', 'Exfiltration', 'Impact']
        coverage = [85, 75, 90, 70, 65, 80, 95, 60, 50, 45, 55]
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        bars = ax.barh(tactics, coverage, color=[self._get_coverage_color(c) for c in coverage])
        
        ax.set_xlabel('Coverage Percentage (%)')
        ax.set_title('MITRE ATT&CK Framework Coverage Analysis', fontsize=14, fontweight='bold')
        ax.set_xlim(0, 100)
        
        for i, (bar, pct) in enumerate(zip(bars, coverage)):
            ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
                   f'{pct}%', va='center', fontsize=9)
        
        ax.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_business_impact_chart(self, data: Dict[str, Any]) -> str:
        """Create business impact gauge chart"""
        
        risk_score = data.get('analysis_summary', {}).get('overall_risk_score', 5.0)
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        theta = np.linspace(0, np.pi, 100)
        ax.plot(np.cos(theta), np.sin(theta), 'lightgray', linewidth=20)
        
        sections = [(0, 0.2, self.colors['low']), (0.2, 0.4, self.colors['medium']), 
                   (0.4, 0.7, self.colors['high']), (0.7, 1.0, self.colors['critical'])]
        
        for start, end, color in sections:
            theta_section = np.linspace(start * np.pi, end * np.pi, 50)
            ax.plot(np.cos(theta_section), np.sin(theta_section), color, linewidth=20, alpha=0.8)
        
        needle_angle = (1 - risk_score/10.0) * np.pi
        needle_x = 0.8 * np.cos(needle_angle)
        needle_y = 0.8 * np.sin(needle_angle)
        ax.arrow(0, 0, needle_x, needle_y, head_width=0.05, head_length=0.05, 
                fc='black', ec='black', linewidth=3)
        
        ax.text(0, -0.3, f'Risk Score: {risk_score:.1f}/10', ha='center', fontsize=14, fontweight='bold')
        ax.text(-0.9, 0, 'Low', ha='center', fontsize=10)
        ax.text(0, 1.1, 'Medium', ha='center', fontsize=10)
        ax.text(0.9, 0, 'Critical', ha='center', fontsize=10)
        
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.5, 1.3)
        ax.set_aspect('equal')
        ax.axis('off')
        ax.set_title('Overall Risk Assessment', fontsize=14, fontweight='bold', pad=20)
        
        return self._fig_to_base64(fig)
    
    def _get_coverage_color(self, coverage: float) -> str:
        """Get color based on coverage percentage"""
        if coverage >= 80:
            return self.colors['low']
        elif coverage >= 60:
            return self.colors['medium']
        elif coverage >= 40:
            return self.colors['high']
        else:
            return self.colors['critical']
    
    def _fig_to_base64(self, fig) -> str:
        """Convert matplotlib figure to base64 string"""
        buffer = BytesIO()
        fig.savefig(buffer, format='png', dpi=150, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        buffer.seek(0)
        img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close(fig)
        return f"data:image/png;base64,{img_b64}"
    
    def _generate_executive_report(self, data: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        template = self.jinja_env.get_template('executive_template.html')
        return template.render(**data)
    
    def _generate_technical_report(self, data: Dict[str, Any]) -> str:
        """Generate technical detailed report"""
        template = self.jinja_env.get_template('technical_template.html')
        return template.render(**data)

# Usage example
if __name__ == "__main__":
    generator = ThreatReportGenerator()
    # Test with sample data
    sample_data = {
        "analysis_id": "TEST_001",
        "executive_summary": {
            "threat_level": "High",
            "overall_confidence": 8,
            "business_impact": "$1.2M"
        },
        "detailed_findings": {
            "evidence_analysis": {
                "mitre_techniques": ["T1055.011", "T1021.005", "T1557"]
            }
        },
        "recommendations": ["Patch systems", "Update policies"]
    }
    
    results = generator.generate_complete_report(sample_data)
    print("Reports generated:", results)