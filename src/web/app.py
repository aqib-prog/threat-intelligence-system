from flask import Flask, render_template, request, jsonify
import os
import sys
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for

# Add project root to sys.path
sys.path.append(Path(__file__).resolve().parents[1].as_posix())

from utils.file_parser import FileParser
from utils.data_validator import DataValidator
from reports.report_generator import ThreatReportGenerator

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'

# Folders
BASE_DIR = Path(__file__).resolve().parents[2]   # project root
DATA_DIR = BASE_DIR / "src" / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"               # JSON analysis results
GENERATED_REPORTS_DIR = BASE_DIR / "src" / "web" / "static" / "reports"  # HTML/PDF outputs

# Ensure dirs exist
for d in [DATA_DIR, UPLOADS_DIR, REPORTS_DIR, GENERATED_REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Helpers
parser = FileParser()
validator = DataValidator()


@app.route('/')
def index():
    """Main dashboard showing generated reports"""
    reports = []
    if GENERATED_REPORTS_DIR.exists():
        for file in GENERATED_REPORTS_DIR.glob("*.html"):
            reports.append({
                'name': file.name,
                'created': datetime.fromtimestamp(file.stat().st_ctime),
                'size': file.stat().st_size
            })
    reports.sort(key=lambda x: x['created'], reverse=True)
    
    # Get dashboard stats
    stats_data = dashboard_stats()  # Call your existing function
    
    # Pass both reports and stats to template
    return render_template('index.html', reports=reports, stats=stats_data)


@app.route('/upload_json', methods=['POST'])
def upload_json():
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({'error': 'Empty JSON payload'}), 400

        # allow ?data_type=asset|evidence or {"data_type":"asset"...}
        data_type = request.args.get('data_type') or payload.get('data_type')
        if data_type not in ('asset', 'evidence'):
            return jsonify({'error': "data_type must be 'asset' or 'evidence'"}), 400

        # pick the right validator
        if data_type == 'asset':
            validation = validator.validate_asset_data(payload)
            count = payload.get('count') or len(payload.get('system_details', []))
            filename = 'asset_data.json'
        else:
            validation = validator.validate_evidence_data(payload)
            count = payload.get('count') or len(payload.get('security_assessment_findings', []))
            filename = 'evidence_data.json'

        # save where /run_analysis expects
        output_dir = Path('src/data')
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename

        with open(output_file, 'w') as f:
            json.dump(payload, f, indent=2)

        return jsonify({
            'success': True,
            'data_type': data_type,
            'validation': validation,
            'record_count': count,
            'saved_to': str(output_file)
        }), 200

    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'details': traceback.format_exc()
        }), 500

@app.route('/run_analysis', methods=['POST'])
def run_analysis():
    """Run threat analysis using uploaded asset/evidence data"""
    try:
        # Load uploaded data
        assets_data = None
        evidence_data = None

        try:
            with open(DATA_DIR / "asset_data.json", "r") as f:
                assets_data = json.load(f)
        except FileNotFoundError:
            pass

        try:
            with open(DATA_DIR / "evidence_data.json", "r") as f:
                evidence_data = json.load(f)
        except FileNotFoundError:
            pass

        if not assets_data and not evidence_data:
            return jsonify({
                'success': False,
                'error': 'No data found. Please upload asset or evidence data first.'
            }), 400

        # Run workflow executor
        from agents.workflow_executor import WorkflowExecutor
        executor = WorkflowExecutor()
        analysis_result = executor.execute_complete_analysis(assets_data, evidence_data)

        # Save JSON result
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = REPORTS_DIR / f"threat_analysis_TI_{timestamp}.json"
        with open(result_file, "w") as f:
            json.dump(analysis_result, f, indent=2, default=str)

        return jsonify({
            'success': True,
            'message': 'Analysis completed successfully',
            'result_file': str(result_file),
            'analysis_id': analysis_result.get('analysis_id', timestamp),
            'quality_score': analysis_result.get('quality_score', 0),
            'approval_status': analysis_result.get('approval_status', 'UNKNOWN')
        })

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'details': traceback.format_exc()}), 500


import base64

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate executive/technical reports from latest JSON analysis"""
    try:
        # Get latest analysis JSON (existing code)
        report_files = sorted(
            REPORTS_DIR.glob("threat_analysis_TI_*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        if not report_files:
            return jsonify({'error': 'No threat analysis report found'}), 404

        latest_file = report_files[0]
        with open(latest_file, "r") as f:
            report_data = json.load(f)

        generator = ThreatReportGenerator()
        results = generator.generate_complete_report(report_data)

        response = {
            'success': True,
            'executive_report': results['executive_filename'],
            'technical_report': results['technical_filename'],
            'source_file': str(latest_file)
        }
        
        # Add base64-encoded PDF data for email attachments
        if 'executive_pdf' in results:
            try:
                with open(results['executive_pdf'], 'rb') as f:
                    exec_pdf_data = base64.b64encode(f.read()).decode('utf-8')
                    response['executive_pdf_b64'] = exec_pdf_data
                    response['executive_pdf_name'] = f"Executive_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
            except Exception as e:
                print(f"Failed to encode executive PDF: {e}")
                
        if 'technical_pdf' in results:
            try:
                with open(results['technical_pdf'], 'rb') as f:
                    tech_pdf_data = base64.b64encode(f.read()).decode('utf-8')
                    response['technical_pdf_b64'] = tech_pdf_data
                    response['technical_pdf_name'] = f"Technical_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
            except Exception as e:
                print(f"Failed to encode technical PDF: {e}")
                
        return jsonify(response)

    except Exception as e:
        import traceback
        return jsonify({'error': str(e), 'details': traceback.format_exc()}), 500
    
@app.route('/download_pdf/<report_type>/<filename>')
def download_pdf(report_type, filename):
    
    """Download PDF version of report"""
    try:
        pdf_filename = filename.replace('.html', '.pdf')
        pdf_path = GENERATED_REPORTS_DIR / pdf_filename
        
        if pdf_path.exists():
            return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
        else:
            flash('PDF not found. Please regenerate the report.', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error downloading PDF: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/pdf/<filename>')
def serve_pdf(filename):
    """Serve PDF files directly"""
    try:
        pdf_path = GENERATED_REPORTS_DIR / filename
        if pdf_path.exists() and filename.endswith('.pdf'):
            return send_file(pdf_path, mimetype='application/pdf', as_attachment=False)
        else:
            return "PDF not found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    import glob, json
    from pathlib import Path
    
    # Fix the Path object concatenation
    reports_dir = REPORTS_DIR  # Use the already defined REPORTS_DIR
    reports = sorted(glob.glob(str(reports_dir / 'threat_analysis_*.json')))
    
    if not reports:
        return {"critical_threats": 0, "assets_analyzed": 0, "mitre_coverage": 0}
    
    latest_report = reports[-1]
    with open(latest_report) as f:
        data = json.load(f)
    
    critical_threats = data.get("challenger_analysis", {}).get("critical_issues_found", 0)
    assets_analyzed = len(data.get("detailed_findings", {}).get("asset_analysis", {}).get("findings", []))
    mitre_coverage = len(data.get("detailed_findings", {}).get("asset_analysis", {}).get("mitre_techniques", []))

    return {
        "critical_threats": critical_threats,
        "assets_analyzed": assets_analyzed,
        "mitre_coverage": mitre_coverage
    }


if __name__ == '__main__':
    app.run(debug=True, port=5000)
