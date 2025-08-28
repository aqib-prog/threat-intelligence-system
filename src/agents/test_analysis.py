import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)  # Add parent directory to path


from agents.workflow_executor import WorkflowExecutor

def run_test_analysis():
    # Create test data matching your workflow's expected format
    assets_data = {
    "system_details": [
        {
            "system_name": "Customer Database",
            "system_type": "Database System",
            "system_criticality": "VeryHigh",
            "site": "Corporate HQ",
            "related_processes": "Customer data processing, customer onboarding",
            "affected_equipment": "MySQL Server",
            "sensitive_data": ["PII", "Financial Records"],
            "exposure": "Internet-facing, accessible via web app",
            "known_vulnerabilities": ["SQL Injection risk", "Weak credential policy"]
        },
        {
            "system_name": "Email Server",
            "system_type": "Email System",
            "system_criticality": "High",
            "site": "Branch Office",
            "related_processes": "Internal and external communications",
            "affected_equipment": "Exchange Server",
            "sensitive_data": ["Internal business communications"],
            "exposure": "Internet-facing, employee remote access",
            "known_vulnerabilities": ["Phishing susceptibility", "Unpatched CVEs"]
        }
    ]
}
    
    evidence_data = {
    "security_assessment_findings": [
        {
            "assessment_type": "Executive Interview",
            "confidence_level": "High",
            "key_security_concerns": "Phishing targeting finance team, weak password reuse, unpatched servers",
            "incident_history": "Two phishing-related financial fraud attempts in last 6 months",
            "business_impact": "High risk to financial integrity and customer trust"
        },
        {
            "assessment_type": "Technical Assessment",
            "confidence_level": "Medium",
            "key_security_concerns": "Unpatched OS, outdated authentication, insufficient monitoring",
            "vulnerability_scan_summary": "15 critical, 27 high vulnerabilities across core systems",
            "business_impact": "High potential downtime and data exfiltration"
        },
        {
            "assessment_type": "User Survey",
            "confidence_level": "Medium",
            "key_security_concerns": "Password sharing, unauthorized USB usage, lack of awareness",
            "awareness_score": "42% of employees failed phishing simulation",
            "business_impact": "High likelihood of initial compromise"
        }
    ]
}
    
    print("Starting threat analysis test...")
    print("=" * 50)
    
    try:
        executor = WorkflowExecutor()
        result = executor.execute_complete_analysis(assets_data, evidence_data)
        
        print(f"Analysis completed!")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Analysis ID: {result.get('analysis_id', 'N/A')}")
        
        if result.get('status') == 'completed':
            print(f"Quality Score: {result.get('quality_score', 'N/A')}")
            print(f"Approval Status: {result.get('approval_status', 'N/A')}")
        elif result.get('status') == 'failed':
            print(f"Error: {result.get('error', 'Unknown error')}")
            
        return result
        
    except Exception as e:
        print(f"Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = run_test_analysis()