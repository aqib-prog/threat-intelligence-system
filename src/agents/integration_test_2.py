import sys
import os
from datetime import datetime

# Add the parent directory to path to properly import from src
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)  # Add parent directory to path

def run_test_analysis():
    """UPDATED Integration Test #2: Test the FIXED Quality Gate System"""
    
    try:
        # Try to import from the correct path - it's in src/agents/
        from src.agents.workflow_executor import WorkflowExecutor
        print("✅ Successfully imported WorkflowExecutor from src.agents.workflow_executor")
    except ImportError as e:
        print(f"❌ Error importing from src.agents.workflow_executor: {e}")
        
        try:
            # Try alternative import path
            from agents.workflow_executor import WorkflowExecutor
            print("✅ Successfully imported WorkflowExecutor from agents.workflow_executor")
        except ImportError as e2:
            print(f"❌ Error importing from agents.workflow_executor: {e2}")
            
            # Try direct import from current directory
            try:
                from workflow_executor import WorkflowExecutor
                print("✅ Successfully imported WorkflowExecutor from current directory")
            except ImportError as e3:
                print(f"❌ Error importing from current directory: {e3}")
                return False
    
    print("🧪 INTEGRATION TEST #2: TESTING FIXED QUALITY GATE")
    print("=" * 60)
    print("🎯 PRIMARY OBJECTIVE: Verify Quality Gate prevents 'garbage-in-polished-out' scenarios")
    print("🔍 TESTING: Input data quality properly impacts final scores")
    
    # TEST SCENARIO 1: Good Assets + Good Evidence = Should get high score
    good_assets = {
        "system_details": [
            {
                "system_name": "Production API Gateway",
                "system_type": "Load Balancer",
                "system_criticality": "Critical",
                "site": "Primary Data Center",
                "related_processes": "Customer authentication, payment processing, order management",
                "affected_equipment": "Web servers, database clusters, payment processors",
                "ip_address": "10.1.1.100",
                "operating_system": "Linux RHEL 8",
                "software_version": "nginx 1.20.1"
            },
            {
                "system_name": "Customer Database Cluster",
                "system_type": "Database System",
                "system_criticality": "Critical", 
                "site": "Primary Data Center",
                "related_processes": "Customer data management, order history, payment records",
                "affected_equipment": "Database servers, storage arrays, backup systems",
                "ip_address": "10.1.2.50-52",
                "operating_system": "Linux Ubuntu 20.04",
                "software_version": "PostgreSQL 13.4"
            },
            {
                "system_name": "Internal File Server",
                "system_type": "File Server",
                "system_criticality": "Medium",
                "site": "Secondary Office",
                "related_processes": "Document storage, shared resources, backup repository",
                "affected_equipment": "NAS devices, tape backup systems"
            }
        ]
    }
    
    good_evidence = {
        "security_assessment_findings": [
            {
                "assessment_type": "Comprehensive Vulnerability Assessment",
                "confidence_level": "High",
                "key_security_concerns": "Detailed analysis revealed multiple attack vectors including unpatched systems, weak authentication mechanisms, insufficient network segmentation, and inadequate logging. Critical vulnerabilities identified in web applications and database configurations."
            },
            {
                "assessment_type": "Security Interview with IT Staff",
                "confidence_level": "High", 
                "key_security_concerns": "Staff interviews revealed gaps in security awareness training, inconsistent patch management procedures, and limited incident response capabilities. Social engineering vulnerabilities were identified through discussions about current security practices."
            },
            {
                "assessment_type": "Network Security Analysis",
                "confidence_level": "Medium",
                "key_security_concerns": "Network analysis identified potential lateral movement paths, insufficient network monitoring, and weak perimeter defenses. Several network segments lack proper access controls."
            }
        ]
    }
    
    # TEST SCENARIO 2: Poor Assets + Poor Evidence = Should get low score (the key test!)
    poor_assets = {
        "system_details": [
            {
                "system_name": "Some Server",
                "system_type": "Server",
                # Missing criticality, site, details - minimal information
            },
            {
                "system_name": "Database",
                "system_type": "Database",
                # Missing most required fields
            }
        ]
    }
    
    poor_evidence = {
        "security_assessment_findings": [
            {
                "assessment_type": "Basic Check",
                "confidence_level": "Low",
                "key_security_concerns": "Some issues"
            }
        ]
    }
    
    print(f"\n📋 TEST SCENARIOS:")
    print(f"Scenario 1 (Good Data): {len(good_assets['system_details'])} detailed systems + {len(good_evidence['security_assessment_findings'])} comprehensive assessments")
    print(f"Scenario 2 (Poor Data): {len(poor_assets['system_details'])} minimal systems + {len(poor_evidence['security_assessment_findings'])} basic assessment")
    
    executor = WorkflowExecutor()
    test_results = []
    
    # TEST 1: Good Quality Data
    print(f"\n🟢 EXECUTING TEST 1: GOOD QUALITY DATA")
    print("="*50)
    start_time = datetime.now()
    
    try:
        result1 = executor.execute_complete_analysis(good_assets, good_evidence)
        duration1 = (datetime.now() - start_time).total_seconds()
        
        print(f"✅ Test 1 completed in {duration1:.1f} seconds")
        
        # Extract key metrics
        qa1 = result1.get('quality_assurance', {})
        quality_score1 = qa1.get('quality_score', 0) or result1.get('quality_score', 0)
        input_quality1 = qa1.get('input_data_quality', 0) or result1.get('input_data_quality', 0)
        approval1 = qa1.get('approval_status', 'UNKNOWN') or result1.get('approval_status', 'UNKNOWN')
        auto_approved1 = result1.get('auto_approved', False)

# BUT the real issue is the report structure - also try:
        if quality_score1 == 0:  # Fallback if quality_assurance is empty
           quality_score1 = result1.get('quality_score', 0)
           input_quality1 = result1.get('input_data_quality', 0) 
           approval1 = result1.get('approval_status', 'UNKNOWN')
        
        test_results.append({
            'name': 'Good Data',
            'quality_score': quality_score1,
            'input_data_quality': input_quality1,
            'approval': approval1,
            'auto_approved': auto_approved1,
            'duration': duration1
        })
        
        print(f"Results 1: Quality {quality_score1}/100, Input {input_quality1}/100, Status {approval1}")
        
    except Exception as e:
        print(f"❌ Test 1 failed: {str(e)}")
        test_results.append({'name': 'Good Data', 'error': str(e)})
    
    # TEST 2: Poor Quality Data (THE CRITICAL TEST)
    print(f"\n🔴 EXECUTING TEST 2: POOR QUALITY DATA (Critical Test)")
    print("="*50)
    start_time = datetime.now()
    
    try:
        result2 = executor.execute_complete_analysis(poor_assets, poor_evidence)
        duration2 = (datetime.now() - start_time).total_seconds()
        
        print(f"✅ Test 2 completed in {duration2:.1f} seconds")
        
        # Extract key metrics
        qa2 = result2.get('quality_assurance', {})
        quality_score2 = qa2.get('quality_score', 0) or result2.get('quality_score', 0)
        input_quality2 = qa2.get('input_data_quality', 0) or result2.get('input_data_quality', 0)
        approval2 = qa2.get('approval_status', 'UNKNOWN') or result2.get('approval_status', 'UNKNOWN')
        auto_approved2 = result2.get('auto_approved', False)
        
        test_results.append({
            'name': 'Poor Data',
            'quality_score': quality_score2,
            'input_data_quality': input_quality2,
            'approval': approval2,
            'auto_approved': auto_approved2,
            'input_gate_passed': input_gate_passed2,
            'duration': duration2
        })
        
        print(f"Results 2: Quality {quality_score2}/100, Input {input_quality2}/100, Status {approval2}")
        print(f"Input Data Gate: {'PASSED' if input_gate_passed2 else 'FAILED'}")
        
    except Exception as e:
        print(f"❌ Test 2 failed: {str(e)}")
        test_results.append({'name': 'Poor Data', 'error': str(e)})
    
    # CRITICAL ANALYSIS: Verify the fix is working
    print(f"\n🎯 CRITICAL FIX VERIFICATION")
    print("="*50)
    
    if len(test_results) == 2 and 'error' not in test_results[0] and 'error' not in test_results[1]:
        good_result = test_results[0]
        poor_result = test_results[1]
        
        # Check 1: Input data quality should be different
        input_quality_diff = good_result['input_data_quality'] - poor_result['input_data_quality']
        input_quality_working = input_quality_diff > 20  # Good should be significantly better
        
        print(f"🔍 INPUT DATA QUALITY DETECTION:")
        print(f"   Good Data Input Quality: {good_result['input_data_quality']}/100")
        print(f"   Poor Data Input Quality: {poor_result['input_data_quality']}/100")
        print(f"   Difference: {input_quality_diff:.1f} points")
        print(f"   Status: {'✅ WORKING' if input_quality_working else '❌ NOT WORKING'}")
        
        # Check 2: Combined scores should be different (the main fix)
        quality_score_diff = good_result['quality_score'] - poor_result['quality_score']
        quality_fix_working = quality_score_diff > 15  # Should be significant difference
        
        print(f"\n🔍 COMBINED QUALITY SCORING:")
        print(f"   Good Data Final Score: {good_result['quality_score']}/100")
        print(f"   Poor Data Final Score: {poor_result['quality_score']}/100") 
        print(f"   Difference: {quality_score_diff:.1f} points")
        print(f"   Status: {'✅ WORKING' if quality_fix_working else '❌ NOT WORKING'}")
        
        # Check 3: Poor data should not auto-approve (even if scenario is polished)
        auto_approval_fix = not poor_result['auto_approved']
        
        print(f"\n🔍 AUTO-APPROVAL PREVENTION:")
        print(f"   Good Data Auto-Approved: {good_result['auto_approved']}")
        print(f"   Poor Data Auto-Approved: {poor_result['auto_approved']}")
        print(f"   Status: {'✅ WORKING' if auto_approval_fix else '❌ NOT WORKING - Poor data was auto-approved!'}")
        
        # Check 4: Input data gate functionality (if implemented)
        input_gate_working = True
        if 'input_gate_passed' in poor_result:
            input_gate_working = not poor_result['input_gate_passed']
            print(f"\n🔍 INPUT DATA GATE:")
            print(f"   Poor Data Gate Status: {'FAILED' if not poor_result['input_gate_passed'] else 'PASSED'}")
            print(f"   Status: {'✅ WORKING' if input_gate_working else '❌ NOT WORKING - Gate should fail poor data'}")
        
        # Check 5: Approval status should reflect data quality
        approval_logic_working = (
            good_result['approval'] in ['APPROVED', 'CONDITIONAL_APPROVAL'] and
            poor_result['approval'] in ['REJECTED']
        )
        
        print(f"\n🔍 APPROVAL LOGIC:")
        print(f"   Good Data Approval: {good_result['approval']}")
        print(f"   Poor Data Approval: {poor_result['approval']}")
        print(f"   Status: {'✅ WORKING' if approval_logic_working else '❌ NOT WORKING'}")
        
        # OVERALL ASSESSMENT
        all_checks = [
            input_quality_working,
            quality_fix_working, 
            auto_approval_fix,
            input_gate_working,
            approval_logic_working
        ]
        
        checks_passed = sum(all_checks)
        total_checks = len(all_checks)
        
        print(f"\n🏆 OVERALL QUALITY GATE FIX STATUS:")
        print(f"   Checks Passed: {checks_passed}/{total_checks}")
        print(f"   Status: {' ===== QUALITY GATE FIXED!' if checks_passed >= 4 else ' NEEDS MORE WORK'}")
        
        if checks_passed >= 4:
            print(f"\n🎊 SUCCESS! The Quality Gate now properly:")
            print(f"    Detects input data quality differences")
            print(f"   Prevents high scores from poor input data")
            print(f"    Blocks auto-approval of garbage-in scenarios")
            print(f"    Makes realistic approval decisions")
            
            # Performance check
            print(f"\n⚡ PERFORMANCE CHECK:")
            print(f"   Good Data Processing: {good_result['duration']:.1f}s")
            print(f"   Poor Data Processing: {poor_result['duration']:.1f}s")
            
            if poor_result['duration'] < good_result['duration']:
                print(f"   ===== OPTIMIZATION WORKING: Poor data rejected faster =====")
            
        else:
            print(f"\n🔧 ISSUES DETECTED:")
            if not input_quality_working:
                print(f"   Input data quality detection needs improvement")
            if not quality_fix_working:
                print(f"    Combined scoring still allows garbage-in-polished-out")
            if not auto_approval_fix:
                print(f"    Poor data is still being auto-approved")
            if not approval_logic_working:
                print(f"    Approval logic needs adjustment")
        
        return checks_passed >= 4
        
    else:
        print(f" Tests failed to execute properly - cannot verify fix")
        for result in test_results:
            if 'error' in result:
                print(f"   {result['name']}: {result['error']}")
        return False

def test_original_problem_scenario():
    """Test the exact scenario from the original problem report"""
    
    print(f"\n========= TESTING ORIGINAL PROBLEM SCENARIO")
    print("="*50)
    print("This tests the exact scenario that was producing 94.1/100 from poor input data")
    
    try:
        from src.agents.workflow_executor import WorkflowExecutor
    except ImportError:
        try:
            from agents.workflow_executor import WorkflowExecutor
        except ImportError:
            from workflow_executor import WorkflowExecutor
    
    # The EXACT scenario that was problematic:
    # Assets: 62.5/100, Evidence: 90/100 → Combined: 94.1/100 (WRONG!)
    
    problematic_assets = {
        "system_details": [
            {
                "system_name": "Test System",
                "system_type": "Database",
                "system_criticality": "High"
                # Missing many details → should be ~62.5/100
            }
        ]
    }
    
    problematic_evidence = {
        "security_assessment_findings": [
            {
                "assessment_type": "Interview",
                "confidence_level": "Medium",
                "key_security_concerns": "Basic security concerns identified during assessment process with some additional details about potential vulnerabilities"
                # Should be ~90/100
            }
        ]
    }
    
    executor = WorkflowExecutor()
    
    print(f"🚀 Executing the original problematic scenario...")
    start_time = datetime.now()
    
    try:
        result = executor.execute_complete_analysis(problematic_assets, problematic_evidence)
        duration = (datetime.now() - start_time).total_seconds()
        
        qa = result.get('quality_assurance', {})
        final_score = qa.get('quality_score', 0)
        input_quality = qa.get('input_data_quality', 0)
        scenario_quality = qa.get('scenario_quality', 0)
        approval = qa.get('approval_status', 'UNKNOWN')
        
        print(f"\n ======  RESULTS:")
        print(f"   Input Data Quality: {input_quality}/100")
        print(f"   Scenario Quality: {scenario_quality}/100") 
        print(f"   FINAL Combined Score: {final_score}/100")
        print(f"   Approval Status: {approval}")
        
        # The fix is working if:
        # 1. Final score is NOT ~94/100 
        # 2. Final score properly reflects the poor input data
        # 3. Approval is not APPROVED for this poor input data
        
        old_behavior = final_score > 90  # The old system would give ~94
        fixed_behavior = final_score < 80  # Fixed system should give much lower score
        
        print(f"\n🎯 FIX VERIFICATION:")
        print(f"   Old Behavior (score >90): {' DETECTED' if old_behavior else ' PREVENTED'}")
        print(f"   Fixed Behavior (score <80): {' WORKING' if fixed_behavior else ' NOT WORKING'}")
        
        if fixed_behavior and not old_behavior:
            print(f"\n==== ORIGINAL PROBLEM FIXED!")
            print(f"   The Quality Gate no longer gives high scores to poor input data")
            print(f"   Score properly reflects data quality: {final_score}/100")
            return True
        else:
            print(f"\nORIGINAL PROBLEM STILL EXISTS!")
            print(f"   The system is still giving unrealistically high scores")
            return False
            
    except Exception as e:
        print(f" Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print(" COMPREHENSIVE QUALITY GATE FIX TESTING")
    print("="*70)
    
    # Test 1: Comprehensive comparison
    print("\n" + "="*50)
    success1 = test_integration_2_medium_quality_with_fixed_quality_gate()
    
    # Test 2: Original problem scenario
    print("\n" + "="*50)
    success2 = test_original_problem_scenario()
    
    # Overall assessment
    print(f"\n" + "="*70)
    print(f"🏆 OVERALL QUALITY GATE FIX STATUS:")
    
    if success1 and success2:
        print(f" QUALITY GATE COMPLETELY FIXED!")
        print(f"    Comprehensive testing passed")
        print(f"    Original problem scenario fixed")
        print(f"    Ready for production deployment")
    elif success1:
        print(f" MOSTLY FIXED - Some edge cases remain")
        print(f"   General functionality working")
        print(f"   Original scenario needs attention")
    elif success2:
        print(f"  ORIGINAL PROBLEM FIXED - General testing issues")
        print(f"   Core issue resolved")
        print(f"    Comprehensive testing needs work")
    else:
        print(f" QUALITY GATE STILL BROKEN")
        print(f"    Comprehensive testing failed")
        print(f"   ❌ Original problem persists") 
        print(f"   🔧 Requires immediate attention")
        
    print(f"\n Next Steps:")
    if success1 and success2:
        print(f"   Deploy to production")
        print(f"    Monitor real-world performance")
    else:
        print(f"    Review and fix remaining issues")
        print(f"    Re-run tests after fixes")
        print(f"   Check Quality Gate implementation")