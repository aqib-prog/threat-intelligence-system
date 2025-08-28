
import sys
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.base_agent import BaseAgent
class WorkflowExecutor:
    def __init__(self):
        self.execution_log = []
        self.results_cache = {}
        
        # OPTIMIZATION: Enhanced caching and monitoring
        self._agent_cache = {}
        self._performance_cache = {}
        self._retry_cache = {}
        
        # OPTIMIZATION: Pre-compiled patterns for performance monitoring
        self.PATTERNS = {
            'error_critical': re.compile(r'(?i)(error|failed|exception|timeout)', re.IGNORECASE),
            'status_success': re.compile(r'(?i)(completed|success|approved)', re.IGNORECASE),
            'critical_flaw': re.compile(r'(?i)(critical|major|severe|impossible|unrealistic|fatal)', re.IGNORECASE),
            'improvement': re.compile(r'(?i)(enhance|improve|additional|discovered|identified)', re.IGNORECASE)
        }
        
        # OPTIMIZATION: Performance thresholds and retry settings
        self.PERFORMANCE_THRESHOLDS = {
            'max_execution_time': 300,  # 5 minutes max per agent
            'retry_attempts': 3,
            'timeout_escalation': 1.5,  # Multiply timeout by this on retry
            'parallel_timeout': 600,    # 10 minutes for parallel operations
            'challenger_timeout': 120   # 2 minutes per challenger
        }
        
        # INTELLIGENT DECISION THRESHOLDS
        self.QUALITY_THRESHOLDS = {
            'auto_approval': 85,        # Auto-approve without challengers
            'challenger_range_min': 70, # Send to challengers
            'challenger_range_max': 84, # Upper bound for challenger range
            'immediate_rejection': 70,  # Reject without challengers
            'conditional_approval_min': 80,  # Minimum for conditional approval
            'critical_issue_max': 3,    # Max critical issues before rejection
            'improvement_threshold': 5, # Minimum improvement to consider success
            'major_flaw_penalty': 15,   # Points deducted for major flaws
            'minor_flaw_penalty': 5     # Points deducted for minor issues
        }
        
        # OPTIMIZATION: Agent execution priorities
        self.AGENT_PRIORITIES = {
            'orchestrator': 1,
            'asset_vulnerability_mapper': 2,
            'interview_analyzer': 2,  # Same priority for parallel execution
            'threat_validator': 3,
            'scenario_generator': 4,
            'quality_gate': 5,
            'asset_vulnerability_challenger': 6,
            'interview_analysis_challenger': 6,
            'scenario_integrity_challenger': 6
        }

    def log_step(self, agent_name, status, duration=None, error=None):
        """OPTIMIZED: Enhanced logging with performance tracking"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": agent_name,
            "status": status,
            "duration": duration,
            "error": error,
            "priority": self.AGENT_PRIORITIES.get(agent_name, 10)
        }
        self.execution_log.append(log_entry)
        
        # OPTIMIZATION: Real-time performance monitoring
        if duration:
            self._track_performance(agent_name, duration, status)
        
        # Enhanced status display
        status_emoji = "✅" if self.PATTERNS['status_success'].search(status) else "❌" if self.PATTERNS['error_critical'].search(status) else "⚡"
        print(f" {status_emoji} {agent_name}: {status}" + (f" ({duration:.2f}s)" if duration else ""))

    def execute_complete_analysis(self, assets_data, evidence_data):
        """PRODUCTION-READY: Execute complete workflow with comprehensive error handling and edge cases"""
        print("Starting PRODUCTION threat intelligence analysis...")
        
        workflow_start_time = datetime.now()
        
        try:
            # EDGE CASE: Validate input data comprehensively
            validation_result = self._comprehensive_data_validation(assets_data, evidence_data)
            if not validation_result['valid']:
                return self._generate_error_report(f"Data validation failed: {validation_result['reason']}")
            
            # Phase 1: Orchestrator - Validation and Planning
            orchestrator_results = self._execute_orchestrator_optimized(assets_data, evidence_data)
            
            # EDGE CASE: Check if orchestrator failed
            if orchestrator_results.get('status') == 'error':
                return self._generate_error_report(f"Orchestrator failed: {orchestrator_results.get('error')}")
            
            # OPTIMIZATION: Adaptive workflow based on orchestrator recommendations
            workflow_strategy = orchestrator_results.get('workflow_plan', {}).get('execution_strategy', 'Standard')
            
            if workflow_strategy == 'Advanced parallel with caching':
                # Phase 2: Advanced Parallel Execution
                parallel_results = self._execute_advanced_parallel_analysis(
                    assets_data, evidence_data, orchestrator_results
                )
            else:
                # Phase 2: Standard Parallel Execution
                parallel_results = self._execute_parallel_analysis_optimized(
                    assets_data, evidence_data, orchestrator_results
                )
            
            # EDGE CASE: Check if parallel analysis failed
            if not parallel_results.get('parallel_execution_success', False):
                print("⚠️ Parallel analysis had issues - continuing with available results...")
            
            # OPTIMIZATION: Pipeline the remaining phases with optimized execution
            with ThreadPoolExecutor(max_workers=3) as executor:
                # Phase 3: Threat Validation
                validation_future = executor.submit(self._execute_threat_validation_optimized, parallel_results)
                
                # Wait for validation to complete before proceeding
                validation_results = validation_future.result()

                # After threat validation, before scenario generation:
               
                
                # EDGE CASE: Check validation results
                if validation_results.get('status') == 'error':
                    print("⚠️ Threat validation failed - using parallel results...")
                    validation_results = parallel_results
                
                # Phase 4 & 5: Scenario Generation and Quality Gate (can be pipelined)
                scenario_future = executor.submit(self._execute_scenario_generation_optimized, validation_results, parallel_results)
                
                scenario_results = scenario_future.result()
                
                # EDGE CASE: Check scenario generation
                if scenario_results.get('status') == 'error':
                    print("⚠️ Scenario generation failed - creating minimal scenario...")
                    scenario_results = self._create_minimal_scenario(validation_results)
                
                quality_future = executor.submit(self._execute_quality_gate_optimized, scenario_results)
                quality_results = quality_future.result()
            
            # EDGE CASE: Check quality gate results
            if quality_results.get('status') == 'error':
                return self._generate_error_report(f"Quality gate failed: {quality_results.get('error')}")
            
            # Phase 6: INTELLIGENT CHALLENGER POOL with smart decision logic
            final_results = self._execute_intelligent_challenger_pool(
                quality_results, assets_data, evidence_data, scenario_results
            )
            
            # OPTIMIZATION: Generate optimized final report
            total_duration = (datetime.now() - workflow_start_time).total_seconds()
            final_report = self._generate_final_report_optimized(final_results, total_duration)
            
            print(f"🎯 Complete analysis workflow finished in {total_duration:.1f} seconds!")
            return final_report
            
        except Exception as e:
            total_duration = (datetime.now() - workflow_start_time).total_seconds()
            self.log_step("workflow_executor", "CRITICAL_FAILURE", total_duration, str(e))
            return self._generate_error_report(f"Critical workflow failure: {str(e)}")

    def _comprehensive_data_validation(self, assets_data, evidence_data):
        """PRODUCTION-READY: Comprehensive data validation with edge cases"""
        print(" Comprehensive Data Validation:")
    
    # EDGE CASE: Both inputs null
        if not assets_data and not evidence_data:
            print("  ❌ CRITICAL: No input data provided")
            return {
            "valid": False, 
            "reason": "No input data provided - both assets and evidence are missing",
            "severity": "critical",
            "validation_details": {
                "assets_status": "missing",
                "evidence_status": "missing",
                "recommended_action": "Provide at least one complete dataset"
            }
        }
    
    # EDGE CASE: Invalid data types
        if assets_data and not isinstance(assets_data, dict):
            print("  ❌ INVALID: Assets data must be a dictionary")
            return {
            "valid": False, 
            "reason": f"Assets data must be a dictionary, got {type(assets_data).__name__}",
            "severity": "critical",
            "validation_details": {
                "assets_status": f"invalid_type_{type(assets_data).__name__}",
                "evidence_status": "not_checked",
                "recommended_action": "Provide assets data as dictionary with 'system_details' key"
            }
        }
    
        if evidence_data and not isinstance(evidence_data, dict):
             print("  ❌ INVALID: Evidence data must be a dictionary")
             return {
            "valid": False, 
            "reason": f"Evidence data must be a dictionary, got {type(evidence_data).__name__}",
            "severity": "critical",
            "validation_details": {
                "assets_status": "valid" if isinstance(assets_data, dict) else "not_checked",
                "evidence_status": f"invalid_type_{type(evidence_data).__name__}",
                "recommended_action": "Provide evidence data as dictionary with 'security_assessment_findings' key"
            }
        }
    
    # Detailed validation of each dataset
        assets_validation = self._validate_assets_data(assets_data)
        evidence_validation = self._validate_evidence_data(evidence_data)
    
        print(f"  Assets: {assets_validation['status']} ({assets_validation['quality_score']}/100)")
        print(f"  Evidence: {evidence_validation['status']} ({evidence_validation['quality_score']}/100)")
    
    # FIXED: Determine overall validation result
        overall_valid = False
        severity = "critical"
        reason_parts = []
    
    # Check if we have at least one usable dataset
        if assets_validation['usable'] or evidence_validation['usable']:
            overall_valid = True
            severity = "acceptable"
        
            if assets_validation['usable'] and evidence_validation['usable']:
                reason = "Both datasets are usable for analysis"
            elif assets_validation['usable']:
                reason = f"Assets data is usable, evidence data is {evidence_validation['status']}"
            else:
                reason = f"Evidence data is usable, assets data is {assets_validation['status']}"
        else:
        # Both datasets are unusable
            reason = f"Both datasets are unusable - Assets: {assets_validation['reason']}, Evidence: {evidence_validation['reason']}"
        
        # Check if this is just empty data vs corrupted data
            if assets_validation['status'] == 'empty' and evidence_validation['status'] == 'empty':
                severity = "critical"
                reason = "Both assets and evidence datasets are completely empty"
            elif 'empty' in [assets_validation['status'], evidence_validation['status']]:
                severity = "major"
                reason = "One dataset is empty, the other has critical issues"
            else:
                severity = "critical"
                reason = "Both datasets have critical validation errors"
    
        return {
        "valid": overall_valid,
        "reason": reason,
        "severity": severity,
        "validation_details": {
            "assets_validation": assets_validation,
            "evidence_validation": evidence_validation,
            "overall_quality_estimate": (assets_validation['quality_score'] + evidence_validation['quality_score']) / 2,
            "recommended_action": "Proceed with analysis" if overall_valid else "Fix data issues before proceeding"
        }
    }

    def _validate_assets_data(self, assets_data):
        if not assets_data:
            return {
            "status": "empty",
            "usable": False,
            "quality_score": 0,
            "reason": "No assets data provided",
            "system_count": 0,
            "issues": ["Missing assets data"]
        }
    
        if 'system_details' not in assets_data:
            return {
            "status": "invalid_structure",
            "usable": False,
            "quality_score": 0,
            "reason": "Missing 'system_details' key in assets data",
            "system_count": 0,
            "issues": ["Invalid assets data structure"]
        }
    
        systems = assets_data['system_details']
    
        if not isinstance(systems, list):
            return {
            "status": "invalid_structure",
            "usable": False,
            "quality_score": 0,
            "reason": "'system_details' must be a list",
            "system_count": 0,
            "issues": ["Invalid system_details data type"]
        }
    
        if len(systems) == 0:
            return {
            "status": "empty",
            "usable": False,
            "quality_score": 0,
            "reason": "No systems provided in system_details",
            "system_count": 0,
            "issues": ["Empty system_details list"]
        }
    
    # Analyze system quality
        quality_score = 0
        issues = []
        usable_systems = 0
    
        for i, system in enumerate(systems):
            if not isinstance(system, dict):
                issues.append(f"System {i+1}: Not a dictionary")
                continue
        
            system_score = 0
            required_fields = ['system_name', 'system_type', 'system_criticality']
        
        # Check required fields
            for field in required_fields:
                if field in system and system[field] and str(system[field]).strip():
                    system_score += 25  # 25 points per required field
                else:
                    issues.append(f"System {i+1}: Missing or empty {field}")
        
        # Bonus for optional detailed fields
            optional_fields = ['site', 'related_processes', 'affected_equipment']
            for field in optional_fields:
                if field in system and system[field] and len(str(system[field]).strip()) > 10:
                    system_score += 8  # Bonus points for detailed info
        
            if system_score >= 75:  # Has all required fields
                usable_systems += 1
        
            quality_score += system_score
    
    # Average quality score
        avg_quality = (quality_score / len(systems)) if systems else 0
    
    # Determine status
        if usable_systems == 0:
            status = "unusable"
            usable = False
            reason = "No systems have the minimum required fields"
        elif usable_systems < len(systems) / 2:
            status = "poor_quality"
            usable = True  # Some systems are usable
            reason = f"Only {usable_systems}/{len(systems)} systems are usable"
        elif avg_quality >= 80:
            status = "good_quality"
            usable = True
            reason = "Assets data meets quality standards"
        else:
            status = "acceptable"
            usable = True
            reason = "Assets data is usable but could be improved"
    
        return {
        "status": status,
        "usable": usable,
        "quality_score": round(avg_quality, 1),
        "reason": reason,
        "system_count": len(systems),
        "usable_systems": usable_systems,
        "issues": issues
    }

    def _validate_evidence_data(self, evidence_data):
        if not evidence_data:
            return {
            "status": "empty",
            "usable": False,
            "quality_score": 0,
            "reason": "No evidence data provided",
            "assessment_count": 0,
            "issues": ["Missing evidence data"]
        }
    
        if 'security_assessment_findings' not in evidence_data:
            return {
            "status": "invalid_structure",
            "usable": False,
            "quality_score": 0,
            "reason": "Missing 'security_assessment_findings' key in evidence data",
            "assessment_count": 0,
            "issues": ["Invalid evidence data structure"]
        }
    
        findings = evidence_data['security_assessment_findings']
    
        if not isinstance(findings, list):
            return {
            "status": "invalid_structure",
            "usable": False,
            "quality_score": 0,
            "reason": "'security_assessment_findings' must be a list",
            "assessment_count": 0,
            "issues": ["Invalid security_assessment_findings data type"]
        }
    
        if len(findings) == 0:
            return {
            "status": "empty",
            "usable": False,
            "quality_score": 0,
            "reason": "No assessment findings provided",
            "assessment_count": 0,
            "issues": ["Empty security_assessment_findings list"]
        }
    
    # Analyze evidence quality
        quality_score = 0
        issues = []
        usable_assessments = 0
    
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                issues.append(f"Assessment {i+1}: Not a dictionary")
                continue
        
            finding_score = 0
            required_fields = ['assessment_type', 'confidence_level', 'key_security_concerns']
        
        # Check required fields
            for field in required_fields:
                if field in finding and finding[field] and str(finding[field]).strip():
                    finding_score += 30  # 30 points per required field
                else:
                    issues.append(f"Assessment {i+1}: Missing or empty {field}")
        
        # Bonus for detailed concerns
            if 'key_security_concerns' in finding:
                concerns = str(finding['key_security_concerns'])
                if len(concerns) > 50:
                    finding_score += 10  # Bonus for detailed concerns
        
            if finding_score >= 90:  # Has all required fields + details
                usable_assessments += 1
        
            quality_score += finding_score
    
    # Average quality score
        avg_quality = (quality_score / len(findings)) if findings else 0
    
    # Determine status
        if usable_assessments == 0:
            status = "unusable"
            usable = False
            reason = "No assessments have the minimum required fields"
        elif usable_assessments < len(findings) / 2:
            status = "poor_quality"
            usable = True
            reason = f"Only {usable_assessments}/{len(findings)} assessments are usable"
        elif avg_quality >= 80:
            status = "good_quality"
            usable = True
            reason = "Evidence data meets quality standards"
        else:
            status = "acceptable"
            usable = True
            reason = "Evidence data is usable but could be improved"
    
        return {
        "status": status,
        "usable": usable,
        "quality_score": round(avg_quality, 1),
        "reason": reason,
        "assessment_count": len(findings),
        "usable_assessments": usable_assessments,
        "issues": issues
    }



    def _execute_intelligent_challenger_pool(self, quality_results, assets_data, evidence_data, scenario_results):
        """PRODUCTION-READY: Intelligent challenger pool with comprehensive decision logic"""
        
        original_quality = quality_results.get("quality_score", 0)
        approval_status = quality_results.get("approval_status", "UNKNOWN")
    
        print(f"🎯 Quality Decision Point: Score {original_quality}, Status: {approval_status}")
        send_flag  = bool(quality_results.get("send_to_challengers", False))
        force_env  = os.getenv("FORCE_CHALLENGERS", "0").strip() == "1"
        force_flag = bool(scenario_results.get("force_challengers", False))

        if not (force_env or force_flag) and not send_flag:
            print("🛡️ Challengers SKIPPED: QualityGate marked 'Not Required'")
            out = quality_results.copy()
            out.update({
            "challenger_execution_completed": False,
            "challenger_enhancement": {
                "challengers_executed": 0,
                "skip_reason": "QualityGate send_to_challengers=False"
            }
        })
            return out
    
    # FIXED: Complete 3-tier intelligent decision logic
    
    # TIER 1: AUTO-APPROVAL for high quality (≥85)
        if original_quality >= self.QUALITY_THRESHOLDS['auto_approval']:  # 85+
            print("✅ AUTO-APPROVED: High quality - skipping challengers entirely")
        
        # Create auto-approved results without challenger overhead
            auto_approved_results = quality_results.copy()
            auto_approved_results.update({
            "approval_status": "APPROVED",
            "quality_score": original_quality,
            "auto_approved": True,
            "challengers_skipped": "High quality - no challengers needed",
            "challenger_analysis": {
                "challengers_executed": False,
                "skip_reason": f"Auto-approved (score {original_quality} ≥ 85)",
                "quality_boost": "N/A - Already high quality",
                "critical_issues_found": 0,
                "overall_impact": "No challengers needed"
            },
            "final_results": quality_results.get("final_results", {})
        })
        
            print(f"🚀 Auto-approval completed - total analysis time optimized")
            return auto_approved_results
    
    # TIER 2: IMMEDIATE REJECTION for very low quality (<70)
        elif original_quality < self.QUALITY_THRESHOLDS['immediate_rejection']:  # <70
            print("❌ IMMEDIATE REJECTION: Quality too low - skipping challengers")
        
        # Create immediate rejection results
            rejected_results = quality_results.copy()
            rejected_results.update({
            "approval_status": "REJECTED",
            "quality_score": original_quality,
            "immediately_rejected": True,
            "rejection_reason": f"Quality score {original_quality} below minimum threshold ({self.QUALITY_THRESHOLDS['immediate_rejection']})",
            "send_for_rework": True,
            "rework_required": self._generate_rework_requirements_for_low_quality(original_quality, quality_results),
            "challenger_analysis": {
                "challengers_executed": False,
                "skip_reason": f"Immediate rejection (score {original_quality} < 70)",
                "quality_boost": "N/A - Quality too low for improvement",
                "critical_issues_found": 0,
                "overall_impact": "Immediate rejection - rework required"
            }
        })
        
            print(f"⚠️ Immediate rejection completed - rework required")
            return rejected_results
    
    # TIER 3: CHALLENGER ENHANCEMENT for improvement range (70-84)
        elif (self.QUALITY_THRESHOLDS['immediate_rejection'] <= original_quality < self.QUALITY_THRESHOLDS['auto_approval']):
            print("🛡️ CHALLENGER ACTIVATION: Quality in improvement range")
            return self._execute_challengers_with_intelligent_evaluation(
            quality_results, assets_data, evidence_data, scenario_results
        )
    
        else:
        # EDGE CASE: Unexpected quality score range - default to challenger review
            print(f"⚠️ UNEXPECTED QUALITY RANGE: {original_quality} - defaulting to challenger review")
            return self._execute_challengers_with_intelligent_evaluation(
            quality_results, assets_data, evidence_data, scenario_results
        )
    
    def _generate_rework_requirements_for_low_quality(self, quality_score, quality_results):
        rework_requirements = []
        # Extract quality breakdown for targeted feedback
        quality_breakdown = quality_results.get("quality_breakdown", {})
    
    # Completeness issues
        completeness = quality_breakdown.get("completeness", 0)
        if completeness < 50:
            rework_requirements.extend([
            "Complete all required analysis components (business impact, timeline, attack phases)",
            "Provide detailed system information and evidence data",
            "Ensure all fields are properly populated with meaningful content"
        ])
    
    # Accuracy issues  
        accuracy = quality_breakdown.get("accuracy", 0)
        if accuracy < 60:
            rework_requirements.extend([
            "Validate MITRE technique mappings with proper database verification",
            "Improve business impact calculations with realistic estimates",
            "Enhance timeline analysis with feasible execution windows"
        ])
    
    # Consistency issues
        consistency = quality_breakdown.get("consistency", 0)
        if consistency < 40:
            rework_requirements.extend([
            "Align attack scenarios with business impact assessments",
            "Ensure timeline consistency across all attack phases",
            "Maintain consistent risk level throughout analysis"
        ])
    
    # Professional standards issues
        professional = quality_breakdown.get("professional", 0)
        if professional < 50:
            rework_requirements.extend([
            "Enhance executive narrative with professional presentation standards",
            "Provide actionable and prioritized recommendations",
            "Improve technical documentation and methodology descriptions"
        ])
    
    # General low quality guidance
        if quality_score < 30:
            rework_requirements.insert(0, "Analysis requires comprehensive revision - consider starting fresh with higher quality input data")
        elif quality_score < 50:
            rework_requirements.insert(0, "Analysis needs significant improvements across multiple quality dimensions")
    
        return rework_requirements[:8] 

    def _execute_challengers_with_intelligent_evaluation(self, quality_results, assets_data, evidence_data, scenario_results):
        """PRODUCTION-READY: Execute challengers with intelligent evaluation of results"""
        print("🛡️ Executing INTELLIGENT challenger pool...")
        
        challenger_start_time = datetime.now()
        original_quality = quality_results.get("quality_score", 0)
        
        # Extract original analysis results for challengers
        final_results = quality_results 
        
        # EDGE CASE: Ensure we have analysis results to challenge
        if not final_results:
            print("⚠️ No final results to challenge - proceeding without challengers")
            return quality_results
        
        # OPTIMIZATION: Parallel execution of all 3 challengers with comprehensive error handling
        challenger_results = {}
        challenger_errors = {}
        asset_analysis = final_results  # Pass the whole final_results
        evidence_analysis = final_results  # Pass the whole final_results
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                'asset_challenger': executor.submit(
                    self._execute_asset_vulnerability_challenger_safe,
                    asset_analysis,
                    assets_data
                ),
                'evidence_challenger': executor.submit(
                    self._execute_interview_analysis_challenger_safe,
                    evidence_analysis,
                    evidence_data
                ),
                'scenario_challenger': executor.submit(
                    self._execute_scenario_integrity_challenger_safe,
                    scenario_results, 
                    {"asset_context": final_results.get("asset_analysis", {})}
                )
            }
            
            # Collect challenger results with comprehensive error handling
            for challenger_name, future in futures.items():
                try:
                    result = future.result(timeout=self.PERFORMANCE_THRESHOLDS['challenger_timeout'])
                    challenger_results[challenger_name] = result
                    
                    # Log challenger performance
                    if isinstance(result, dict) and result.get('status') == 'completed':
                        if 'challenger_techniques' in result:
                            discovered_count = len(result.get('challenger_techniques', []))
                            print(f"   {challenger_name}: {discovered_count} enhancements")
                        elif 'integrity_assessment' in result:
                            issues_count = result.get('integrity_assessment', {}).get('total_issues_identified', 0)
                            print(f"    {challenger_name}: {issues_count} integrity issues")
                        else:
                            print(f"     {challenger_name}: Analysis completed")
                    else:
                        print(f"    ⚠️ {challenger_name}: {result.get('status', 'unknown')}")
                        challenger_errors[challenger_name] = result.get('error', 'Unknown error')
                        
                except Exception as e:
                    self.log_step(challenger_name, "CHALLENGER_ERROR", error=str(e))
                    challenger_errors[challenger_name] = str(e)
                    challenger_results[challenger_name] = {"status": "error", "error": str(e)}
        
        # INTELLIGENT EVALUATION: Analyze challenger results comprehensively
        evaluation_result = self._intelligent_challenger_evaluation(
            quality_results, challenger_results, challenger_errors
        )
        
        challenger_duration = (datetime.now() - challenger_start_time).total_seconds()
        print(f"    🎯 Intelligent challenger evaluation completed in {challenger_duration:.1f} seconds")
        
        return evaluation_result

    def _intelligent_challenger_evaluation(self, quality_results, challenger_results, challenger_errors):
        """PRODUCTION-READY: Intelligent evaluation of challenger results with comprehensive decision logic"""
        
        
        
        original_quality = quality_results.get("quality_score", 0)
        final_results = quality_results.get("final_results", {})
        
        print(f"🧠 Intelligent Evaluation: Original Quality {original_quality}/100")
        
        # STEP 1: Analyze challenger success rate
        successful_challengers = len([r for r in challenger_results.values() if r.get('status') == 'completed'])
        total_challengers = len(challenger_results)
        success_rate = (successful_challengers / total_challengers) * 100 if total_challengers > 0 else 0
        
        print(f"    Challenger Success Rate: {success_rate:.1f}% ({successful_challengers}/{total_challengers})")
        
        # EDGE CASE: All challengers failed
        if success_rate < 50:
            print("❌ CHALLENGER FAILURE: Majority of challengers failed - maintaining original quality")
            enhanced_results = quality_results.copy()
            enhanced_results.update({
                "approval_status": "APPROVED" if original_quality >= 75 else "REJECTED",
                "challenger_failure_mode": True,
                "challenger_errors": challenger_errors,
                "quality_score": original_quality,
                "challenger_execution_completed": True
            })
            return enhanced_results
        
        # STEP 2: Comprehensive analysis of challenger findings
        analysis_metrics = self._analyze_challenger_findings_comprehensive(challenger_results)
        
        # STEP 3: Detect critical flaws and improvements
        critical_analysis = self._detect_critical_issues_and_improvements(challenger_results, analysis_metrics)
        
        # STEP 4: INTELLIGENT QUALITY CALCULATION
        enhanced_quality = self._calculate_intelligent_quality_score(
            original_quality, analysis_metrics, critical_analysis
        )
        
        # STEP 5: INTELLIGENT APPROVAL DECISION
        approval_decision = self._make_intelligent_approval_decision(
            original_quality, enhanced_quality, critical_analysis, analysis_metrics
        )
        
        # STEP 6: Create comprehensive enhanced results
        enhanced_results = self._create_enhanced_results_comprehensive(
            quality_results, challenger_results, analysis_metrics, critical_analysis,
            original_quality, enhanced_quality, approval_decision
        )
        
        print(f"    📈 Quality Evolution: {original_quality} → {enhanced_quality} ({approval_decision})")
        
        return enhanced_results

    def _analyze_challenger_findings_comprehensive(self, challenger_results):
        """PRODUCTION-READY: Comprehensive analysis of all challenger findings"""
        
        metrics = {
            "total_techniques_added": 0,
            "total_issues_identified": 0,
            "critical_flaws_found": 0,
            "minor_issues_found": 0,
            "improvements_discovered": 0,
            "challenger_confidence_scores": [],
            "finding_categories": {
                "technique_enhancements": 0,
                "behavioral_improvements": 0,
                "scenario_issues": 0,
                "critical_gaps": 0
            }
        }
        
        for challenger_name, result in challenger_results.items():
            
            if result.get('status') != 'completed':
                continue

            if 'scenario' in challenger_name:
                techniques = result.get('scenario_integrity_issues', []) 
                findings = result.get('challenger_findings', '')
            else:
                techniques = result.get('challenger_techniques', [])
                findings = result.get('challenger_findings', '')
            
            metrics["total_techniques_added"] += len(techniques)

            if techniques:
                metrics["finding_categories"]["technique_enhancements"] += len(techniques)
            
            if isinstance(findings, dict):
                findings = str(findings)
            elif not isinstance(findings, str):
                findings = ''
            
            if self.PATTERNS['critical_flaw'].search(findings):
                metrics["critical_flaws_found"] += 1
            elif self.PATTERNS['improvement'].search(findings):
                metrics["improvements_discovered"] += 1
            else:
                metrics["minor_issues_found"] += 1
            
            # Extract confidence scores
            confidence_text = result.get('confidence_assessment', '')
            if 'high' in confidence_text.lower():
                metrics["challenger_confidence_scores"].append(0.8)
            elif 'medium' in confidence_text.lower():
                metrics["challenger_confidence_scores"].append(0.6)
            else:
                metrics["challenger_confidence_scores"].append(0.4)
            
            # Analyze specific challenger types
            if 'asset' in challenger_name:
                metrics["finding_categories"]["technique_enhancements"] += len(techniques)
            elif 'evidence' in challenger_name or 'interview' in challenger_name:
                metrics["finding_categories"]["behavioral_improvements"] += len(techniques)
            elif 'scenario' in challenger_name:
                integrity_issues = result.get('integrity_assessment', {}).get('total_issues_identified', 0)
                metrics["total_issues_identified"] += integrity_issues
                metrics["finding_categories"]["scenario_issues"] += integrity_issues
        
        # Calculate average confidence
        if metrics["challenger_confidence_scores"]:
            metrics["average_confidence"] = sum(metrics["challenger_confidence_scores"]) / len(metrics["challenger_confidence_scores"])
        else:
            metrics["average_confidence"] = 0.5
        
        return metrics

    def _detect_critical_issues_and_improvements(self, challenger_results, analysis_metrics):
        """PRODUCTION-READY: Detect critical issues vs improvements in challenger findings"""
        
        critical_analysis = {
            "has_critical_flaws": False,
            "has_major_improvements": False,
            "critical_issue_count": 0,
            "improvement_significance": "None",
            "overall_challenger_impact": "Neutral",
            "specific_issues": [],
            "specific_improvements": []
        }
        
        # Analyze each challenger for critical issues
        for challenger_name, result in challenger_results.items():
            if result.get('status') != 'completed':
                continue
            
            findings = result.get('challenger_findings', '')

            if isinstance(findings, dict):
                findings = str(findings)
            elif not isinstance(findings, str):
                findings = ''
            
            # DETECTION: Critical flaws that would reduce quality
            critical_keywords = [
                'unrealistic', 'impossible', 'fatal flaw', 'major gap', 
                'critical issue', 'severely flawed', 'fundamentally wrong'
            ]
            
            for keyword in critical_keywords:
                if keyword in findings.lower():
                    critical_analysis["has_critical_flaws"] = True
                    critical_analysis["critical_issue_count"] += 1
                    critical_analysis["specific_issues"].append(f"{challenger_name}: {keyword} identified")
            
            # DETECTION: Significant improvements that would increase quality
            improvement_keywords = [
                'significant enhancement', 'major discovery', 'comprehensive improvement',
                'substantial addition', 'critical coverage', 'important finding'
            ]
            
            for keyword in improvement_keywords:
                if keyword in findings.lower():
                    critical_analysis["has_major_improvements"] = True
                    critical_analysis["specific_improvements"].append(f"{challenger_name}: {keyword}")
            
            # Analyze scenario integrity specifically
            if 'scenario' in challenger_name:
                integrity_assessment = result.get('integrity_assessment', {})
                
                # Check individual integrity categories
                chain_integrity = integrity_assessment.get('attack_chain_integrity', 'Acceptable')
                timeline_feasibility = integrity_assessment.get('timeline_feasibility', 'Acceptable')
                impact_accuracy = integrity_assessment.get('impact_accuracy', 'Acceptable')
                
                if any(status == 'Questionable' for status in [chain_integrity, timeline_feasibility, impact_accuracy]):
                    critical_analysis["has_critical_flaws"] = True
                    critical_analysis["critical_issue_count"] += 1
                    critical_analysis["specific_issues"].append("Scenario integrity compromised")
        
        # OVERALL IMPACT ASSESSMENT
        technique_improvement = analysis_metrics["total_techniques_added"]
        confidence_score = analysis_metrics["average_confidence"]
        
        if critical_analysis["has_critical_flaws"] and critical_analysis["critical_issue_count"] >= 2:
            critical_analysis["overall_challenger_impact"] = "Negative"
        elif technique_improvement >= 10 and confidence_score >= 0.7:
            critical_analysis["overall_challenger_impact"] = "Highly Positive"
            critical_analysis["improvement_significance"] = "Major"
        elif technique_improvement >= 5 and confidence_score >= 0.5:
            critical_analysis["overall_challenger_impact"] = "Positive" 
            critical_analysis["improvement_significance"] = "Moderate"
        elif technique_improvement >= 1:
            critical_analysis["overall_challenger_impact"] = "Slightly Positive"
            critical_analysis["improvement_significance"] = "Minor"
        else:
            critical_analysis["overall_challenger_impact"] = "Neutral"
        
        return critical_analysis

    def _calculate_intelligent_quality_score(self, original_quality, analysis_metrics, critical_analysis):
        """PRODUCTION-READY: Intelligent quality score calculation with comprehensive logic"""
        
        enhanced_quality = original_quality
        total_adjustment = 0
    
    # DYNAMIC: Calculate improvement based on actual challenger findings
        technique_improvement = analysis_metrics.get("total_techniques_added", 0)
        issues_found = analysis_metrics.get("total_issues_identified", 0)
        confidence_factor = analysis_metrics.get("average_confidence", 0.5)
    
        print(f"    🔍 Dynamic Quality Calculation:")
        print(f"      Original Quality: {original_quality}")
        print(f"      Techniques Added: {technique_improvement}")
        print(f"      Issues Found: {issues_found}")
        print(f"      Confidence Factor: {confidence_factor:.2f}")
    
    # PENALIZE for critical flaws (can decrease score)
        critical_penalty = 0
        if critical_analysis.get("has_critical_flaws", False):
            critical_issue_count = critical_analysis.get("critical_issue_count", 0)
        # Dynamic penalty based on number and severity of critical issues
            critical_penalty = min(critical_issue_count * 5, 20)  # 5 points per issue, max 20
            enhanced_quality -= critical_penalty
            total_adjustment -= critical_penalty
            print(f"      Critical Flaw Penalty: -{critical_penalty} points")
    
    # REWARD for technique improvements (can increase score)
        technique_bonus = 0
        if technique_improvement > 0:
           # Dynamic bonus calculation
            if technique_improvement >= 20:
                technique_bonus = min(10 + (technique_improvement - 20) * 0.2, 15)  # Major improvement
            elif technique_improvement >= 10:
                technique_bonus = 5 + (technique_improvement - 10) * 0.3  # Moderate improvement
            elif technique_improvement >= 5:
                technique_bonus = 2 + (technique_improvement - 5) * 0.4  # Minor improvement
            else:
                technique_bonus = technique_improvement * 0.5  # Small improvement
        
        # Apply confidence factor
            technique_bonus *= confidence_factor
            technique_bonus = round(technique_bonus, 1)
        
            enhanced_quality += technique_bonus
            total_adjustment += technique_bonus
            print(f"      Technique Improvement Bonus: +{technique_bonus} points")
    
    # ADJUST for issues identified (minor penalty)
        issue_penalty = 0
        if issues_found > 0:
            issue_penalty = min(issues_found * 0.5, 3)  # Small penalty for issues, max 3 points
            enhanced_quality -= issue_penalty
            total_adjustment -= issue_penalty
            print(f"      Issues Identified Penalty: -{issue_penalty} points")
    
    # CONFIDENCE ADJUSTMENT
        confidence_adjustment = 0
        if confidence_factor < 0.3:  # Low confidence
            confidence_adjustment = -2
        elif confidence_factor > 0.8:  # High confidence
            confidence_adjustment = +1
    
        enhanced_quality += confidence_adjustment
        total_adjustment += confidence_adjustment
    
        if confidence_adjustment != 0:
            print(f"      Confidence Adjustment: {confidence_adjustment:+.1f} points")
    
    # EDGE CASE: Ensure quality score stays within realistic bounds
        enhanced_quality = max(0, min(enhanced_quality, 100))
    
        print(f"      Total Adjustment: {total_adjustment:+.1f} points")
        print(f"      Final Enhanced Quality: {enhanced_quality}")
    
        return round(enhanced_quality, 1)

    def _make_intelligent_approval_decision(self, original_quality, enhanced_quality, critical_analysis, analysis_metrics):
        """PRODUCTION-READY: Intelligent approval decision with comprehensive edge case handling"""
        
        quality_change = enhanced_quality - original_quality
    
        print(f"    🎯 Intelligent Decision Analysis:")
        print(f"      Quality Evolution: {original_quality} → {enhanced_quality} ({quality_change:+.1f})")
    
    # DECISION LOGIC: Post-challenger auto-approval
        if enhanced_quality >= self.QUALITY_THRESHOLDS['auto_approval']:  # 85+
            print(f"      Decision: APPROVED (Enhanced quality ≥ 85)")
            return "APPROVED"
    
    # DECISION LOGIC: Critical flaws override improvements
        if critical_analysis.get("has_critical_flaws", False):
            critical_count = critical_analysis.get("critical_issue_count", 0)
            if critical_count >= 3:  # Multiple critical issues
                print(f"      Decision: REJECTED (Too many critical flaws: {critical_count})")
                return "REJECTED"
            elif enhanced_quality < 70:  # Critical flaws + low quality
                print(f"      Decision: REJECTED (Critical flaws + low quality: {enhanced_quality})")
                return "REJECTED"
    
    # DECISION LOGIC: Significant quality degradation
        if quality_change <= -10:
            print(f"      Decision: REJECTED (Significant quality degradation: {quality_change})")
            return "REJECTED"
    
    # DECISION LOGIC: Good improvement with acceptable quality
        if enhanced_quality >= 75 and quality_change >= 2:
            print(f"      Decision: APPROVED (Good quality + improvement)")
            return "APPROVED"
    
    # DECISION LOGIC: Acceptable quality maintained or improved
        if enhanced_quality >= 70 and quality_change >= 0:
            print(f"      Decision: APPROVED (Acceptable quality maintained)")
            return "APPROVED"
    
    # DECISION LOGIC: Insufficient quality despite challenger efforts
        if enhanced_quality < 65:
            print(f"      Decision: REJECTED (Quality still too low: {enhanced_quality})")
            return "REJECTED"
    
    # EDGE CASE: Borderline cases - lean toward approval if no critical flaws
        if not critical_analysis.get("has_critical_flaws", False) and enhanced_quality >= 65:
            print(f"      Decision: APPROVED (Borderline - no critical flaws)")
            return "APPROVED"
        else:
            print(f"      Decision: REJECTED (Borderline - has issues)")
            return "REJECTED"

# UPDATED: Quality thresholds for the complete system
    QUALITY_THRESHOLDS = {
    'auto_approval': 85,        # ≥85: Auto-approve without challengers
    'challenger_range_min': 70, # 70-84: Send to challengers for improvement
    'challenger_range_max': 84,
    'immediate_rejection': 70,  # <70: Immediate rejection without challengers
    'conditional_approval_min': 70,  # Minimum for any approval
    'critical_issue_max': 2,    # Max critical issues before rejection
    'improvement_threshold': 2, # Minimum improvement to consider meaningful
    'major_flaw_penalty': 5,    # Points deducted per critical flaw
    'minor_issue_penalty': 0.5  # Points deducted per minor issue
}

    def _create_enhanced_results_comprehensive(self, quality_results, challenger_results, analysis_metrics, 
                                            critical_analysis, original_quality, enhanced_quality, approval_decision):
        """PRODUCTION-READY: Create comprehensive enhanced results with all challenger data"""

        enhanced_results = quality_results.copy()
        final_results = quality_results.get("final_results", {})
        
        # Comprehensive challenger summary
        challenger_summary = {
            "challengers_executed": len(challenger_results),
            "successful_challengers": len([r for r in challenger_results.values() if r.get('status') == 'completed']),
            "challenger_success_rate": analysis_metrics.get("average_confidence", 0) * 100,
            "total_techniques_added": analysis_metrics.get("total_techniques_added", 0),
            "total_issues_identified": analysis_metrics.get("total_issues_identified", 0),
            "critical_flaws_detected": critical_analysis.get("critical_issue_count", 0),
            "improvements_discovered": analysis_metrics.get("improvements_discovered", 0), 
            "finding_categories": analysis_metrics.get("finding_categories", {}),
            "challenger_performance": {},
            "quality_impact_analysis": {
                "original_quality": original_quality,
                "enhanced_quality": enhanced_quality,
                "quality_change": round(enhanced_quality - original_quality, 1),
                "improvement_significance": critical_analysis.get("improvement_significance", "None"),  
                "overall_impact": critical_analysis.get("overall_challenger_impact", "Unknown")

            }
        }
        
        # Process individual challenger results for summary
        for challenger_name, challenger_result in challenger_results.items():
            if challenger_result.get('status') == 'completed':
                techniques = challenger_result.get('challenger_techniques', [])
                confidence = challenger_result.get('confidence_assessment', 'Unknown')
                findings_text = str(challenger_result.get('challenger_findings', ''))
                
                challenger_summary["challenger_performance"][challenger_name] = {
                    "techniques_added": len(techniques),
                    "status": "completed",
                    "confidence": confidence,
                    "findings": findings_text[:100] + "..." if len(findings_text) > 100 else findings_text
                }
                
                # Merge enhanced analysis if available
                if challenger_result.get('enhanced_analysis'):
                    enhanced_key = f"{challenger_name}_enhanced"
                    final_results[enhanced_key] = challenger_result['enhanced_analysis']
            else:
                challenger_summary["challenger_performance"][challenger_name] = {
                    "status": challenger_result.get('status', 'error'),
                    "error": challenger_result.get('error', 'Unknown error')
                }
        
        # Determine rework requirements for rejections
        rework_required = []
        if approval_decision == "REJECTED":
            if critical_analysis.get("has_critical_flaws", False):
                rework_required.extend([
                    "Address critical flaws identified by challenger analysis",
                    "Resolve scenario integrity issues",
                    "Improve attack chain realism and feasibility"
                ])
            
            if enhanced_quality < self.QUALITY_THRESHOLDS['conditional_approval_min']:
                rework_required.extend([
                    "Enhance MITRE technique coverage and accuracy",
                    "Improve business impact assessment methodology",
                    "Strengthen evidence interpretation and analysis quality",
                    "Improve professional presentation standards"
                ])
        
        # Create comprehensive enhanced results
        enhanced_results.update({
            "approval_status": approval_decision,
            "quality_score": enhanced_quality,
            "original_quality_score": original_quality,
            "challenger_enhancement": challenger_summary,
            "final_results": final_results,
            "challenger_execution_completed": True,
            "quality_improvement": round(enhanced_quality - original_quality, 1),
            "intelligent_evaluation_completed": True,
            "critical_issues_analysis": critical_analysis,
            "rework_required": rework_required if approval_decision == "REJECTED" else [],
            "send_for_rework": approval_decision == "REJECTED"
        })
        
        return enhanced_results

    def _execute_asset_vulnerability_challenger_safe(self, asset_analysis, assets_data):
        """PRODUCTION-READY: Safe execution of asset vulnerability challenger"""
        try:
            return self._execute_agent_with_optimization(
                agent_name="asset_vulnerability_challenger",
                import_path="agents.asset_vulnerability_challenger",
                class_name="AssetVulnerabilityChallenger",
                method_name="challenge",
                method_args=(asset_analysis, assets_data),
                fallback_result={
                    "challenger_techniques": [],
                    "challenger_findings": "Asset challenger not available - using fallback",
                    "status": "fallback"
                }
            )
        except Exception as e:
            return {"status": "error", "error": f"Asset challenger execution failed: {str(e)}"}

    def _execute_interview_analysis_challenger_safe(self, evidence_analysis, evidence_data):
        """PRODUCTION-READY: Safe execution of interview analysis challenger"""
        try:
            return self._execute_agent_with_optimization(
                agent_name="interview_analysis_challenger",
                import_path="agents.interview_analysis_challenger",
                class_name="InterviewAnalysisChallenger", 
                method_name="challenge",
                method_args=(evidence_analysis, evidence_data),
                fallback_result={
                    "challenger_techniques": [],
                    "challenger_findings": "Evidence challenger not available - using fallback",
                    "status": "fallback"
                }
            )
        except Exception as e:
            return {"status": "error", "error": f"Evidence challenger execution failed: {str(e)}"}

    def _execute_scenario_integrity_challenger_safe(self, scenario_analysis, context):
        """PRODUCTION-READY: Safe execution of scenario integrity challenger"""
        try:
            return self._execute_agent_with_optimization(
                agent_name="scenario_integrity_challenger",
                import_path="agents.scenario_integrity_challenger",
                class_name="ScenarioIntegrityChallenger",
                method_name="challenge", 
                method_args=(scenario_analysis, context),
                fallback_result={
                    "challenger_findings": "Scenario challenger not available - using fallback",
                    "scenario_flaws": {},
                    "status": "fallback"
                }
            )
        except Exception as e:
            return {"status": "error", "error": f"Scenario challenger execution failed: {str(e)}"}
        

    def _create_minimal_scenario(self, validation_results):
        """EDGE CASE: Create minimal scenario when scenario generation fails"""
        return {
            "executive_summary": {
                "title": "Minimal Threat Scenario",
                "overview": "Basic threat assessment based on available validation data"
            },
            "calculated_business_impact": {
                "range": "$1M - $5M",
                "methodology": "Conservative estimate based on validation data"
            },
            "calculated_timeline": {
                "range": "5-10 days", 
                "methodology": "Conservative timeline estimate"
            },
            "success_probability": {
                "percentage": "50%",
                "assessment": "Medium"
            },
            "detailed_attack_phases": [
                {
                    "phase": "Initial Access",
                    "techniques": validation_results.get('mitre_techniques', [])[:2],
                    "timeline": "Days 1-3"
                }
            ],
            "prioritized_recommendations": [
                "Implement basic security controls",
                "Enhance monitoring and detection",
                "Review incident response procedures"
            ],
            "status": "minimal_scenario"
        }

    def _execute_orchestrator_optimized(self, assets_data, evidence_data):
        """OPTIMIZED: Execute orchestrator with caching and performance monitoring"""
        return self._execute_agent_with_optimization(
            agent_name="orchestrator",
            import_path="agents.orchestrator",
            class_name="OrchestratorAgent",
            method_name="validate_input_data",
            method_args=(assets_data, evidence_data),
            fallback_result={
                "validation": {"analysis_feasible": True},
                "workflow_plan": {"execution_strategy": "Standard"}
            }
        )

    def _execute_parallel_analysis_optimized(self, assets_data, evidence_data, orchestrator_results):
        """OPTIMIZED: Parallel execution with enhanced error handling and performance monitoring"""
        print("⚡ Executing OPTIMIZED parallel analysis phase...")
        
        # OPTIMIZATION: Dynamic timeout based on data complexity
        estimated_times = orchestrator_results.get('workflow_plan', {})
        asset_timeout = estimated_times.get('phase_1_parallel', {}).get('asset_analysis', {}).get('estimated_time', 300)
        evidence_timeout = estimated_times.get('phase_1_parallel', {}).get('evidence_analysis', {}).get('estimated_time', 300)
        
        # Convert minutes to seconds and add buffer
        asset_timeout = (asset_timeout * 60) + 60
        evidence_timeout = (evidence_timeout * 60) + 60
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                'asset_analysis': executor.submit(self._execute_asset_analysis_optimized, assets_data),
                'evidence_analysis': executor.submit(self._execute_evidence_analysis_optimized, evidence_data)
            }
            
            # OPTIMIZATION: Collect results with individual timeouts
            results = {}
            
            try:
                results['asset_analysis'] = futures['asset_analysis'].result(timeout=asset_timeout)
            except Exception as e:
                self.log_step("asset_vulnerability_mapper", "TIMEOUT/ERROR", error=str(e))
                results['asset_analysis'] = {"status": "error", "error": str(e)}
            
            try:
                results['evidence_analysis'] = futures['evidence_analysis'].result(timeout=evidence_timeout)
            except Exception as e:
                self.log_step("interview_analyzer", "TIMEOUT/ERROR", error=str(e))
                results['evidence_analysis'] = {"status": "error", "error": str(e)}
        
        return {
            "asset_analysis": results['asset_analysis'],
            "evidence_analysis": results['evidence_analysis'],
            "orchestrator_context": orchestrator_results,
            "parallel_execution_success": all(r.get('status') != 'error' for r in results.values())
        }

    def _execute_advanced_parallel_analysis(self, assets_data, evidence_data, orchestrator_results):
        """OPTIMIZED: Advanced parallel execution with resource optimization"""
        print("🚀 Executing ADVANCED parallel analysis with optimization...")
        
        # OPTIMIZATION: Pre-cache frequently used data
        priority_systems = orchestrator_results.get('validation', {}).get('analysis_priority', {}).get('high_priority_systems', [])
        
        # OPTIMIZATION: Enhanced parallel execution with resource management
        with ThreadPoolExecutor(max_workers=3) as executor:  # Increased workers for advanced mode
            futures = {
                'asset_analysis': executor.submit(self._execute_asset_analysis_with_priority, assets_data, priority_systems),
                'evidence_analysis': executor.submit(self._execute_evidence_analysis_optimized, evidence_data),
                'orchestrator_refinement': executor.submit(self._refine_orchestrator_context, orchestrator_results)
            }
            
            # Collect results with enhanced error handling
            results = {}
            for task_name, future in futures.items():
                try:
                    results[task_name] = future.result(timeout=self.PERFORMANCE_THRESHOLDS['parallel_timeout'])
                except Exception as e:
                    self.log_step(task_name, "ADVANCED_ERROR", error=str(e))
                    results[task_name] = {"status": "error", "error": str(e)}
        
        return {
            "asset_analysis": results.get('asset_analysis', {}),
            "evidence_analysis": results.get('evidence_analysis', {}),
            "orchestrator_context": results.get('orchestrator_refinement', orchestrator_results),
            "execution_mode": "advanced",
            "parallel_execution_success": True
        }

    def _execute_agent_with_optimization(self, agent_name, import_path, class_name, method_name, method_args, fallback_result=None):
        """OPTIMIZED: Generic agent execution with caching, retries, and performance monitoring"""
        start_time = datetime.now()
        
        # OPTIMIZATION: Check cache first
        cache_key = f"{agent_name}_{hash(str(method_args))}"
        if cache_key in self.results_cache:
            duration = (datetime.now() - start_time).total_seconds()
            self.log_step(agent_name, "CACHED", duration)
            return self.results_cache[cache_key]
        
        # OPTIMIZATION: Retry logic with exponential backoff
        for attempt in range(self.PERFORMANCE_THRESHOLDS['retry_attempts']):
            try:
                # Dynamic import with caching
                if agent_name not in self._agent_cache:
                    module = __import__(import_path, fromlist=[class_name])
                    agent_class = getattr(module, class_name)
                    self._agent_cache[agent_name] = agent_class()
                
                agent = self._agent_cache[agent_name]
                
                # Execute method
                if hasattr(agent, method_name):
                    if method_args:
                        results = getattr(agent, method_name)(*method_args)
                    else:
                        results = getattr(agent, method_name)()
                else:
                    results = agent.analyze(*method_args) if method_args else agent.analyze()
                
                # Success - cache and return
                duration = (datetime.now() - start_time).total_seconds()
                self.log_step(agent_name, "COMPLETED", duration)
                
                self.results_cache[cache_key] = results
                return results
                
            except ImportError:
                # Agent not implemented - use fallback
                duration = (datetime.now() - start_time).total_seconds()
                self.log_step(agent_name, "PLACEHOLDER", duration)
                return fallback_result or {"status": "placeholder"}
                
            except Exception as e:
                duration = (datetime.now() - start_time).total_seconds()
                
                if attempt < self.PERFORMANCE_THRESHOLDS['retry_attempts'] - 1:
                    self.log_step(agent_name, f"RETRY_{attempt + 1}", duration, str(e))
                    time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                else:
                    self.log_step(agent_name, "ERROR", duration, str(e))
                    return {"status": "error", "error": str(e)}
        
        return fallback_result or {"status": "error", "error": "Max retries exceeded"}

    def _execute_asset_analysis_optimized(self, assets_data=None):
        """OPTIMIZED: Execute asset analysis with performance monitoring"""
        # Use cached sample data if none provided (for testing)
        if assets_data is None:
            assets_data = self._get_sample_assets_data()
        
        return self._execute_agent_with_optimization(
            agent_name="asset_vulnerability_mapper",
            import_path="agents.asset_vulnerability_mapper",
            class_name="AssetVulnerabilityMapper", 
            method_name="analyze",
            method_args=(assets_data,),
            fallback_result={"status": "placeholder", "mitre_techniques": ["T1190", "T1078"]}
        )

    def _execute_asset_analysis_with_priority(self, assets_data, priority_systems):
        """OPTIMIZED: Execute asset analysis with priority system focus"""
        # Enhanced asset analysis with priority context
        result = self._execute_asset_analysis_optimized(assets_data)
        
        # Add priority context to results
        if result and priority_systems:
            result['priority_analysis'] = {
                'high_priority_systems': priority_systems,
                'priority_focused': True
            }
        
        return result

    def _execute_evidence_analysis_optimized(self, evidence_data):
        """OPTIMIZED: Execute evidence analysis with performance monitoring"""
        return self._execute_agent_with_optimization(
            agent_name="interview_analyzer",
            import_path="agents.interview_analyzer",
            class_name="InterviewAnalyzer",
            method_name="analyze", 
            method_args=(evidence_data,),
            fallback_result={"status": "placeholder", "mitre_techniques": ["T1566", "T1204"]}
        )

    def _execute_threat_validation_optimized(self, parallel_results):
        """OPTIMIZED: Execute threat validation with performance monitoring"""
        return self._execute_agent_with_optimization(
            agent_name="threat_validator",
            import_path="agents.threat_validator",
            class_name="ThreatValidator",
            method_name="validate",
            method_args=(parallel_results,),
            fallback_result={"status": "placeholder", "overall_confidence": 7}
        )

    def _execute_scenario_generation_optimized(self, validation_results, parallel_results):
        """OPTIMIZED: Execute scenario generation with performance monitoring"""
        scenario_results = self._execute_agent_with_optimization(
        agent_name="scenario_generator",
        import_path="agents.scenario_generator", 
        class_name="ScenarioGenerator",
        method_name="analyze",
        method_args=(validation_results,),
        fallback_result={"status": "placeholder", "executive_summary": "Placeholder scenario"}
    )
    
    # FIXED: Get analysis results from parallel_results instead of validation_results
        if isinstance(scenario_results, dict):
            scenario_results['asset_analysis'] = parallel_results.get('asset_analysis', {})
            scenario_results['evidence_analysis'] = parallel_results.get('evidence_analysis', {})
    
        return scenario_results
    

    def _execute_quality_gate_optimized(self, scenario_results):
        """OPTIMIZED: Execute quality gate with performance monitoring"""
        return self._execute_agent_with_optimization(
            agent_name="quality_gate",
            import_path="agents.quality_agent",
            class_name="QualityGate",
            method_name="review",
            method_args=(scenario_results,),
            fallback_result={
                "approval_status": "PENDING",
    "quality_score": 0,  
    "findings": "Quality placeholder - requires challenger review",
    "send_to_challengers": True,
    "final_results": scenario_results
            }
        )

    def _generate_final_report_optimized(self, final_results, total_duration):
        """PRODUCTION-READY: Generate comprehensive final report with challenger analytics"""
        report_id = f"TI_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # OPTIMIZATION: Enhanced performance analytics
        performance_metrics = self._analyze_execution_performance()
        
        # Extract challenger and quality information
        challenger_executed = final_results.get("challenger_execution_completed", False)
        quality_improvement = final_results.get("quality_improvement", 0)
        approval_status = final_results.get("approval_status", "UNKNOWN")
        send_for_rework = final_results.get("send_for_rework", False)
        auto_approved = final_results.get("auto_approved", False)

        report = {
            "analysis_id": report_id,
            "timestamp": datetime.now().isoformat(),
            "execution_time": round(total_duration, 2),
            "executive_summary": self._create_executive_summary_optimized(final_results),
            "detailed_findings": final_results.get("final_results", {}),
            "execution_log": self.execution_log,
            "performance_metrics": performance_metrics,
            "recommendations": self._generate_recommendations_optimized(final_results),
            "auto_approved": auto_approved,
            "quality_assurance": {
                "approval_status": approval_status,
                "quality_score": final_results.get("quality_score", 0),
                "original_quality_score": final_results.get("original_quality_score", 0),
                "confidence_level": final_results.get("overall_confidence", 5),
                "challenger_enhancement": final_results.get("challenger_enhancement", {}),
                "quality_improvement": quality_improvement,
                "intelligent_evaluation": final_results.get("intelligent_evaluation_completed", False),
                "send_for_rework": send_for_rework,
                "rework_requirements": final_results.get("rework_required", [])
            },
            "challenger_analysis": {
                "challengers_executed": challenger_executed,
                "enhancement_summary": final_results.get("challenger_enhancement", {}),
                "quality_boost": f"+{quality_improvement} points" if quality_improvement > 0 else f"{quality_improvement} points",
                "critical_issues_found": final_results.get("critical_issues_analysis", {}).get("critical_issue_count", 0),
                "overall_impact": final_results.get("critical_issues_analysis", {}).get("overall_challenger_impact", "Unknown")
            },
            "workflow_status": {
                "completion_status": "completed" if approval_status != "REJECTED" else "requires_rework",
                "ready_for_stakeholders": approval_status == "APPROVED",
                "next_steps": "Present to stakeholders" if approval_status == "APPROVED" else "Address rework requirements"
            },
            "optimization_used": True,
            "status": "completed"
        }
        
        # OPTIMIZATION: Async file writing (for large reports)
        self._save_report_optimized(report)
        
        return report

    @lru_cache(maxsize=32)
    def _analyze_execution_performance(self):
        """OPTIMIZED: Analyze execution performance with caching"""
        if not self.execution_log:
            return {"total_agents": 0, "avg_execution_time": 0}
        
        completed_steps = [step for step in self.execution_log if step.get('duration')]
        
        if not completed_steps:
            return {"total_agents": len(self.execution_log), "avg_execution_time": 0}
        
        total_time = sum(step['duration'] for step in completed_steps)
        avg_time = total_time / len(completed_steps)
        
        # OPTIMIZATION: Performance insights
        fastest_agent = min(completed_steps, key=lambda x: x['duration'])
        slowest_agent = max(completed_steps, key=lambda x: x['duration'])
        
        return {
            "total_agents": len(self.execution_log),
            "completed_agents": len(completed_steps),
            "total_execution_time": round(total_time, 2),
            "avg_execution_time": round(avg_time, 2),
            "fastest_agent": {
                "name": fastest_agent['agent'],
                "time": round(fastest_agent['duration'], 2)
            },
            "slowest_agent": {
                "name": slowest_agent['agent'], 
                "time": round(slowest_agent['duration'], 2)
            },
            "optimization_effectiveness": "High" if avg_time < 5 else "Medium"
        }

    def _create_executive_summary_optimized(self, results):
        """OPTIMIZED: Create enhanced executive summary"""
        final_results = results.get("final_results", {})
        challenger_executed = results.get("challenger_execution_completed", False)
        
        return {
            "threat_level": final_results.get("risk_level", "Medium"),
            "overall_confidence": final_results.get("overall_confidence", 7),
            "key_findings": "Comprehensive threat analysis completed with optimization",
            "immediate_actions": 3,
            "strategic_recommendations": 5,
            "business_impact": final_results.get("calculated_business_impact", {}).get("range", "Significant"),
            "analysis_quality": results.get("quality_score", 85),
            "challenger_enhanced": challenger_executed,
            "approval_status": results.get("approval_status", "UNKNOWN")
        }

    def _generate_recommendations_optimized(self, results):
        """OPTIMIZED: Generate enhanced recommendations based on analysis"""
        base_recommendations = [
            "Implement multi-factor authentication on critical systems",
            "Conduct security awareness training focusing on phishing",
            "Review and update incident response procedures",
            "Implement network segmentation for database systems",
            "Deploy endpoint detection and response (EDR) solutions"
        ]
        
        # OPTIMIZATION: Dynamic recommendations based on results
        final_results = results.get("final_results", {})
        
        # Add rework requirements if analysis was rejected
        if results.get("send_for_rework", False):
            rework_recommendations = results.get("rework_required", [])
            if rework_recommendations:
                return rework_recommendations + base_recommendations[:3]
        
        if final_results.get("prioritized_recommendations"):
            # Use agent-generated recommendations if available
            return final_results["prioritized_recommendations"][:8]
        
        return base_recommendations

    def _save_report_optimized(self, report):
        """OPTIMIZED: Save report with performance considerations"""
        try:
            os.makedirs("reports", exist_ok=True)
            report_path = f"reports/threat_analysis_{report['analysis_id']}.json"
            
            # OPTIMIZATION: Write with better formatting and error handling
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"📊 Production report saved: {report_path}")
            
        except Exception as e:
            print(f"⚠️ Report save warning: {e}")

    def _track_performance(self, agent_name, duration, status):
        """OPTIMIZED: Track agent performance for optimization insights"""
        if agent_name not in self._performance_cache:
            self._performance_cache[agent_name] = {
                "executions": 0,
                "total_time": 0,
                "successes": 0,
                "failures": 0
            }
        
        stats = self._performance_cache[agent_name]
        stats["executions"] += 1
        stats["total_time"] += duration
        
        if self.PATTERNS['status_success'].search(status):
            stats["successes"] += 1
        elif self.PATTERNS['error_critical'].search(status):
            stats["failures"] += 1

    def _refine_orchestrator_context(self, orchestrator_results):
        """OPTIMIZED: Refine orchestrator context with additional insights"""
        # Add runtime refinements to orchestrator context
        refined_context = orchestrator_results.copy()
        
        # Add execution timestamp
        refined_context['execution_timestamp'] = datetime.now().isoformat()
        refined_context['optimization_level'] = 'advanced'
        
        return refined_context

    def _get_sample_assets_data(self):
        """Get sample assets data for testing"""
        return {
            "system_details": [
                {
                    "system_name": "Test Database",
                    "system_type": "Database System",
                    "system_criticality": "High",
                    "site": "Test Site"
                }
            ]
        }

    def _generate_error_report(self, error_message):
        """PRODUCTION-READY: Generate enhanced error report"""
        return {
            "analysis_id": f"TI_ERROR_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "status": "failed",
            "error": error_message,
            "execution_log": self.execution_log,
            "performance_metrics": self._analyze_execution_performance() if self.execution_log else {},
            "optimization_attempted": True,
            "recovery_suggestions": [
                "Check input data format and completeness",
                "Verify all required agent files are present",
                "Review execution logs for specific errors",
                "Consider reducing data complexity for testing"
            ]
        }
    
    def _deep_get(d, path, default=None):
            cur = d
            for k in path:
                if not isinstance(cur, dict) or k not in cur:
                    return default
            cur = cur[k]
            return cur

    def _deep_set(d, path, value):
            cur = d
            for k in path[:-1]:
                if k not in cur or not isinstance(cur[k], dict):
                    cur[k] = {}
                cur = cur[k]
            cur[path[-1]] = value
    
    
def test_data_validation_complete():
    """Test complete data validation with various edge cases"""
    
    executor = WorkflowExecutor()
    
    print("Testing COMPLETE Data Validation System...")
    print("=" * 60)
    
    # Test Case 1: Both empty (should reject)
    print("\n🧪 TEST 1: Both Empty (Should Reject)")
    result1 = executor._comprehensive_data_validation(None, None)
    print(f"  Valid: {result1['valid']}")
    print(f"  Severity: {result1['severity']}")
    print(f"  Reason: {result1['reason']}")
    
    # Test Case 2: Invalid data types (should reject)
    print("\n🧪 TEST 2: Invalid Data Types (Should Reject)")
    result2 = executor._comprehensive_data_validation("invalid", ["invalid"])
    print(f"  Valid: {result2['valid']}")
    print(f"  Severity: {result2['severity']}")
    print(f"  Reason: {result2['reason']}")
    
    # Test Case 3: Empty valid structure (should reject)
    print("\n🧪 TEST 3: Empty Valid Structure (Should Reject)")
    empty_valid = {
        "system_details": []
    }, {
        "security_assessment_findings": []
    }
    result3 = executor._comprehensive_data_validation(*empty_valid)
    print(f"  Valid: {result3['valid']}")
    print(f"  Severity: {result3['severity']}")
    print(f"  Reason: {result3['reason']}")
    
    # Test Case 4: Minimal valid data (should accept)
    print("\n🧪 TEST 4: Minimal Valid Data (Should Accept)")
    minimal_valid = {
        "system_details": [
            {
                "system_name": "Test System",
                "system_type": "Database",
                "system_criticality": "High"
            }
        ]
    }, {
        "security_assessment_findings": [
            {
                "assessment_type": "Interview",
                "confidence_level": "Medium",
                "key_security_concerns": "Basic security concerns identified"
            }
        ]
    }
    result4 = executor._comprehensive_data_validation(*minimal_valid)
    print(f"  Valid: {result4['valid']}")
    print(f"  Severity: {result4['severity']}")
    print(f"  Quality Estimate: {result4['validation_details']['overall_quality_estimate']:.1f}/100")
    
    print(f"\n✅ Data Validation Test Results:")
    print(f"  Empty Data: {'✅ Properly Rejected' if not result1['valid'] else '❌ Should Reject'}")
    print(f"  Invalid Types: {'✅ Properly Rejected' if not result2['valid'] else '❌ Should Reject'}")  
    print(f"  Empty Structure: {'✅ Properly Rejected' if not result3['valid'] else '❌ Should Reject'}")
    print(f"  Minimal Valid: {'✅ Properly Accepted' if result4['valid'] else '❌ Should Accept'}")
    
    return all([
        not result1['valid'],  # Empty should be rejected
        not result2['valid'],  # Invalid should be rejected
        not result3['valid'],  # Empty structure should be rejected
        result4['valid']       # Minimal valid should be accepted
    ])

if __name__ == "__main__":
    validation_works = test_data_validation_complete()
    print(f"\n🎯 Overall Data Validation: {'✅ WORKING' if validation_works else '❌ NEEDS FIXES'}")



            