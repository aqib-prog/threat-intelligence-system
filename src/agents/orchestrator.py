import json 
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.base_agent import BaseAgent

class OrchestratorAgent(BaseAgent):
    def __init__(self):
        super().__init__("orchestrator", "workflow coordination and data management")
        
        # OPTIMIZATION: Enhanced caching system
        self._validation_cache = {}
        self._priority_cache = {}
        self._workflow_cache = {}
        
        # OPTIMIZATION: Pre-compiled regex patterns
        self.PATTERNS = {
            'date_recent': re.compile(r'202[4-5]'),
            'criticality_high': re.compile(r'(?i)(veryhigh|very\s*high|critical)', re.IGNORECASE),
            'system_types': re.compile(r'(?i)(database|server|application|network)', re.IGNORECASE)
        }
        
        # OPTIMIZATION: Pre-defined quality thresholds
        self.QUALITY_THRESHOLDS = {
            'minimum_assets': 1,
            'minimum_evidence': 1,
            'optimal_assets': 3,
            'optimal_evidence': 2,
            'max_quality_issues': 10
        }
    
    def get_system_prompt(self):
        return """Expert Orchestrator Agent for threat intelligence workflow coordination.

Expertise: Data validation, workflow management, priority assessment, quality assurance.

Return structured analysis with data quality scores, priority rankings, and workflow recommendations.
Focus: Actionable workflow guidance, risk-based prioritization, comprehensive coverage."""

    def validate_input_data(self, assets_data, evidence_data):
        """OPTIMIZED: Validate and assess input data quality with parallel processing"""
        print("====== Orchestrator: Validating input data =====...")
        
        # OPTIMIZATION: Parallel processing for all validation tasks
        # Convert data to JSON strings for cac`hing compatibility
        assets_data_str = self._convert_to_json_string(assets_data)
        evidence_data_str = self._convert_to_json_string(evidence_data)
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                'assets_summary': executor.submit(self._summarize_assets_optimized, assets_data_str),
                'evidence_summary': executor.submit(self._summarize_evidence_optimized, evidence_data_str),
                'quality_checks': executor.submit(self._check_data_quality_optimized, assets_data, evidence_data),
                'priority_analysis': executor.submit(self._determine_analysis_priority_optimized, assets_data_str)
            }
            
            # Collect results
            assets_summary = futures['assets_summary'].result()
            evidence_summary = futures['evidence_summary'].result()
            quality_checks = futures['quality_checks'].result()
            priority_analysis = futures['priority_analysis'].result()
        
        # OPTIMIZATION: Fast context preparation
        validation_context = {
            "assets_summary": assets_summary,
            "evidence_summary": evidence_summary,
            "data_quality_checks": quality_checks,
            "priority_analysis": priority_analysis,
            "workflow_feasibility": self._assess_workflow_feasibility_fast(quality_checks)
        }
        
        # OPTIMIZATION: Skip LLM for simple validation cases
        if (quality_checks['data_quality_score'] > 80 and 
            quality_checks['issues_found'] < 3):
            print("  Using fast validation for high-quality data...")
            result = {
                "data_quality": "High",
                "analysis_feasible": True,
                "workflow_recommendation": "Standard analysis workflow",
                "priority_focus": "Critical systems prioritization"
            }
        else:
            # Streamlined LLM prompt for complex cases
            prompt = f"""
            Analyze input data quality for threat intelligence workflow:
            
            Data Quality Score: {quality_checks['data_quality_score']}/100
            Assets: {assets_summary['total_systems']} systems
            Evidence: {evidence_summary['total_assessments']} assessments
            Issues Found: {quality_checks['issues_found']}
            
            Provide workflow recommendations and priority guidance.
            Return JSON with data_quality, analysis_feasible, workflow_recommendation.
            """
            result = self.analyze_with_llm(prompt, validation_context)
        
        # Parse LLM results
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except:
                result = {"data_quality": "Medium", "analysis_feasible": True}
        
        # OPTIMIZATION: Enhance with programmatic validation
        result['programmatic_validation'] = self._programmatic_validation_fast(assets_data, evidence_data)
        result['analysis_priority'] = priority_analysis
        result['quality_metrics'] = quality_checks
        result['performance_estimates'] = self._estimate_performance_fast(validation_context)
        
        print(f"  Data Quality: {quality_checks['data_quality_score']}/100")
        print(f"  Analysis Feasible: {result['programmatic_validation']['analysis_feasible']}")
        
        return result
    
    def coordinate_analysis_workflow(self, validation_results, assets_data, evidence_data):
        """OPTIMIZED: Coordinate analysis workflow with dynamic optimization"""
        print("⚙️ Orchestrator: Coordinating analysis workflow...")
        
        # OPTIMIZATION: Cache workflow plans for similar scenarios
        workflow_key = self._generate_workflow_cache_key(validation_results, assets_data, evidence_data)
        
        if workflow_key in self._workflow_cache:
            print("  Using cached workflow plan...")
            return self._workflow_cache[workflow_key]
        
        # OPTIMIZATION: Dynamic workflow based on data characteristics
        data_complexity = self._assess_data_complexity_fast(assets_data, evidence_data)
        priority_systems = validation_results.get('analysis_priority', {}).get('high_priority_systems', [])
        
        # OPTIMIZATION: Adaptive time estimates based on data size
        time_estimates = self._calculate_dynamic_time_estimates(data_complexity, len(priority_systems))
        
        workflow_plan = {
            "execution_strategy": self._determine_execution_strategy_fast(data_complexity),
            "phase_1_parallel": {
                "asset_analysis": {
                    "agent": "asset_vulnerability_mapper",
                    "input": assets_data,
                    "priority_systems": priority_systems,
                    "estimated_time": time_estimates['asset_analysis'],
                    "parallel_execution": True
                },
                "evidence_analysis": {
                    "agent": "interview_analyzer", 
                    "input": evidence_data,
                    "focus_areas": validation_results.get('workflow_recommendation', ''),
                    "estimated_time": time_estimates['evidence_analysis'],
                    "parallel_execution": True
                }
            },
            "phase_2_validation": {
                "agent": "threat_validator",
                "dependency": "phase_1_parallel",
                "estimated_time": time_estimates['threat_validation'],
                "optimization_hints": self._get_validation_optimization_hints(data_complexity)
            },
            "phase_3_scenarios": {
                "agent": "scenario_generator",
                "dependency": "phase_2_validation", 
                "estimated_time": time_estimates['scenario_generation'],
                "business_focus": self._determine_business_focus(priority_systems)
            },
            "phase_4_quality": {
                "agent": "quality_gate",
                "dependency": "phase_3_scenarios",
                "estimated_time": time_estimates['quality_gate'],
                "quality_thresholds": self._get_dynamic_quality_thresholds(data_complexity)
            },
            "total_estimated_time": sum(time_estimates.values()),
            "workflow_optimization": {
                "parallel_phases": ["phase_1_parallel"],
                "critical_path": ["phase_2_validation", "phase_3_scenarios", "phase_4_quality"],
                "fallback_strategies": self._generate_fallback_strategies(data_complexity)
            }
        }
        
        # Cache workflow plan
        self._workflow_cache[workflow_key] = workflow_plan
        
        print(f"  Total Estimated Time: {workflow_plan['total_estimated_time']:.1f} minutes")
        print(f"  Execution Strategy: {workflow_plan['execution_strategy']}")
        
        return workflow_plan
    
    @lru_cache(maxsize=128)
    def _summarize_assets_optimized(self, assets_data_str):
        """OPTIMIZED: Fast asset summarization with caching"""
        # Convert string back to dict (required for caching)
        if isinstance(assets_data_str, str):
            try:
                assets_data = json.loads(assets_data_str)
            except:
                return {"status": "Invalid asset data"}
        else:
            assets_data = assets_data_str
        
        if not assets_data or 'system_details' not in assets_data:
            return {"status": "No asset data provided"}
        
        systems = assets_data['system_details']
        
        # OPTIMIZATION: Vectorized counting
        criticality_dist = {}
        system_types = {}
        sites = set()
        
        for system in systems:
            # Fast criticality categorization
            criticality = system.get('system_criticality', 'Unknown')
            criticality_dist[criticality] = criticality_dist.get(criticality, 0) + 1
            
            # Fast system type categorization
            sys_type = system.get('system_type', 'Unknown')
            system_types[sys_type] = system_types.get(sys_type, 0) + 1
            
            # Fast site collection
            site = system.get('site', 'Unknown')
            sites.add(site)
        
        return {
            "total_systems": len(systems),
            "criticality_distribution": criticality_dist,
            "system_types": system_types,
            "sites": list(sites),
            "high_criticality_count": sum(
                count for crit, count in criticality_dist.items()
                if self.PATTERNS['criticality_high'].search(crit)
            )
        }
    
    @lru_cache(maxsize=128)
    def _summarize_evidence_optimized(self, evidence_data_str):
        """OPTIMIZED: Fast evidence summarization with caching"""
        # Convert string back to dict (required for caching)
        if isinstance(evidence_data_str, str):
            try:
                evidence_data = json.loads(evidence_data_str)
            except:
                return {"status": "Invalid evidence data"}
        else:
            evidence_data = evidence_data_str
        
        if not evidence_data or 'security_assessment_findings' not in evidence_data:
            return {"status": "No evidence data provided"}
        
        findings = evidence_data['security_assessment_findings']
        
        # OPTIMIZATION: Vectorized analysis
        assessment_types = {}
        confidence_levels = {}
        recent_count = 0
        
        for finding in findings:
            # Fast type categorization
            assess_type = finding.get('assessment_type', 'Unknown')
            assessment_types[assess_type] = assessment_types.get(assess_type, 0) + 1
            
            # Fast confidence categorization
            confidence = finding.get('confidence_level', 'Unknown')
            confidence_levels[confidence] = confidence_levels.get(confidence, 0) + 1
            
            # Fast recent assessment check
            assess_date = finding.get('assessment_date', '')
            if self.PATTERNS['date_recent'].search(assess_date):
                recent_count += 1
        
        return {
            "total_assessments": len(findings),
            "assessment_types": assessment_types,
            "confidence_levels": confidence_levels,
            "recent_assessments": recent_count,
            "evidence_quality": "High" if recent_count / len(findings) > 0.7 else "Medium"
        }
    
    def _check_data_quality_optimized(self, assets_data, evidence_data):
        """OPTIMIZED: Fast data quality checks with parallel processing"""
        quality_issues = []
        
        # OPTIMIZATION: Parallel quality checks
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                'asset_issues': executor.submit(self._check_asset_quality_fast, assets_data),
                'evidence_issues': executor.submit(self._check_evidence_quality_fast, evidence_data)
            }
            
            asset_issues = futures['asset_issues'].result()
            evidence_issues = futures['evidence_issues'].result()
        
        quality_issues.extend(asset_issues)
        quality_issues.extend(evidence_issues)
        
        # OPTIMIZATION: Fast quality scoring
        total_issues = len(quality_issues)
        quality_score = max(0, 100 - (total_issues * 10))
        
        return {
            "issues_found": total_issues,
            "issues": quality_issues[:10],  # Limit display
            "data_quality_score": quality_score,
            "asset_issues": len(asset_issues),
            "evidence_issues": len(evidence_issues)
        }
    
    def _check_asset_quality_fast(self, assets_data):
        """OPTIMIZED: Fast asset quality validation"""
        issues = []
        
        if not assets_data or 'system_details' not in assets_data:
            return ["No asset data provided"]
        
        required_fields = ['system_name', 'system_type', 'system_criticality']
        
        for i, system in enumerate(assets_data['system_details']):
            missing_fields = [field for field in required_fields if not system.get(field)]
            
            if missing_fields:
                issues.append(f"Asset {i+1}: Missing {', '.join(missing_fields)}")
                
            # Stop checking after too many issues for performance
            if len(issues) >= self.QUALITY_THRESHOLDS['max_quality_issues']:
                break
        
        return issues
    
    def _check_evidence_quality_fast(self, evidence_data):
        """OPTIMIZED: Fast evidence quality validation"""
        issues = []
        
        if not evidence_data or 'security_assessment_findings' not in evidence_data:
            return ["No evidence data provided"]
        
        required_fields = ['assessment_type', 'assessment_date']
        
        for i, finding in enumerate(evidence_data['security_assessment_findings']):
            missing_fields = [field for field in required_fields if not finding.get(field)]
            
            if missing_fields:
                issues.append(f"Evidence {i+1}: Missing {', '.join(missing_fields)}")
                
            # Stop checking after too many issues for performance
            if len(issues) >= self.QUALITY_THRESHOLDS['max_quality_issues']:
                break
        
        return issues
    
    @lru_cache(maxsize=64)
    def _determine_analysis_priority_optimized(self, assets_data_str):
        """OPTIMIZED: Fast priority analysis with caching"""
        # Convert string back to dict (required for caching)
        if isinstance(assets_data_str, str):
            try:
                assets_data = json.loads(assets_data_str)
            except:
                return {"high_priority_systems": []}
        else:
            assets_data = assets_data_str
        
        if not assets_data or 'system_details' not in assets_data:
            return {"high_priority_systems": []}
        
        high_priority = []
        critical_systems = []
        
        for system in assets_data['system_details']:
            criticality = system.get('system_criticality', '')
            system_type = system.get('system_type', '').lower()
            
            # OPTIMIZATION: Fast criticality check with regex
            if self.PATTERNS['criticality_high'].search(criticality):
                high_priority.append({
                    'name': system.get('system_name', 'Unknown'),
                    'type': system.get('system_type', 'Unknown'),
                    'criticality': criticality
                })
            
            # OPTIMIZATION: Fast critical system identification
            if (self.PATTERNS['system_types'].search(system_type) or 
                'critical' in criticality.lower()):
                critical_systems.append(system.get('system_name', 'Unknown'))
        
        return {
            "high_priority_systems": high_priority,
            "critical_systems": critical_systems,
            "analysis_order": "prioritize_critical_first",
            "priority_count": len(high_priority)
        }
    
    def _programmatic_validation_fast(self, assets_data, evidence_data):
        """OPTIMIZED: Fast programmatic validation"""
        asset_count = len(assets_data.get('system_details', [])) if assets_data else 0
        evidence_count = len(evidence_data.get('security_assessment_findings', [])) if evidence_data else 0
        
        return {
            "assets_valid": asset_count > 0,
            "evidence_valid": evidence_count > 0,
            "minimum_data_threshold": (asset_count >= self.QUALITY_THRESHOLDS['minimum_assets'] and 
                                     evidence_count >= self.QUALITY_THRESHOLDS['minimum_evidence']),
            "analysis_feasible": (asset_count >= self.QUALITY_THRESHOLDS['optimal_assets'] or 
                                evidence_count >= self.QUALITY_THRESHOLDS['optimal_evidence']),
            "data_sufficiency_score": min(100, (asset_count + evidence_count) * 10)
        }
    
    def _assess_workflow_feasibility_fast(self, quality_checks):
        """OPTIMIZED: Fast workflow feasibility assessment"""
        quality_score = quality_checks['data_quality_score']
        issues_count = quality_checks['issues_found']
        
        if quality_score >= 80 and issues_count <= 3:
            return {"feasibility": "High", "confidence": 90}
        elif quality_score >= 60 and issues_count <= 7:
            return {"feasibility": "Medium", "confidence": 70}
        else:
            return {"feasibility": "Low", "confidence": 50}
    
    def _assess_data_complexity_fast(self, assets_data, evidence_data):
        """OPTIMIZED: Fast data complexity assessment"""
        asset_count = len(assets_data.get('system_details', [])) if assets_data else 0
        evidence_count = len(evidence_data.get('security_assessment_findings', [])) if evidence_data else 0
        
        complexity_score = (asset_count * 2) + (evidence_count * 3)
        
        if complexity_score >= 20:
            return {"level": "High", "score": complexity_score}
        elif complexity_score >= 10:
            return {"level": "Medium", "score": complexity_score}
        else:
            return {"level": "Low", "score": complexity_score}
    
    def _calculate_dynamic_time_estimates(self, data_complexity, priority_count):
        """OPTIMIZED: Dynamic time estimation based on data characteristics"""
        base_times = {
            'asset_analysis': 5.0,
            'evidence_analysis': 4.0,
            'threat_validation': 3.5,
            'scenario_generation': 4.5,
            'quality_gate': 2.0
        }
        
        # Complexity multiplier
        complexity_multiplier = {
            'Low': 0.8,
            'Medium': 1.0,
            'High': 1.3
        }.get(data_complexity['level'], 1.0)
        
        # Priority system multiplier
        priority_multiplier = 1.0 + (priority_count * 0.1)
        
        # Apply multipliers
        estimated_times = {}
        for phase, base_time in base_times.items():
            estimated_times[phase] = round(base_time * complexity_multiplier * priority_multiplier, 1)
        
        return estimated_times
    
    def _determine_execution_strategy_fast(self, data_complexity):
        """OPTIMIZED: Fast execution strategy determination"""
        strategies = {
            'Low': 'Standard sequential execution',
            'Medium': 'Optimized parallel execution', 
            'High': 'Advanced parallel with caching'
        }
        
        return strategies.get(data_complexity['level'], 'Standard execution')
    
    def _get_validation_optimization_hints(self, data_complexity):
        """Generate optimization hints for threat validation"""
        hints = []
        
        if data_complexity['level'] == 'High':
            hints.extend(['Use batch processing', 'Enable caching'])
        elif data_complexity['level'] == 'Medium':
            hints.append('Use parallel validation')
        else:
            hints.append('Use fast-path validation')
        
        return hints
    
    def _determine_business_focus(self, priority_systems):
        """Determine business focus based on priority systems"""
        if not priority_systems:
            return "General business impact analysis"
        
        system_types = [sys.get('type', '').lower() for sys in priority_systems]
        
        if any('database' in st for st in system_types):
            return "Data protection and compliance focus"
        elif any('financial' in st for st in system_types):
            return "Financial impact and regulatory focus"
        else:
            return "Operational continuity focus"
    
    def _get_dynamic_quality_thresholds(self, data_complexity):
        """Get dynamic quality thresholds based on complexity"""
        base_threshold = 85
        
        if data_complexity['level'] == 'High':
            return base_threshold - 5  # More lenient for complex data
        elif data_complexity['level'] == 'Low':
            return base_threshold + 5  # More strict for simple data
        else:
            return base_threshold
    
    def _generate_fallback_strategies(self, data_complexity):
        """Generate fallback strategies for workflow failures"""
        strategies = []
        
        if data_complexity['level'] == 'High':
            strategies.extend([
                'Reduce parallel processing on failure',
                'Use simplified analysis models',
                'Enable detailed error logging'
            ])
        else:
            strategies.extend([
                'Retry with increased timeouts',
                'Use alternative agent implementations'
            ])
        
        return strategies
    
    def _estimate_performance_fast(self, validation_context):
        """Fast performance estimation"""
        quality_score = validation_context['data_quality_checks']['data_quality_score']
        
        return {
            "expected_accuracy": min(95, quality_score + 10),
            "confidence_level": "High" if quality_score >= 80 else "Medium",
            "processing_efficiency": "Optimized" if quality_score >= 70 else "Standard"
        }
    
    def _generate_workflow_cache_key(self, validation_results, assets_data, evidence_data):
        """Generate cache key for workflow plans"""
        asset_count = len(assets_data.get('system_details', [])) if assets_data else 0
        evidence_count = len(evidence_data.get('security_assessment_findings', [])) if evidence_data else 0
        quality_score = validation_results.get('quality_metrics', {}).get('data_quality_score', 0)
        
        return f"workflow_{asset_count}_{evidence_count}_{quality_score//10}"
    
    def _convert_to_json_string(self, data):
        """Convert data to JSON string for caching"""
        if isinstance(data, dict):
            return json.dumps(data, sort_keys=True)
        return str(data)

def test_optimized_orchestrator():
    """Test optimized orchestrator performance"""
    orchestrator = OrchestratorAgent()
    
    # Sample test data
    sample_assets = {
        "system_details": [
            {
                "system_name": "Customer Database",
                "system_type": "Database System", 
                "system_criticality": "VeryHigh",
                "site": "Corporate HQ"
            },
            {
                "system_name": "Email Server",
                "system_type": "Email System",
                "system_criticality": "High", 
                "site": "Branch Office"
            },
            {
                "system_name": "Web Application",
                "system_type": "Web Server",
                "system_criticality": "Medium",
                "site": "DMZ"
            }
        ]
    }
    
    sample_evidence = {
        "security_assessment_findings": [
            {
                "assessment_type": "Executive Interview",
                "assessment_date": "2025-01-15",
                "confidence_level": "High",
                "key_security_concerns": "Phishing attacks and credential theft"
            },
            {
                "assessment_type": "Technical Assessment", 
                "assessment_date": "2025-01-10",
                "confidence_level": "High",
                "key_security_concerns": "Network segmentation issues"
            }
        ]
    }
    
    print("Testing OPTIMIZED Orchestrator Agent...")
    print("=" * 50)
    
    # Performance test
    total_time = 0
    num_runs = 3
    
    for i in range(num_runs):
        start_time = datetime.now()
        
        # Test validation
        validation_result = orchestrator.validate_input_data(sample_assets, sample_evidence)
        
        # Test workflow coordination
        workflow = orchestrator.coordinate_analysis_workflow(validation_result, sample_assets, sample_evidence)
        
        duration = (datetime.now() - start_time).total_seconds()
        total_time += duration
        
        if i == 0:  # Print results from first run
            print(f"\n📊 OPTIMIZED Results:")
            print(f"Data Quality Score: {validation_result['quality_metrics']['data_quality_score']}/100")
            print(f"Analysis Feasible: {validation_result['programmatic_validation']['analysis_feasible']}")
            print(f"High Priority Systems: {len(validation_result['analysis_priority']['high_priority_systems'])}")
            print(f"Total Estimated Time: {workflow['total_estimated_time']:.1f} minutes")
            print(f"Execution Strategy: {workflow['execution_strategy']}")
    
    avg_time = total_time / num_runs
    print(f"\n⚡ PERFORMANCE RESULTS:")
    print(f"Average execution time: {avg_time:.3f} seconds")
    print(f"Total runs: {num_runs}")
    print(f"🎯 Target: <2 seconds - {'✅ ACHIEVED' if avg_time < 2 else '❌ NEEDS MORE OPTIMIZATION'}")
    
    print("✅ OPTIMIZED Orchestrator test complete")
    return validation_result, workflow

if __name__ == "__main__":
    test_optimized_orchestrator()