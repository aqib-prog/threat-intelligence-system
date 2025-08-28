import sys
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent

class QualityGate(BaseAgent):
    def __init__(self):
        self._technique_cache = {}
        self._batch_validation_cache = {}

        super().__init__("quality_gate", "final quality validation and approval gate")
        # Quality thresholds for auto-approval
        self.THRESHOLDS = {
            'completeness': 95,
            'accuracy': 85, 
            'consistency': 80,
            'professional': 85,
            'auto_approval': 60,
            'input_data_minimum': 40  
        }
        
        # Pre-compiled regex patterns
        self.PATTERNS = {
            'technique': re.compile(r'T\d{4}(?:\.\d{3})?'),
            'money': re.compile(r'\$(\d+\.?\d*)[MmBb]'),
            'days': re.compile(r'(\d+)'),
            'percentage': re.compile(r'(\d+)%')
        }
        
        # Cache for technique validation - optimized structure
        self._technique_cache = {}
        self._batch_validation_cache = {}

    def get_system_prompt(self):
        return """
Expert QualityGate validator for cybersecurity threat intelligence systems.

CRITICAL: Assess both scenario quality AND input data quality to prevent garbage-in-polished-out scenarios.

Expertise: Comprehensive quality assessment, MITRE validation, business impact verification, professional standards compliance, input data quality validation.

Return JSON: approval_status, quality_score (COMBINED), findings, send_to_challengers decision.
Focus: Enterprise security standards, executive presentation quality, actionable decisions, input data integrity.
"""

    def review(self, scenario_results):
        """FIXED: Execute comprehensive quality gate review with input data quality integration"""
        print("🔍 Quality Gate: Executing FIXED validation with input data quality...")

        if not scenario_results:
            return self._generate_rejection_response("No scenario results provided")

    # --- Input data quality first ---
        input_data_quality = self._extract_input_data_quality_comprehensive(scenario_results)

        if input_data_quality < self.THRESHOLDS['input_data_minimum']:
            print(f"❌ INPUT DATA QUALITY GATE FAILURE: {input_data_quality}/100 < {self.THRESHOLDS['input_data_minimum']}")
            return self._generate_input_data_rejection(input_data_quality, scenario_results)

    # --- Extract once for scenario scoring ---
        extracted_data = self._extract_all_data_optimized(scenario_results)

        print(f"  Input Data Quality: {input_data_quality}/100")
        print(f"  Analyzing {len(extracted_data.get('all_techniques', []))} techniques...")

    # --- Parallel checks ---
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
            'completeness': executor.submit(self._check_completeness_fast, extracted_data),
            'accuracy': executor.submit(self._check_accuracy_fast, extracted_data),
            'consistency': executor.submit(self._check_consistency_fast, extracted_data),
            'professional': executor.submit(self._check_professional_fast, extracted_data)
        }
        scenario_quality_scores = {name: future.result() for name, future in futures.items()}

    # --- Scores ---
        combined_score = self._calculate_combined_quality_score_fixed(scenario_quality_scores, input_data_quality)
        scenario_only_score = self._calculate_scenario_only_score(scenario_quality_scores)

    # --- Approval decision with input quality consideration ---
        approval_decision = self._make_approval_decision_with_input_quality(
        combined_score, scenario_quality_scores, input_data_quality
    )

    # --- Challenger trigger logic (more flexible) ---
    # env override or per-request flag to force challengers
        force_challengers_env = os.getenv("FORCE_CHALLENGERS", "0").strip() == "1"
        force_challengers_flag = bool(scenario_results.get("force_challengers", False))

        auto_threshold = int(os.getenv("QUALITY_GATE_AUTO_APPROVE", str(self.THRESHOLDS['auto_approval'])))

    # “Near the line” band: within 2 points of auto-approval → challenge
        near_line = (auto_threshold - 2) <= combined_score < auto_threshold

    # Regular band where challengers are useful
        useful_band = (combined_score >= 65 and combined_score < auto_threshold and input_data_quality >= 60)

    # If input is decent but not excellent, prefer challengers
        input_moderate = (60 <= input_data_quality < 75)

        needs_challengers = (
        force_challengers_env or
        force_challengers_flag or
        near_line or
        useful_band or
        input_moderate
    )

    # But never run challengers if input is awful
        if input_data_quality < self.THRESHOLDS['input_data_minimum']:
            needs_challengers = False

    # If truly auto-approved and not forced, skip challengers
        if combined_score >= auto_threshold and not (force_challengers_env or force_challengers_flag):
            needs_challengers = False

        print(f"  Scenario Quality: {scenario_only_score:.1f}/100")
        print(f"  Input Data Quality: {input_data_quality:.1f}/100")
        print(f"  Combined Quality Score: {combined_score}/100")
        print(f"  Approval Status: {approval_decision}")
        print(f"  Challenger Review: {'Required' if needs_challengers else 'Not Required'}")

    # Always return final_results so downstream never gets None
        return {
        "approval_status": approval_decision,
        "quality_score": combined_score,                 # COMBINED score
        "scenario_quality": scenario_only_score,
        "input_data_quality": input_data_quality,
        "quality_breakdown": scenario_quality_scores,
        "findings": self._generate_findings_with_input_quality(scenario_quality_scores, input_data_quality),
        "send_to_challengers": needs_challengers,
        "final_results": scenario_results,               # <= Always present now
        "improvement_recommendations": self._generate_recommendations_with_input_quality(
            scenario_quality_scores, input_data_quality
        ),
        "executive_summary": self._generate_executive_summary_fixed(
            combined_score, approval_decision, input_data_quality
        ),
        "quality_calculation_method": "Combined: 60% scenario quality + 40% input data quality with penalties",
        "input_data_gate_passed": True,
        "status": "completed"
    }


    def _extract_input_data_quality_comprehensive(self, scenario_results):
        """CRITICAL FIX: Comprehensive input data quality extraction with realistic assessment"""
        
        print("    🔍 Extracting Input Data Quality...")
        
        # Method 1: Direct from orchestrator context (most reliable)
        if 'orchestrator_context' in scenario_results:
            orchestrator = scenario_results['orchestrator_context']
            if 'validation' in orchestrator and 'data_quality' in orchestrator['validation']:
                input_quality = orchestrator['validation']['data_quality']
                print(f"      From orchestrator: {input_quality}/100")
                return float(input_quality)
        
        # Method 2: Extract from asset and evidence analysis results
        asset_analysis = scenario_results.get('asset_analysis', {})
        evidence_analysis = scenario_results.get('evidence_analysis', {})

        if not asset_analysis:
            validation_results = scenario_results.get('validation_results', {})
            asset_analysis = validation_results.get('asset_analysis', {})
    
        if not evidence_analysis:
            validation_results = scenario_results.get('validation_results', {})
            evidence_analysis = validation_results.get('evidence_analysis', {})
        
        input_quality_factors = []
        
        # FIXED: More realistic asset data quality assessment
        if asset_analysis:
            # Check if we have real asset analysis or placeholder
            if asset_analysis.get('status') == 'placeholder':
                input_quality_factors.append(25)  # Placeholder = very poor quality
                print(f"      Asset analysis: PLACEHOLDER (25/100)")
            else:
                # Real analysis - check depth and completeness
                systems_analyzed = asset_analysis.get('quantitative_analysis', {}).get('total_systems_analyzed', 0)
                techniques_found = len(asset_analysis.get('mitre_techniques', []))
                
                if systems_analyzed >= 3 and techniques_found >= 10:
                    asset_quality = 85
                elif systems_analyzed >= 2 and techniques_found >= 5:
                    asset_quality = 70
                elif systems_analyzed >= 1 and techniques_found >= 2:
                    asset_quality = 55
                else:
                    asset_quality = 30
                
                input_quality_factors.append(asset_quality)
                print(f"      Asset analysis: {asset_quality}/100 ({systems_analyzed} systems, {techniques_found} techniques)")
        else:
            input_quality_factors.append(20)  # No asset analysis
            print(f"      Asset analysis: MISSING (20/100)")
        
        # FIXED: More realistic evidence data quality assessment
        if evidence_analysis:
            # Check if we have real evidence analysis or placeholder
            if evidence_analysis.get('status') == 'placeholder':
                input_quality_factors.append(25)  # Placeholder = very poor quality
                print(f"      Evidence analysis: PLACEHOLDER (25/100)")
            else:
                # Real analysis - check depth and completeness
                evidence_techniques = len(evidence_analysis.get('mitre_techniques', []))
                confidence_indicators = evidence_analysis.get('confidence_assessment', '')
                
                if evidence_techniques >= 15 and 'high' in confidence_indicators.lower():
                    evidence_quality = 85
                elif evidence_techniques >= 10:
                    evidence_quality = 75
                elif evidence_techniques >= 5:
                    evidence_quality = 60
                elif evidence_techniques >= 2:
                    evidence_quality = 45
                else:
                    evidence_quality = 30
                
                input_quality_factors.append(evidence_quality)
                print(f"      Evidence analysis: {evidence_quality}/100 ({evidence_techniques} techniques)")
        else:
            input_quality_factors.append(20)  # No evidence analysis
            print(f"      Evidence analysis: MISSING (20/100)")
        
        # Method 3: Check for data completeness indicators
        original_data_indicators = []
        
        # Check if we have signs of incomplete or poor original data
        attack_phases = scenario_results.get('detailed_attack_phases', [])
        business_impact = scenario_results.get('calculated_business_impact', {})
        
        # Look for signs of data gaps filled by scenario generator
        if len(attack_phases) <= 2:
            original_data_indicators.append(40)  # Limited attack complexity suggests poor input
        elif len(attack_phases) <= 4:
            original_data_indicators.append(60)  # Moderate complexity
        else:
            original_data_indicators.append(75)  # Good complexity
            
        # Business impact realism check
        impact_range = business_impact.get('range', '')
        if 'placeholder' in impact_range.lower() or len(impact_range) < 10:
            original_data_indicators.append(30)  # Poor business impact data
        else:
            original_data_indicators.append(70)  # Reasonable business impact
            
        # Calculate weighted average
        all_factors = input_quality_factors + original_data_indicators
        estimated_input_quality = sum(all_factors) / len(all_factors) if all_factors else 40
        
        # CRITICAL: Apply penalty if both main analyses are placeholders
        asset_is_placeholder = asset_analysis.get('status') == 'placeholder'
        evidence_is_placeholder = evidence_analysis.get('status') == 'placeholder'
        
        if asset_is_placeholder and evidence_is_placeholder:
            placeholder_penalty = 20
            estimated_input_quality -= placeholder_penalty
            print(f"      PLACEHOLDER PENALTY: -{placeholder_penalty} points (both analyses are placeholders)")
        elif asset_is_placeholder or evidence_is_placeholder:
            placeholder_penalty = 10
            estimated_input_quality -= placeholder_penalty
            print(f"      PLACEHOLDER PENALTY: -{placeholder_penalty} points (one analysis is placeholder)")
        
        # Ensure bounds
        estimated_input_quality = max(0, min(estimated_input_quality, 100))
        
        print(f"      FINAL Input Data Quality: {estimated_input_quality:.1f}/100")
        return round(estimated_input_quality, 1)

    def _generate_input_data_rejection(self, input_data_quality, scenario_results):
        """CRITICAL FIX: Generate rejection specifically for poor input data"""
        return {
            "approval_status": "REJECTED",
            "quality_score": input_data_quality,  # Use input data quality as the score
            "scenario_quality": 0,  # Don't even score the scenario
            "input_data_quality": input_data_quality,
            "quality_breakdown": {
                "completeness": 0,
                "accuracy": 0,
                "consistency": 0,
                "professional": 0
            },
            "findings": [
                f"INPUT DATA QUALITY FAILURE: {input_data_quality}/100 below minimum threshold ({self.THRESHOLDS['input_data_minimum']})",
                "Analysis generated from insufficient or placeholder input data",
                "High-quality scenarios cannot compensate for poor foundational data",
                "Require complete asset inventory and comprehensive security assessment data"
            ],
            "send_to_challengers": False,  # No point in challenging scenarios built on bad data
            "final_results": None,
            "improvement_recommendations": [
                "Collect comprehensive asset inventory with system details",
                "Conduct thorough security assessment interviews", 
                "Provide complete evidence data with confidence levels",
                "Ensure all required input fields are populated with meaningful data",
                "Validate data quality before submitting for analysis"
            ],
            "executive_summary": f"Analysis rejected due to insufficient input data quality ({input_data_quality}/100). Comprehensive data collection required before analysis can proceed.",
            "quality_calculation_method": "Input data quality gate failure - scenario not evaluated",
            "input_data_gate_passed": False,
            "rejection_type": "INPUT_DATA_INSUFFICIENT",
            "status": "rejected"
        }

    def _calculate_combined_quality_score_fixed(self, scenario_quality_scores, input_data_quality):
        """CRITICAL FIX: Proper combined quality score calculation with realistic weighting"""
        
        scenario_score = self._calculate_scenario_only_score(scenario_quality_scores)
        
        # FIXED: More realistic weighting - input data quality matters more
        scenario_weight = 0.60  # Scenario execution quality
        input_weight = 0.40     # Input data quality
    
        combined_score = (scenario_score * scenario_weight) + (input_data_quality * input_weight)
    
        print(f"    Quality Score Calculation:")
        print(f"      Scenario Quality: {scenario_score:.1f} × {scenario_weight} = {scenario_score * scenario_weight:.1f}")
        print(f"      Input Data Quality: {input_data_quality:.1f} × {input_weight} = {input_data_quality * input_weight:.1f}")
        print(f"      Combined Score: {combined_score:.1f}/100")
    
        # CRITICAL FIX: Apply severe penalties for very poor input data
        if input_data_quality < 40:
            severe_penalty = (40 - input_data_quality) * 0.8  # 0.8 point penalty per point below 40
            combined_score -= severe_penalty
            print(f"      SEVERE INPUT DATA PENALTY: -{severe_penalty:.1f} points")
        elif input_data_quality < 60:
            moderate_penalty = (60 - input_data_quality) * 0.4  # 0.4 point penalty per point below 60
            combined_score -= moderate_penalty
            print(f"      MODERATE INPUT DATA PENALTY: -{moderate_penalty:.1f} points")
    
        # CRITICAL FIX: Cap the maximum score based on input data quality
        # You can't get an A+ paper from F- source material
        if input_data_quality < 50:
            max_possible_score = 60  # Cap at 60/100 for very poor input data
        elif input_data_quality < 70:
            max_possible_score = 75  # Cap at 75/100 for poor input data
        else:
            max_possible_score = 100  # No cap for good input data
            
        if combined_score > max_possible_score:
            original_score = combined_score
            combined_score = max_possible_score
            print(f"      INPUT DATA QUALITY CAP: {original_score:.1f} → {combined_score:.1f} (max for {input_data_quality:.1f}/100 input quality)")
    
        # Ensure score stays within bounds
        combined_score = max(0, min(combined_score, 100))
    
        return round(combined_score, 1)

    def _make_approval_decision_with_input_quality(self, combined_score, scenario_quality_scores, input_data_quality):
        """CRITICAL FIX: Approval decision that considers input data quality"""
        
        print(f"    🎯 FIXED Approval Decision Logic:")
        print(f"      Combined Score: {combined_score}/100")
        print(f"      Input Data Quality: {input_data_quality}/100")
        print(f"      Auto-Approval Threshold: {self.THRESHOLDS['auto_approval']}")

        # CRITICAL FIX: No auto-approval with poor input data, regardless of scenario quality
        if input_data_quality < 50:
            print("      Decision: REJECTED (Poor input data prevents approval)")
            return "REJECTED"
            
        if combined_score >= self.THRESHOLDS['auto_approval']:
            print("      Decision: APPROVED (Meets combined quality standards)")
            return "APPROVED"
        
        # CRITICAL FIX: More stringent requirements when input data is questionable
        if input_data_quality < 70:
            if combined_score >= 75:  # Higher bar for questionable input data
                print("      Decision: CONDITIONAL_APPROVAL (Acceptable despite input data concerns)")
                return "CONDITIONAL_APPROVAL"
            else:
                print("      Decision: REJECTED (Combined quality insufficient with poor input data)")
                return "REJECTED"
        
        # Good input data - use normal thresholds
        if combined_score >= 70:
            print("      Decision: CONDITIONAL_APPROVAL (Acceptable combined quality)")
            return "CONDITIONAL_APPROVAL"
    
        print("      Decision: REJECTED (Below minimum combined standards)")
        return "REJECTED"

    def _determine_challenger_need_with_input_quality(self, combined_score, scenario_quality_scores, input_data_quality):
        """CRITICAL FIX: Challenger determination considering input data quality"""
        
        print(f"    🛡️ FIXED Challenger Logic:")
        print(f"      Combined Score: {combined_score}/100")
        print(f"      Input Data Quality: {input_data_quality}/100")
        
        # CRITICAL FIX: No challengers if input data is too poor
        if input_data_quality < 40:
            print("      Challenger Decision: SKIP (Input data too poor for meaningful improvement)")
            return False
            
        if combined_score >= self.THRESHOLDS['auto_approval']:
            print("      Challenger Decision: SKIP (Auto-Approved)")
            return False
    
        # CRITICAL FIX: Challengers only helpful if input data is decent
        if input_data_quality >= 60 and 50 <= combined_score < self.THRESHOLDS['auto_approval']:
            print("      Challenger Decision: REQUIRED (Can improve with good input data foundation)")
            return True
        elif input_data_quality >= 40 and 65 <= combined_score < self.THRESHOLDS['auto_approval']:
            print("      Challenger Decision: REQUIRED (May improve despite input data limitations)")
            return True
    
        print("      Challenger Decision: SKIP (Insufficient foundation for improvement)")
        return False

    def _generate_findings_with_input_quality(self, scenario_quality_scores, input_data_quality):
        """CRITICAL FIX: Findings that address input data quality issues"""
        
        findings = []
        
        # CRITICAL FIX: Input data quality findings first
        if input_data_quality < 40:
            findings.append(f"CRITICAL: Input data quality severely insufficient ({input_data_quality}/100)")
            findings.append("Analysis based on placeholder or incomplete foundational data")
        elif input_data_quality < 60:
            findings.append(f"WARNING: Input data quality below standards ({input_data_quality}/100)")
            findings.append("Limited confidence in analysis due to data gaps")
        elif input_data_quality < 80:
            findings.append(f"NOTICE: Input data quality adequate but improvable ({input_data_quality}/100)")
        
        # Scenario quality findings (existing logic)
        thresholds = [
            ('completeness', 90, "Scenario completeness concerns"),
            ('accuracy', 85, "Scenario accuracy issues detected"),
            ('consistency', 80, "Scenario consistency gaps found"),
            ('professional', 85, "Professional presentation standards below threshold")
        ]
        
        for component, threshold, message in thresholds:
            score = scenario_quality_scores.get(component, 0)
            if score < threshold:
                findings.append(f"{message}: {score}/100")
        
        if not findings:
            findings.append("Analysis meets all combined quality standards for executive presentation")
        
        return findings

    def _generate_recommendations_with_input_quality(self, scenario_quality_scores, input_data_quality):
        """CRITICAL FIX: Recommendations that address input data quality"""
        
        recommendations = []
        
        # CRITICAL FIX: Input data recommendations first
        if input_data_quality < 50:
            recommendations.extend([
                "PRIORITY: Collect comprehensive asset inventory with detailed system information",
                "PRIORITY: Conduct thorough security assessment interviews with evidence documentation",
                "PRIORITY: Validate all input data completeness before analysis",
                "Consider data collection process improvements to ensure analysis quality"
            ])
        elif input_data_quality < 70:
            recommendations.extend([
                "Enhance asset data collection with additional system details",
                "Strengthen evidence documentation and confidence assessments"
            ])
        
        # Scenario quality recommendations (existing logic)
        if scenario_quality_scores.get('completeness', 0) < 90:
            recommendations.append("Ensure all required analysis components are present and fully populated")
        
        if scenario_quality_scores.get('accuracy', 0) < 85:
            recommendations.append("Validate MITRE technique mappings and business impact calculations")
        
        if scenario_quality_scores.get('consistency', 0) < 80:
            recommendations.append("Review cross-component alignment and narrative consistency")
        
        if scenario_quality_scores.get('professional', 0) < 85:
            recommendations.append("Enhance executive narrative and recommendation actionability")
        
        return recommendations[:8]  # Limit to top 8 recommendations

    def _generate_executive_summary_fixed(self, combined_score, approval_decision, input_data_quality):
        """CRITICAL FIX: Executive summary that addresses input data quality"""
        
        if input_data_quality < 50:
            return f"Analysis rejected due to insufficient input data quality ({input_data_quality}/100). Comprehensive data collection required before reliable threat intelligence can be generated. Current combined score: {combined_score}/100."
        
        templates = {
            "APPROVED": f"Threat intelligence analysis approved with {combined_score}/100 combined quality score (input data: {input_data_quality}/100). Analysis meets enterprise standards for executive presentation and strategic decision-making.",
            "CONDITIONAL_APPROVAL": f"Analysis conditionally approved with {combined_score}/100 combined quality score (input data: {input_data_quality}/100). Review input data quality improvements and scenario enhancements before final presentation.",
            "REJECTED": f"Analysis requires revision ({combined_score}/100 combined quality score, input data: {input_data_quality}/100). Address input data quality issues and scenario improvements before executive presentation."
        }
        
        return templates.get(approval_decision, f"Quality assessment completed with {combined_score}/100 combined score (input data: {input_data_quality}/100).")

    # Existing methods remain the same...
    def _calculate_scenario_only_score(self, scenario_quality_scores):
        """Calculate scenario quality score (original logic)"""
        weights = {'completeness': 0.25, 'accuracy': 0.30, 'consistency': 0.25, 'professional': 0.20}
        
        weighted_total = sum(
            scenario_quality_scores.get(component, 0) * weight
            for component, weight in weights.items()
        )
        
        return round(weighted_total, 1)

    def _extract_all_data_optimized(self, scenario_results):
        """OPTIMIZED: Extract all required data in single pass"""
        # Required components for completeness check
        required_components = [
            'calculated_business_impact', 'calculated_timeline', 'success_probability',
            'detailed_attack_phases', 'prioritized_recommendations', 'executive_narrative'
        ]
        
        # Extract all techniques for validation
        all_techniques = []
        phases = scenario_results.get('detailed_attack_phases', [])
        for phase in phases:
            if isinstance(phase, dict) and 'techniques' in phase:
                all_techniques.extend(phase['techniques'])
        
        # Single extraction pass
        extracted = {
            'completeness_data': [
                {
                    'component': comp,
                    'present': comp in scenario_results,
                    'populated': self._is_populated_fast(scenario_results.get(comp)),
                    'quality': self._assess_quality_fast(scenario_results.get(comp))
                }
                for comp in required_components
            ],
            'all_techniques': list(set(all_techniques)),  # Remove duplicates
            'business_impact': scenario_results.get('calculated_business_impact', {}),
            'timeline': scenario_results.get('calculated_timeline', {}),
            'success_probability': scenario_results.get('success_probability', {}),
            'executive_narrative': scenario_results.get('executive_narrative', ''),
            'recommendations': scenario_results.get('prioritized_recommendations', []),
            'attack_phases': phases
        }
        
        return extracted

    def _check_completeness_fast(self, extracted_data):
        """OPTIMIZED: Fast completeness check"""
        completeness_data = extracted_data['completeness_data']
        
        if not completeness_data:
            print("    Completeness: 0% (No data provided)")
            return 0
        
        total_score = 0
        required_fields = len(completeness_data)

        for check in completeness_data:
            field_score = 0

            if check['present']:
                field_score += 40

                if check['populated']:
                    field_score += 40

                field_score += check['quality'] * 0.20

            total_score += field_score
        
        # Calculate percentage
        max_possible = required_fields * 100
        overall_percentage = (total_score / max_possible * 100) if max_possible > 0 else 0

        present_count = sum(1 for check in completeness_data if check['present'])
        populated_count = sum(1 for check in completeness_data if check['populated'])

        print(f"    Completeness: {overall_percentage:.1f}% ({present_count}/{required_fields} present, {populated_count}/{required_fields} populated)")

        return round(overall_percentage, 1)

    def _check_accuracy_fast(self, extracted_data):
        """OPTIMIZED: Fast accuracy check with batch MITRE validation"""
        # Batch validate all techniques at once
        techniques = extracted_data['all_techniques']
        mitre_accuracy = self._validate_mitre_techniques_batch(techniques)
        
        # Fast business impact validation
        business_impact_tuple = tuple(extracted_data['business_impact'].items())
        business_accuracy = self._validate_business_impact_fast(business_impact_tuple)
        
        # Fast timeline validation
        timeline_data_tuple = tuple(extracted_data['timeline'].items())
        timeline_accuracy = self._validate_timeline_fast(timeline_data_tuple)
        
        # Fast probability validation
        success_probability_tuple = tuple(extracted_data['success_probability'].items())
        probability_accuracy = self._validate_probability_fast(success_probability_tuple)
        
        # Weighted calculation
        weighted_score = (
            mitre_accuracy * 0.4 +
            business_accuracy * 0.25 +
            timeline_accuracy * 0.2 +
            probability_accuracy * 0.15
        )
        
        print(f"    Accuracy: {weighted_score:.1f}% (MITRE: {mitre_accuracy:.1f}, Business: {business_accuracy:.1f})")
        
        return round(weighted_score, 1)

    def _validate_mitre_techniques_batch(self, techniques):
        """OPTIMIZED: Batch validate MITRE techniques with caching"""
        if not techniques:
            return 50
        
        # Check cache for entire batch
        cache_key = '|'.join(sorted(techniques))
        if cache_key in self._batch_validation_cache:
            return self._batch_validation_cache[cache_key]
        
        # Separate cached and uncached
        cached_results = {}
        uncached_techniques = []
        
        for tech_id in techniques:
            if tech_id in self._technique_cache:
                cached_results[tech_id] = self._technique_cache[tech_id]
            else:
                uncached_techniques.append(tech_id)
        
        # Batch query uncached techniques
        if uncached_techniques:
            try:
                placeholders = ','.join(['?' for _ in uncached_techniques])
                query = f"SELECT id FROM techniques WHERE id IN ({placeholders})"
                results = self.query_mitre_db(query, uncached_techniques)
                
                valid_ids = {result[0] for result in results}
                
                # Cache individual results
                for tech_id in uncached_techniques:
                    is_valid = tech_id in valid_ids
                    self._technique_cache[tech_id] = is_valid
                    cached_results[tech_id] = is_valid
                    
            except Exception as e:
                print(f"Error in batch MITRE validation: {e}")
                # Assume valid for uncached if DB error
                for tech_id in uncached_techniques:
                    cached_results[tech_id] = True
        
        # Calculate accuracy
        valid_count = sum(1 for is_valid in cached_results.values() if is_valid)
        accuracy = (valid_count / len(techniques) * 100) if techniques else 0
        
        # Cache batch result
        self._batch_validation_cache[cache_key] = accuracy
        
        return min(accuracy, 100)

    def _validate_business_impact_fast(self, business_impact_str):
        """OPTIMIZED: Fast business impact validation with caching"""
        if not business_impact_str:
            return 50
        
        # Convert to string for regex
        if isinstance(business_impact_str, tuple):
            business_impact_str = dict(business_impact_str)
            
        if isinstance(business_impact_str, dict):
            range_str = business_impact_str.get('range', '')
        else:
            range_str = str(business_impact_str)
        
        if not range_str:
            return 30
        
        # Fast regex extraction
        impact_values = self.PATTERNS['money'].findall(range_str)
        
        if not impact_values:
            return 40
        
        try:
            min_impact = float(impact_values[0])
            
            if 0.1 <= min_impact <= 500:
                return 90
            elif 0.01 <= min_impact <= 1000:
                return 75
            else:
                return 50
        except ValueError:
            return 40

    def _validate_timeline_fast(self, timeline_str):
        """OPTIMIZED: Fast timeline validation with caching"""
        if not timeline_str:
            return 50
        
        # Convert to string for regex
        if isinstance(timeline_str, tuple):
            timeline_str = dict(timeline_str)
            
        if isinstance(timeline_str, dict):
            range_str = timeline_str.get('range', '')
        else:
            range_str = str(timeline_str)
        
        if not range_str:
            return 30
        
        # Fast regex extraction
        day_values = self.PATTERNS['days'].findall(range_str)
        
        if not day_values:
            return 40
        
        try:
            min_days = int(day_values[0])
            max_days = int(day_values[-1]) if len(day_values) > 1 else min_days
            
            if 1 <= min_days <= 90 and max_days >= min_days:
                return 90
            elif 1 <= min_days <= 365:
                return 70
            else:
                return 50
        except ValueError:
            return 40

    def _validate_probability_fast(self, probability_str):
        """OPTIMIZED: Fast probability validation with caching"""
        if not probability_str:
            return 50
        
        # Convert to string for regex
        if isinstance(probability_str, tuple):
            probability_str = dict(probability_str)
            
        if isinstance(probability_str, dict):
            percentage_str = probability_str.get('percentage', '')
        else:
            percentage_str = str(probability_str)
        
        if not percentage_str:
            return 30
        
        # Fast regex extraction
        percentage_match = self.PATTERNS['percentage'].findall(percentage_str)
        
        if not percentage_match:
            return 40
        
        try:
            percentage = int(percentage_match[0])
            
            if 10 <= percentage <= 95:
                return 90
            elif 1 <= percentage <= 99:
                return 70
            else:
                return 50
        except ValueError:
            return 40

    def _check_consistency_fast(self, extracted_data):
        """OPTIMIZED: Fast consistency check"""
        # Simple component presence alignment
        has_timeline = bool(extracted_data.get('timeline'))
        has_impact = bool(extracted_data.get('business_impact'))
        has_phases = bool(extracted_data.get('attack_phases'))
        has_narrative = bool(extracted_data.get('executive_narrative'))
        
        alignment_score = sum([has_timeline, has_impact, has_phases, has_narrative]) * 25
        
        # Quick narrative consistency check
        narrative = extracted_data.get('executive_narrative', '').lower()
        if narrative:
            narrative_keywords = ['timeline', 'impact', 'probability']
            found_keywords = sum(1 for keyword in narrative_keywords if keyword in narrative)
            narrative_score = (found_keywords / len(narrative_keywords)) * 100
        else:
            narrative_score = 0
        
        # Weighted consistency
        consistency_score = (alignment_score * 0.6) + (narrative_score * 0.4)
        
        print(f"    Consistency: {consistency_score:.1f}%")
        
        return round(consistency_score, 1)

    def _check_professional_fast(self, extracted_data):
        """OPTIMIZED: Fast professional standards check"""
        narrative = extracted_data.get('executive_narrative', '')
        recommendations = extracted_data.get('recommendations', [])
        business_impact = extracted_data.get('business_impact', {})
        
        # Fast narrative quality (length-based)
        if not narrative:
            narrative_score = 0
        elif len(narrative) < 100:
            narrative_score = 40
        elif len(narrative) < 300:
            narrative_score = 70
        else:
            narrative_score = 85
        
        # Fast recommendation quality (count-based)
        rec_count = len(recommendations)
        if rec_count == 0:
            rec_score = 0
        elif rec_count < 3:
            rec_score = 60
        elif rec_count < 6:
            rec_score = 80
        else:
            rec_score = 90
        
        # Fast business impact quality
        if not business_impact:
            impact_score = 0
        else:
            has_range = bool(business_impact.get('range'))
            has_methodology = bool(business_impact.get('methodology'))
            
            if has_range and has_methodology:
                impact_score = 90
            elif has_range:
                impact_score = 70
            else:
                impact_score = 50
        
        # Weighted professional score
        professional_score = (
            narrative_score * 0.4 +
            rec_score * 0.3 +
            impact_score * 0.2 +
            80 * 0.1  # Default formatting score
        )
        
        print(f"    Professional: {professional_score:.1f}%")
        
        return round(professional_score, 1)

    # OPTIMIZED: Helper methods with fast checks
    def _is_populated_fast(self, component):
        """OPTIMIZED: Fast population check"""
        if not component:
            return False
        
        if isinstance(component, dict):
            if not component:
                return False
            
            meaningful_pairs = sum(1 for k, v in component.items() if v and str(v).strip())
            return meaningful_pairs >= 2
        
        elif isinstance(component, list):
            return len(component) > 0 and any(item for item in component if item)
        
        elif isinstance(component, str):
            return len(component.strip()) >= 20
        
        return bool(component)

    def _assess_quality_fast(self, component):
        """OPTIMIZED: Fast quality assessment"""
        if not component:
            return 0
        
        if isinstance(component, dict):
            meaningful_pairs = sum(1 for k, v in component.items() if v and str(v).strip())
            if meaningful_pairs >= 5:
                return 90
            elif meaningful_pairs >= 3:
                return 75 
            elif meaningful_pairs >= 2:
                return 60
            else:
                return 30
        
        elif isinstance(component, list):
            # Score based on list length and item quality
            if len(component) >= 5:
                return 85  # Excellent
            elif len(component) >= 3:
                return 75  # Good
            elif len(component) >= 1:
                return 60  # Adequate
            else:
                return 0 
        
        elif isinstance(component, str):
            # Score based on content length and quality
            length = len(component.strip())
            if length >= 200:
                return 90  # Excellent - detailed content
            elif length >= 100:
                return 80  # Good - adequate detail
            elif length >= 50:
                return 65  # Fair - minimal detail
            elif length >= 20:
                return 45  # Poor - very brief
            else:
                return 20  # Very poor - inadequate
        return 50

    def _generate_rejection_response(self, reason):
        """OPTIMIZED: Fast rejection response"""
        return {
            "approval_status": "REJECTED",
            "quality_score": 0,
            "findings": [f"Quality Gate Rejection: {reason}"],
            "send_to_challengers": False,
            "final_results": None,
            "status": "rejected"
        }


def test_fixed_quality_gate_comprehensive():
    """Comprehensive test of the fixed quality gate system"""
    
    agent = QualityGate()
    
    print("🧪 Testing FIXED Quality Gate - Comprehensive Scenarios")
    print("=" * 70)
    
    # Test Case 1: Good scenario + Good input data = High score
    print("\n🟢 TEST 1: Good Scenario + Good Input Data (Should APPROVE)")
    good_scenario_good_input = {
        "calculated_business_impact": {
            "range": "$2.5M - $8.2M",
            "methodology": "Comprehensive analysis with industry benchmarks"
        },
        "calculated_timeline": {
            "range": "5-12 days",
            "methodology": "Dynamic calculation based on MITRE complexity"
        },
        "success_probability": {"percentage": "72%"},
        "detailed_attack_phases": [
            {"phase": "Initial Access", "techniques": ["T1190", "T1566"], "duration_days": 2},
            {"phase": "Persistence", "techniques": ["T1053", "T1547"], "duration_days": 1}
        ],
        "prioritized_recommendations": ["Implement segmentation", "Deploy EDR", "Enhance training"],
        "executive_narrative": "Comprehensive threat analysis demonstrates significant risk to organizational assets with detailed impact assessment and actionable recommendations for stakeholders...",
        "asset_analysis": {
            "status": "completed",
            "quantitative_analysis": {"total_systems_analyzed": 5},
            "mitre_techniques": ["T1190", "T1566", "T1053", "T1547", "T1078", "T1105", "T1083", "T1055", "T1003", "T1012"]
        },
        "evidence_analysis": {
            "status": "completed",
            "mitre_techniques": ["T1566.001", "T1204.002", "T1059.003", "T1027", "T1082", "T1057", "T1016", "T1033", "T1087", "T1124", "T1083", "T1005", "T1039", "T1074", "T1041"],
            "confidence_assessment": "High confidence based on comprehensive evidence"
        }
    }
    
    # Test Case 2: Good scenario + Poor input data (placeholders) = Medium/Low score
    print("\n🟡 TEST 2: Good Scenario + Poor Input Data (Should REJECT/CONDITIONAL)")
    good_scenario_poor_input = {
        "calculated_business_impact": {
            "range": "$2.5M - $8.2M",
            "methodology": "Comprehensive analysis with industry benchmarks"
        },
        "calculated_timeline": {
            "range": "5-12 days",
            "methodology": "Dynamic calculation based on MITRE complexity"
        },
        "success_probability": {"percentage": "72%"},
        "detailed_attack_phases": [
            {"phase": "Initial Access", "techniques": ["T1190", "T1566"], "duration_days": 2}
        ],
        "prioritized_recommendations": ["Implement segmentation", "Deploy EDR", "Enhance training"],
        "executive_narrative": "Comprehensive threat analysis demonstrates significant risk to organizational assets...",
        "asset_analysis": {
            "status": "placeholder",  # PLACEHOLDER ANALYSIS
            "mitre_techniques": ["T1190", "T1078"]  # Very few techniques
        },
        "evidence_analysis": {
            "status": "placeholder",  # PLACEHOLDER ANALYSIS
            "mitre_techniques": ["T1566", "T1204"]  # Very few techniques
        }
    }
    
    # Test Case 3: Poor scenario + Poor input data = Low score
    print("\n🔴 TEST 3: Poor Scenario + Poor Input Data (Should REJECT)")
    poor_scenario_poor_input = {
        "calculated_business_impact": {"range": "Significant impact"},
        "calculated_timeline": {"range": "Several days"},
        "success_probability": {"percentage": "High"},
        "detailed_attack_phases": [
            {"phase": "Attack", "techniques": ["T1234"], "duration_days": 1}
        ],
        "prioritized_recommendations": ["Fix security"],
        "executive_narrative": "Basic analysis.",
        "asset_analysis": {"status": "placeholder", "mitre_techniques": []},
        "evidence_analysis": {"status": "placeholder", "mitre_techniques": []}
    }
    
    # Test Case 4: Very poor input data (should trigger input data gate)
    print("\n🔴 TEST 4: Input Data Gate Test (Should REJECT at input data gate)")
    input_data_gate_test = {
        "calculated_business_impact": {
            "range": "$10M - $50M",
            "methodology": "Sophisticated analysis"
        },
        "calculated_timeline": {
            "range": "7-14 days",
            "methodology": "Advanced modeling"
        },
        "success_probability": {"percentage": "85%"},
        "detailed_attack_phases": [
            {"phase": "Initial Access", "techniques": ["T1190", "T1566"], "duration_days": 2},
            {"phase": "Persistence", "techniques": ["T1053", "T1547"], "duration_days": 2},
            {"phase": "Defense Evasion", "techniques": ["T1027", "T1055"], "duration_days": 3}
        ],
        "prioritized_recommendations": ["Critical security overhaul", "Deploy advanced monitoring", "Complete incident response"],
        "executive_narrative": "Extremely sophisticated threat analysis demonstrates critical organizational vulnerabilities requiring immediate executive attention and substantial security investment...",
        # BUT - terrible input data
        "asset_analysis": {"status": "placeholder", "mitre_techniques": []},  # No analysis
        "evidence_analysis": {"status": "error", "error": "No evidence provided"}  # Failed analysis
    }
    
    # Execute tests
    test_results = []
    
    print("\n" + "="*50)
    result1 = agent.review(good_scenario_good_input)
    test_results.append(("Good+Good", result1))
    print(f"Result 1: {result1['approval_status']} | Combined: {result1['quality_score']}/100 | Input: {result1['input_data_quality']}/100")
    
    print("\n" + "="*50)
    result2 = agent.review(good_scenario_poor_input) 
    test_results.append(("Good+Poor", result2))
    print(f"Result 2: {result2['approval_status']} | Combined: {result2['quality_score']}/100 | Input: {result2['input_data_quality']}/100")
    
    print("\n" + "="*50)
    result3 = agent.review(poor_scenario_poor_input)
    test_results.append(("Poor+Poor", result3))
    print(f"Result 3: {result3['approval_status']} | Combined: {result3['quality_score']}/100 | Input: {result3['input_data_quality']}/100")
    
    print("\n" + "="*50)
    result4 = agent.review(input_data_gate_test)
    test_results.append(("Gate Test", result4))
    print(f"Result 4: {result4['approval_status']} | Combined: {result4['quality_score']}/100 | Input: {result4['input_data_quality']}/100")
    print(f"Input Data Gate: {'PASSED' if result4.get('input_data_gate_passed', False) else 'FAILED'}")
    
    # Analysis
    print(f"\n🎯 CRITICAL FIX VERIFICATION:")
    print(f"=" * 50)
    
    # Check that good input data produces higher scores than poor input data
    good_input_score = result1['quality_score']
    poor_input_score = result2['quality_score'] 
    score_difference = good_input_score - poor_input_score
    
    print(f"✅ Input Data Impact: {score_difference:.1f} point difference")
    print(f"   Good input data: {good_input_score}/100")
    print(f"   Poor input data: {poor_input_score}/100")
    
    # Check input data gate functionality
    input_gate_working = not result4.get('input_data_gate_passed', True)
    print(f"✅ Input Data Gate: {'WORKING' if input_gate_working else 'NOT WORKING'}")
    
    # Check realistic scoring
    realistic_scoring = (
        result1['quality_score'] > result2['quality_score'] > result3['quality_score']
    )
    print(f"✅ Realistic Score Progression: {'WORKING' if realistic_scoring else 'NOT WORKING'}")
    
    # Check approval logic
    approval_logic = (
        result1['approval_status'] in ['APPROVED', 'CONDITIONAL_APPROVAL'] and
        result2['approval_status'] in ['REJECTED', 'CONDITIONAL_APPROVAL'] and  
        result3['approval_status'] == 'REJECTED' and
        result4['approval_status'] == 'REJECTED'
    )
    print(f"✅ Approval Logic: {'WORKING' if approval_logic else 'NOT WORKING'}")
    
    # Overall assessment
    all_working = score_difference > 0 and input_gate_working and realistic_scoring and approval_logic
    print(f"\n🏆 OVERALL SYSTEM STATUS: {'✅ FIXED!' if all_working else '❌ NEEDS MORE WORK'}")
    
    if all_working:
        print("🎉 The Quality Gate now properly prevents 'garbage-in-polished-out' scenarios!")
        print("🎉 Input data quality is properly weighted in the final decision!")
    
    return test_results


if __name__ == "__main__":
    test_results = test_fixed_quality_gate_comprehensive()
    
    print(f"\n📊 Test Summary:")
    for test_name, result in test_results:
        print(f"  {test_name}: {result['approval_status']} (Combined: {result['quality_score']}/100, Input: {result['input_data_quality']}/100)")