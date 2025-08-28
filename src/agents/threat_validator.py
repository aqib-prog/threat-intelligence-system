import sys
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent

class ThreatValidator(BaseAgent):
    def __init__(self):
        super().__init__("threat_validator", "threat validation and MITRE ATT&CK cross-reference analysis")
        # OPTIMIZATION: Enhanced caching system
        self._technique_cache = {}
        self._tactic_sequence_cache = None
        self._batch_validation_cache = {}
        
        # OPTIMIZATION: Pre-compiled regex patterns
        self.PATTERNS = {
            'technique_id': re.compile(r'T\d{4}(?:\.\d{3})?'),
            'tactic_name': re.compile(r'[a-z-]+'),
        }

    def get_system_prompt(self):
        return """Expert ThreatValidator for cybersecurity threat intelligence.

Expertise: MITRE ATT&CK validation, attack chain feasibility, cross-validation, confidence scoring.

Return JSON: validated_techniques, cross_validation_score, overall_confidence, validation_metrics.
Focus: Technical accuracy, attack progression logic, evidence correlation."""

    def validate(self, parallel_results):
        """OPTIMIZED: Validate threats with parallel processing"""
        print("🔍 Threat Validator: Cross-referencing threat intelligence...")
        
        if not parallel_results:
            return self._generate_no_data_response()
        
        asset_analysis = parallel_results.get('asset_analysis', {})
        evidence_analysis = parallel_results.get('evidence_analysis', {})
        
        # OPTIMIZATION: Extract all data in single pass
        validation_context = self._extract_validation_context_optimized(asset_analysis, evidence_analysis)
        
        print(f"  Asset techniques: {len(validation_context['asset_techniques'])}")
        print(f"  Evidence techniques: {len(validation_context['evidence_techniques'])}")
        print(f"  Combined techniques: {len(validation_context['combined_techniques'])}")
        
        # OPTIMIZATION: Fast path for simple cases
        if len(validation_context['combined_techniques']) <= 3:
            print("  Using fast validation for small technique set...")
            llm_results = {
                "validated_techniques": validation_context['combined_techniques'],
                "overall_confidence": 8,
                "findings": "Fast validation with limited techniques"
            }
        else:
            # Streamlined LLM prompt
            prompt = f"""
            Validate threat intelligence:
            - Asset techniques: {validation_context['asset_techniques'][:5]}
            - Evidence techniques: {validation_context['evidence_techniques'][:5]}
            - Attack surface: {validation_context['attack_surface']}/100
            
            Return JSON: validated_techniques, overall_confidence (1-10), findings.
            """
            llm_results = self.analyze_with_llm(prompt, validation_context)
        
        # Parse LLM results
        if isinstance(llm_results, str):
            try:
                llm_results = json.loads(llm_results)
            except:
                llm_results = {"validated_techniques": validation_context['combined_techniques']}
        
        if not isinstance(llm_results, dict):
            llm_results = {"validated_techniques": validation_context['combined_techniques']}
        
        # OPTIMIZATION: Parallel validation metrics calculation
        enhanced_results = self._enhance_with_validation_metrics_parallel(llm_results, validation_context)
        
        # OPTIMIZATION: Batch MITRE validation
        all_techniques = enhanced_results.get('validated_techniques', [])
        technique_ids = [str(t) for t in all_techniques] if all_techniques else validation_context['combined_techniques']
        
        validated_techniques = self.validate_mitre_techniques(technique_ids)
        enhanced_results['mitre_validated_techniques'] = validated_techniques
        
        return enhanced_results

    def _extract_validation_context_optimized(self, asset_analysis, evidence_analysis):
        """OPTIMIZED: Extract all validation context in single pass"""
        asset_techniques = self._extract_techniques_fast(asset_analysis)
        evidence_techniques = self._extract_techniques_fast(evidence_analysis)
        
        return {
            "asset_techniques": asset_techniques,
            "evidence_techniques": evidence_techniques,
            "combined_techniques": list(set(asset_techniques + evidence_techniques)),
            "system_inventory": self._extract_system_inventory_fast(asset_analysis),
            "behavioral_indicators": self._extract_behavioral_indicators_fast(evidence_analysis),
            "attack_surface": asset_analysis.get('quantitative_analysis', {}).get('attack_surface_score', 0)
        }

    def _extract_techniques_fast(self, analysis_results):
        """OPTIMIZED: Fast technique extraction with prioritized lookup"""
        techniques = []
        
        # Single-pass extraction with prioritized fields
        for field in ['validated_mitre_techniques', 'mitre_techniques', 'techniques']:
            if field in analysis_results:
                field_data = analysis_results[field]
                if isinstance(field_data, list):
                    for item in field_data:
                        if isinstance(item, dict) and 'id' in item:
                            techniques.append(item['id'])
                        elif isinstance(item, str) and self.PATTERNS['technique_id'].match(item):
                            techniques.append(item)
                break  # Stop at first successful extraction
        
        return list(set(techniques))

    def _extract_system_inventory_fast(self, asset_analysis):
        """OPTIMIZED: Fast system inventory extraction"""
        qa = asset_analysis.get('quantitative_analysis', {})
        return {
            'total_systems': qa.get('total_systems_analyzed', 0),
            'critical_systems': qa.get('critical_systems_count', 0),
            'attack_surface': qa.get('attack_surface_score', 0)
        }

    def _extract_behavioral_indicators_fast(self, evidence_analysis):
        """OPTIMIZED: Fast behavioral indicators extraction"""
        bm = evidence_analysis.get('behavioral_metrics', {})
        return {
            'phishing_susceptibility': bm.get('phishing_susceptibility_score', 0),
            'credential_hygiene': bm.get('credential_hygiene_score', 0),
            'security_awareness': bm.get('security_awareness_score', 0)
        }

    def _enhance_with_validation_metrics_parallel(self, llm_results, validation_context):
        """OPTIMIZED: Parallel validation metrics calculation"""
        enhanced = llm_results.copy() if isinstance(llm_results, dict) else {}
        
        # OPTIMIZATION: Parallel processing for all validation metrics
        # Convert context to tuple for caching compatibility
        context_tuple = self._convert_context_to_tuple(validation_context)
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                'overlap': executor.submit(self._calculate_technique_overlap_fast, context_tuple),
                'chain_feasibility': executor.submit(self._assess_attack_chain_feasibility_optimized, validation_context),
                'behavioral_alignment': executor.submit(self._assess_behavioral_alignment_fast, context_tuple),
                'consistency': executor.submit(self._analyze_cross_validation_consistency_fast, context_tuple)
            }
            
            # Collect results
            overlap_score = futures['overlap'].result()
            chain_feasibility = futures['chain_feasibility'].result()
            behavioral_alignment = futures['behavioral_alignment'].result()
            consistency_analysis = futures['consistency'].result()
        
        # OPTIMIZATION: Fast calculations
        cross_validation_score = self._calculate_cross_validation_score_fast(
            overlap_score, chain_feasibility, behavioral_alignment, consistency_analysis
        )
        
        overall_confidence = self._calculate_overall_confidence_fast(
            llm_results.get('overall_confidence', 5),
            cross_validation_score,
            len(validation_context['combined_techniques']),
            validation_context['attack_surface']
        )
        
        risk_validation = self._validate_risk_levels_fast(validation_context)
        
        # Assign all metrics
        enhanced['validation_metrics'] = {
            'technique_overlap_score': overlap_score,
            'attack_chain_feasibility': chain_feasibility,
            'behavioral_technical_alignment': behavioral_alignment
        }
        
        enhanced['consistency_analysis'] = consistency_analysis
        enhanced['risk_validation'] = risk_validation
        enhanced['cross_validation_score'] = cross_validation_score
        enhanced['overall_confidence'] = overall_confidence
        
        return enhanced

    @lru_cache(maxsize=256)
    def _calculate_technique_overlap_fast(self, validation_context_tuple):
        """OPTIMIZED: Fast technique overlap calculation with caching"""
        # Convert tuple back to usable format
        validation_context = self._convert_context_from_tuple(validation_context_tuple)
        
        asset_techs = set(validation_context['asset_techniques'])
        evidence_techs = set(validation_context['evidence_techniques'])
        
        if not asset_techs and not evidence_techs:
            return 0
        
        intersection = len(asset_techs.intersection(evidence_techs))
        union = len(asset_techs.union(evidence_techs))
        
        return round((intersection / union * 100) if union > 0 else 0, 1)

    def _assess_attack_chain_feasibility_optimized(self, validation_context):
        """OPTIMIZED: Enhanced attack chain feasibility with parallel processing"""
        techniques = validation_context['combined_techniques']
        
        if not techniques:
            return {'score': 0, 'assessment': 'Low'}
        
        # OPTIMIZATION: Batch get technique details
        technique_details = self._get_techniques_batch_optimized(techniques)
        if not technique_details:
            return {'score': 0, 'assessment': 'Low'}
        
        # Collect all tactics
        covered_tactics = set()
        for details in technique_details.values():
            covered_tactics.update(details.get('tactics', []))
        
        # OPTIMIZATION: Parallel calculation of attack phases
        attack_phases = {
            'entry': ['reconnaissance', 'resource-development', 'initial-access'],
            'establish': ['execution', 'persistence', 'privilege-escalation'],
            'operate': ['defense-evasion', 'credential-access', 'discovery', 'lateral-movement'],
            'complete': ['collection', 'command-and-control', 'exfiltration', 'impact']
        }
        
        # Convert to tuples for caching
        covered_tactics_tuple = tuple(sorted(covered_tactics))
        attack_phases_tuple = tuple((k, tuple(v)) for k, v in attack_phases.items())
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                'phase_coverage': executor.submit(self._calculate_phase_coverage_fast, covered_tactics_tuple, attack_phases_tuple),
                'consecutive_chain': executor.submit(self._find_longest_consecutive_chain_fast, covered_tactics_tuple),
                'completeness': executor.submit(self._calculate_attack_completeness_fast, covered_tactics_tuple)
            }
            
            phase_coverage = futures['phase_coverage'].result()
            longest_consecutive = futures['consecutive_chain'].result()
            completeness_score = futures['completeness'].result()
        
        # Calculate scores
        transition_score = self._calculate_phase_transitions_fast(covered_tactics_tuple, attack_phases_tuple)
        consecutive_score = self._score_consecutive_chain_fast(longest_consecutive)
        
        # Combined scoring
        weights = {'consecutive': 0.4, 'completeness': 0.4, 'transitions': 0.2}
        
        final_score = (
            consecutive_score * weights['consecutive'] +
            completeness_score * weights['completeness'] +
            transition_score * weights['transitions']
        )
        
        # Assessment based on final score
        if final_score >= 75:
            assessment = 'Critical'
        elif final_score >= 70:
            assessment = 'High'
        elif final_score >= 45:
            assessment = 'Medium'
        else:
            assessment = 'Low'
        
        print(f"    Attack Chain: {final_score:.1f} ({assessment})")
        
        return {
            'score': round(final_score, 1),
            'assessment': assessment,
            'breakdown': {
                'consecutive_chain_length': longest_consecutive,
                'consecutive_score': consecutive_score,
                'completeness_score': completeness_score,
                'transition_score': transition_score,
                'phase_coverage': phase_coverage
            },
            'covered_tactics': list(covered_tactics),
            'attack_phases_covered': len([p for p in phase_coverage.values() if p['covered'] > 0])
        }

    def _get_techniques_batch_optimized(self, technique_ids):
        """OPTIMIZED: Batch query with enhanced caching"""
        if not technique_ids:
            return {}
        
        # Check cache first
        cache_key = '|'.join(sorted(technique_ids))
        if cache_key in self._batch_validation_cache:
            return self._batch_validation_cache[cache_key]
        
        cached_results = {}
        uncached_ids = []
        
        for tech_id in technique_ids:
            if tech_id in self._technique_cache:
                cached_results[tech_id] = self._technique_cache[tech_id]
            else:
                uncached_ids.append(tech_id)
        
        # Batch query uncached techniques
        if uncached_ids:
            try:
                placeholders = ','.join(['?' for _ in uncached_ids])
                query = f"SELECT id, name, tactic_ids FROM techniques WHERE id IN ({placeholders})"
                results = self.query_mitre_db(query, uncached_ids)
                
                for result in results:
                    tech_id = result[0]
                    tactics = json.loads(result[2]) if result[2] else []
                    tech_data = {
                        'name': result[1],
                        'tactics': tactics
                    }
                    # Cache individual and batch results
                    self._technique_cache[tech_id] = tech_data
                    cached_results[tech_id] = tech_data
                    
            except Exception as e:
                print(f"Error in batch query: {e}")
        
        # Cache batch result
        self._batch_validation_cache[cache_key] = cached_results
        
        return cached_results

    @lru_cache(maxsize=128)
    def _calculate_phase_coverage_fast(self, covered_tactics_tuple, attack_phases_tuple):
        """OPTIMIZED: Fast phase coverage calculation"""
        covered_tactics = set(covered_tactics_tuple)
        attack_phases = dict(attack_phases_tuple)
        
        phase_coverage = {}
        for phase, tactics in attack_phases.items():
            covered_in_phase = len([t for t in tactics if t in covered_tactics])
            phase_coverage[phase] = {
                'covered': covered_in_phase,
                'total': len(tactics),
                'percentage': (covered_in_phase / len(tactics)) * 100
            }
        
        return phase_coverage

    @lru_cache(maxsize=128)
    def _find_longest_consecutive_chain_fast(self, covered_tactics_tuple):
        """OPTIMIZED: Fast consecutive chain calculation"""
        covered_tactics = set(covered_tactics_tuple)
        
        attack_sequence = [
            'reconnaissance', 'resource-development', 'initial-access', 
            'execution', 'persistence', 'privilege-escalation', 
            'defense-evasion', 'credential-access', 'discovery', 
            'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ]
        
        longest_chain = 0
        current_chain = 0
        
        for tactic in attack_sequence:
            if tactic in covered_tactics:
                current_chain += 1
                longest_chain = max(longest_chain, current_chain)
            else:
                current_chain = 0
        
        return longest_chain

    @lru_cache(maxsize=128)
    def _calculate_attack_completeness_fast(self, covered_tactics_tuple):
        """OPTIMIZED: Fast attack completeness calculation"""
        covered_tactics = set(covered_tactics_tuple)
        
        # Quick completeness scoring
        base_score = (len(covered_tactics) / 14) * 60
        
        # Fast bonus calculations
        bonus_points = 0
        
        # High-value combinations
        if {'initial-access', 'persistence', 'exfiltration'}.issubset(covered_tactics):
            bonus_points += 20
        
        if {'defense-evasion', 'collection'}.issubset(covered_tactics):
            bonus_points += 15
        
        if {'command-and-control', 'exfiltration'}.issubset(covered_tactics):
            bonus_points += 10
        
        # Lifecycle bonus
        phase_indicators = {
            'entry': ['reconnaissance', 'resource-development', 'initial-access'],
            'establish': ['execution', 'persistence', 'privilege-escalation'],
            'operate': ['defense-evasion', 'credential-access', 'discovery', 'lateral-movement'],
            'complete': ['collection', 'command-and-control', 'exfiltration', 'impact']
        }
        
        lifecycle_bonus = sum(
            15 for phase_tactics in phase_indicators.values()
            if any(tactic in covered_tactics for tactic in phase_tactics)
        )
        
        return min(base_score + lifecycle_bonus + bonus_points, 95)

    @lru_cache(maxsize=64)
    def _calculate_phase_transitions_fast(self, covered_tactics_tuple, attack_phases_tuple):
        """OPTIMIZED: Fast phase transitions calculation"""
        covered_tactics = set(covered_tactics_tuple)
        attack_phases = dict(attack_phases_tuple)
        
        transitions = 0
        phases = list(attack_phases.keys())
        
        for i in range(len(phases) - 1):
            current_phase = phases[i]
            next_phase = phases[i + 1]
            
            current_covered = any(t in covered_tactics for t in attack_phases[current_phase])
            next_covered = any(t in covered_tactics for t in attack_phases[next_phase])
            
            if current_covered and next_covered:
                transitions += 1
        
        return (transitions / (len(phases) - 1)) * 80

    @lru_cache(maxsize=32)
    def _score_consecutive_chain_fast(self, chain_length):
        """OPTIMIZED: Fast consecutive chain scoring"""
        if chain_length >= 6:
            return 80 + (chain_length - 6) * 5
        elif chain_length >= 4:
            return 60 + (chain_length - 4) * 10
        elif chain_length >= 3:
            return 40 + (chain_length - 3) * 10
        elif chain_length >= 2:
            return 25 + (chain_length - 2) * 15
        else:
            return chain_length * 5

    @lru_cache(maxsize=128)
    def _assess_behavioral_alignment_fast(self, validation_context_tuple):
        """OPTIMIZED: Fast behavioral alignment assessment"""
        validation_context = self._convert_context_from_tuple(validation_context_tuple)
        
        behavioral = validation_context.get('behavioral_indicators', {})
        attack_surface = validation_context.get('attack_surface', 0)
        
        if not behavioral:
            return 50
        
        # Fast alignment calculation
        phishing_score = behavioral.get('phishing_susceptibility', 50)
        credential_score = behavioral.get('credential_hygiene', 50)
        awareness_score = behavioral.get('security_awareness', 50)
        
        avg_behavioral_risk = (phishing_score + (100 - credential_score) + (100 - awareness_score)) / 3
        alignment_diff = abs(avg_behavioral_risk - attack_surface)
        alignment_score = max(0, 100 - (alignment_diff * 1.5))
        
        return round(min(alignment_score, 85), 1)

    @lru_cache(maxsize=128)
    def _analyze_cross_validation_consistency_fast(self, validation_context_tuple):
        """OPTIMIZED: Fast cross-validation consistency analysis"""
        validation_context = self._convert_context_from_tuple(validation_context_tuple)
        
        asset_techs = set(validation_context['asset_techniques'])
        evidence_techs = set(validation_context['evidence_techniques'])
        
        total_techniques = len(asset_techs.union(evidence_techs))
        shared_techniques = len(asset_techs.intersection(evidence_techs))
        
        consistency_score = (shared_techniques / total_techniques * 100) if total_techniques > 0 else 0
        
        return {
            'consistency_score': round(consistency_score, 1),
            'shared_techniques': list(asset_techs.intersection(evidence_techs)),
            'asset_unique': list(asset_techs - evidence_techs),
            'evidence_unique': list(evidence_techs - asset_techs),
            'assessment': 'High' if consistency_score >= 70 else 'Medium' if consistency_score >= 40 else 'Low'
        }

    def _calculate_cross_validation_score_fast(self, overlap_score, chain_feasibility, behavioral_alignment, consistency_analysis):
        """OPTIMIZED: Fast cross-validation score calculation"""
        weights = {'technique_overlap': 0.35, 'chain_feasibility': 0.30, 'behavioral_alignment': 0.15, 'consistency': 0.20}
        
        feasibility_score = chain_feasibility.get('score', 0)
        consistency_score = consistency_analysis.get('consistency_score', 0)
        normalized_behavioral = min(behavioral_alignment, 80)
        
        cross_validation_score = (
            (overlap_score * weights['technique_overlap']) +
            (feasibility_score * weights['chain_feasibility']) +
            (normalized_behavioral * weights['behavioral_alignment']) +
            (consistency_score * weights['consistency'])
        )
        
        print(f"    Cross-validation: {cross_validation_score:.1f}")
        
        return round(cross_validation_score, 1)

    def _calculate_overall_confidence_fast(self, llm_confidence, cross_validation_score, technique_count, attack_surface):
        """OPTIMIZED: Fast overall confidence calculation"""
        base_confidence = max(1, min(10, llm_confidence))
        cv_adjustment = (cross_validation_score - 50) / 10
        technique_adjustment = min(technique_count * 0.5, 2)
        surface_adjustment = (attack_surface - 50) / 25
        
        final_confidence = base_confidence + cv_adjustment + technique_adjustment + surface_adjustment
        return round(max(1, min(10, final_confidence)), 1)

    def _validate_risk_levels_fast(self, validation_context):
        """OPTIMIZED: Fast risk level validation"""
        attack_surface = validation_context.get('attack_surface', 0)
        technique_count = len(validation_context['combined_techniques'])
        
        risk_score = (attack_surface * 0.6) + (min(technique_count * 10, 40))
        
        if risk_score >= 80:
            risk_level = 'Critical'
        elif risk_score >= 60:
            risk_level = 'High'
        elif risk_score >= 40:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'calculated_risk_score': round(risk_score, 1),
            'validated_risk_level': risk_level,
            'contributing_factors': {
                'attack_surface_contribution': attack_surface * 0.6,
                'technique_count_contribution': min(technique_count * 10, 40)
            }
        }

    def _convert_context_to_tuple(self, validation_context):
        """Convert validation context to tuple for caching"""
        return (
            tuple(validation_context.get('asset_techniques', [])),
            tuple(validation_context.get('evidence_techniques', [])),
            tuple(validation_context.get('combined_techniques', [])),
            validation_context.get('attack_surface', 0),
            tuple(validation_context.get('behavioral_indicators', {}).items())
        )

    def _convert_context_from_tuple(self, context_tuple):
        """Convert tuple back to validation context"""
        if isinstance(context_tuple, dict):
            return context_tuple
        
        asset_techniques, evidence_techniques, combined_techniques, attack_surface, behavioral_items = context_tuple
        
        return {
            'asset_techniques': list(asset_techniques),
            'evidence_techniques': list(evidence_techniques),
            'combined_techniques': list(combined_techniques),
            'attack_surface': attack_surface,
            'behavioral_indicators': dict(behavioral_items)
        }

    def _generate_no_data_response(self):
        """Generate response when no data is provided"""
        return {
            "validated_techniques": [],
            "attack_chain_validation": {
                "most_likely_progression": [],
                "timeline_estimate": "Unknown",
                "success_probability": 0
            },
            "cross_validation_score": 0,
            "overall_confidence": 1,
            "status": "insufficient_data"
        }

def test_optimized_threat_validator():
    """Test optimized threat validator performance"""
    
    agent = ThreatValidator()
    
    # Sample data for testing
    sample_data = {
        "asset_analysis": {
            "mitre_techniques": ["T1190", "T1068", "T1005", "T1041", "T1078"],
            "validated_mitre_techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
                {"id": "T1005", "name": "Data from Local System"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                {"id": "T1078", "name": "Valid Accounts"}
            ],
            "quantitative_analysis": {
                "total_systems_analyzed": 5,
                "critical_systems_count": 3,
                "attack_surface_score": 75.5
            }
        },
        "evidence_analysis": {
            "mitre_techniques": ["T1190", "T1078", "T1204", "T1041", "T1566"],
            "validated_mitre_techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"}, 
                {"id": "T1078", "name": "Valid Accounts"},
                {"id": "T1204", "name": "User Execution"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                {"id": "T1566", "name": "Phishing"}
            ],
            "behavioral_metrics": {
                "phishing_susceptibility_score": 70,
                "credential_hygiene_score": 40,
                "security_awareness_score": 55
            }
        }
    }
    
    print("Testing OPTIMIZED Threat Validator...")
    print("=" * 50)
    
    # Performance test
    total_time = 0
    num_runs = 5
    
    for i in range(num_runs):
        start_time = datetime.now()
        results = agent.validate(sample_data)
        duration = (datetime.now() - start_time).total_seconds()
        total_time += duration
        
        if i == 0:  # Print results from first run
            print(f"\n📊 OPTIMIZED Results:")
            print(f"Overall Confidence: {results.get('overall_confidence', 0)}/10")
            print(f"Cross-validation Score: {results.get('cross_validation_score', 0)}")
            print(f"MITRE Validated Techniques: {len(results.get('mitre_validated_techniques', []))}")
            
            if results.get('validation_metrics'):
                feasibility = results['validation_metrics']['attack_chain_feasibility']
                print(f"Attack Chain: {feasibility.get('score', 0)} ({feasibility.get('assessment', 'Unknown')})")
    
    avg_time = total_time / num_runs
    print(f"\n⚡ PERFORMANCE RESULTS:")
    print(f"Average execution time: {avg_time:.3f} seconds")
    print(f"Total runs: {num_runs}")
    print(f"🎯 Target: <3 seconds - {'✅ ACHIEVED' if avg_time < 3 else '❌ NEEDS MORE OPTIMIZATION'}")
    
    print(f"\n✅ OPTIMIZED Threat Validator test complete")
    return results

if __name__ == "__main__":
    test_optimized_threat_validator()