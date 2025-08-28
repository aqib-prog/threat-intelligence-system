import sys
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent

class ScenarioGenerator(BaseAgent):
    def __init__(self):
        super().__init__("scenario_generator", "attack scenario generation and business impact modeling")
        
        # OPTIMIZATION: Enhanced caching system
        self._technique_cache = {}
        self._tactic_cache = {}
        self._tactic_sequence_cache = None
        self._recommendation_templates_cache = None
        self._business_impact_cache = {}
        self._technique_cache = {}


        
        # OPTIMIZATION: Pre-compiled regex patterns
        self.PATTERNS = {
            'technique_id': re.compile(r'T\d{4}(?:\.\d{3})?'),
            'money_amount': re.compile(r'\$(\d+\.?\d*)[MmBb]'),
            'time_range': re.compile(r'(\d+)-(\d+)\s*days?'),
        }
        
        # OPTIMIZATION: Pre-calculated constants
        self.BUSINESS_CONSTANTS = {
            'base_cost': 500000,
            'cost_per_record': 169,
            'max_records': 500000,
            'records_per_system': 25000
        }

    def get_system_prompt(self):
        return """Expert ScenarioGenerator for cybersecurity threat intelligence.

Expertise: Attack scenario creation, business impact modeling, executive narratives, timeline analysis.

Return JSON: executive_summary, calculated_business_impact, calculated_timeline, success_probability, detailed_attack_phases, prioritized_recommendations.
Focus: Realistic scenarios, industry-standard calculations, actionable recommendations."""

    def analyze(self, validation_results):
        """OPTIMIZED: Generate scenarios with parallel processing"""
        print("📋 Scenario Generator: Creating attack narratives...")
        
        if not validation_results:
            return self._generate_no_data_response()
        
        # OPTIMIZATION: Fast data extraction
        validated_techniques = self._extract_validated_techniques_fast(validation_results)
        
        max_scenario = int(os.getenv("MAX_SCENARIO_TECHNIQUES", "10"))
        validated_techniques = list(dict.fromkeys(validated_techniques))[:max_scenario]

        risk_level = validation_results.get('risk_level', 'Medium')
        overall_confidence = validation_results.get('overall_confidence', 7)
        
        # OPTIMIZATION: Single-pass context preparation
        scenario_context = {
            "validated_techniques": validated_techniques,
        "risk_level": risk_level,
        "confidence": overall_confidence,
        "system_inventory": self._extract_system_inventory_fast(validation_results),
        "behavioral_metrics": self._extract_behavioral_metrics_fast(validation_results)
        }

        # OPTIMIZATION: Fast path for small technique sets
        if len(validated_techniques) <= 2:
            print("  Using fast scenario generation for small technique set...")
            llm_results = {
                "executive_summary": {
                    "title": f"Targeted Attack Using {len(validated_techniques)} Techniques",
                    "overview": "Focused attack scenario based on validated threat intelligence",
                    "probability": "Medium"
                }
            }
        else:
            # Streamlined LLM prompt
            prompt = f"""
            Generate attack scenario for: {validated_techniques[:5]}  
            Risk: {risk_level}, Confidence: {overall_confidence}
            
            Return JSON with executive_summary, attack_progression, recommendations.
            """
            llm_results = self.analyze_with_llm(prompt, scenario_context)
        
        # Parse LLM results
        if isinstance(llm_results, str):
            try:
                llm_results = json.loads(llm_results)
            except:
                llm_results = {}
        
        # OPTIMIZATION: Parallel enhancement of all metrics
        enhanced_results = self._enhance_with_calculated_metrics_parallel(llm_results, scenario_context)
        
        return enhanced_results
    
    def _extract_validated_techniques_fast(self, validation_results):
        """OPTIMIZED: Fast technique extraction with prioritized lookup"""
        techniques = []
        
        # Single-pass extraction with prioritized fields
        for source in ['mitre_validated_techniques', 'validated_techniques']:
            if source in validation_results:
                data = validation_results[source]
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'id' in item:
                            techniques.append(item['id'])
                        elif isinstance(item, str) and self.PATTERNS['technique_id'].match(item):
                            techniques.append(item)
                break  # Stop at first successful extraction
        
        return list(set(techniques))
    
    def _extract_system_inventory_fast(self, validation_results):
        """OPTIMIZED: Fast system inventory extraction"""
        asset_data = validation_results.get('asset_analysis', {})
        qa = asset_data.get('quantitative_analysis', {})
        return {
            'total_systems': qa.get('total_systems_analyzed', 0),
            'critical_systems': qa.get('critical_systems_count', 0),
            'attack_surface': qa.get('attack_surface_score', 0)
        }
    
    def _extract_behavioral_metrics_fast(self, validation_results):
        """OPTIMIZED: Fast behavioral metrics extraction"""
        evidence_data = validation_results.get('evidence_analysis', {})
        return evidence_data.get('behavioral_metrics', {})
    
    def _enhance_with_calculated_metrics_parallel(self, llm_results, scenario_context):
        """OPTIMIZED: Parallel calculation of all scenario metrics (with caps)"""
        enhanced = llm_results.copy() if isinstance(llm_results, dict) else {}

    # 1) CAP the validated techniques right here (dedupe + limit)
        max_scenario = int(os.getenv("MAX_SCENARIO_TECHNIQUES", "10"))
        validated_techniques = list(dict.fromkeys(scenario_context.get('validated_techniques', [])))[:max_scenario]

    # keep the trimmed list in context going forward
        scenario_context = dict(scenario_context)
        scenario_context["validated_techniques"] = validated_techniques

    # Convert to tuples for cached funcs
        scenario_context_tuple = self._convert_scenario_context_to_tuple(scenario_context)
        validated_techniques_tuple = tuple(validated_techniques)

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
            'business_impact': executor.submit(self._calculate_business_impact_optimized, scenario_context_tuple),
            'timeline': executor.submit(self._calculate_attack_timeline_optimized, validated_techniques_tuple),
            'success_probability': executor.submit(self._calculate_success_probability_optimized, scenario_context_tuple),
            'attack_phases': executor.submit(self._generate_attack_phases_optimized, validated_techniques_tuple),
            'recommendations': executor.submit(self._generate_recommendations_optimized, validated_techniques_tuple, scenario_context_tuple),
            'narrative': executor.submit(self._create_executive_narrative_optimized, scenario_context_tuple),
        }

            enhanced['calculated_business_impact'] = futures['business_impact'].result()
            enhanced['calculated_timeline'] = futures['timeline'].result()
            enhanced['success_probability'] = futures['success_probability'].result()

        # 2) Post-process phases to CAP per-phase techniques
            per_phase_cap = int(os.getenv("MAX_TECHNIQUES_PER_PHASE", "4"))
            phases = futures['attack_phases'].result() or []
            for p in phases:
                if isinstance(p, dict):
                    if 'techniques' in p:
                        p['techniques'] = p['techniques'][:per_phase_cap]
                    if 'technique_details' in p and isinstance(p['technique_details'], list):
                        p['technique_details'] = p['technique_details'][:per_phase_cap]
            enhanced['detailed_attack_phases'] = phases

        # 3) Recommendations already capped downstream, but safe-guard here
            recs = futures['recommendations'].result() or []
            enhanced['prioritized_recommendations'] = recs[:8]

        # Add narrative after other calculations are done
            enhanced['executive_narrative'] = self._create_executive_narrative_with_results(
            scenario_context, enhanced
        )

        return enhanced

    
    @lru_cache(maxsize=128)
    def _calculate_business_impact_optimized(self, scenario_context_tuple):
        """OPTIMIZED: Fast business impact calculation with caching"""
        scenario_context = self._convert_scenario_context_from_tuple(scenario_context_tuple)
        
        systems = scenario_context.get('system_inventory', {})
        total_systems = systems.get('total_systems', 3)
        critical_systems = systems.get('critical_systems', 1)
        risk_level = scenario_context.get('risk_level', 'Medium')
        
        # OPTIMIZATION: Pre-calculated constants
        estimated_records = min(total_systems * self.BUSINESS_CONSTANTS['records_per_system'], 
                               self.BUSINESS_CONSTANTS['max_records'])
        record_cost = estimated_records * self.BUSINESS_CONSTANTS['cost_per_record']
        
        # OPTIMIZATION: Fast multiplier lookup
        multipliers = {'Critical': 3.5, 'High': 2.2, 'Medium': 1.4, 'Low': 1.0}
        multiplier = multipliers.get(risk_level, 1.4)
        if critical_systems > 2:
            multiplier = max(multiplier, 3.5)
        
        total_impact = (self.BUSINESS_CONSTANTS['base_cost'] + record_cost) * multiplier
        min_impact = total_impact * 0.7
        max_impact = total_impact * 1.3
        
        return {
            "estimated_records": estimated_records,
            "cost_per_record": self.BUSINESS_CONSTANTS['cost_per_record'],
            "range": f"${min_impact/1000000:.1f}M - ${max_impact/1000000:.1f}M",
            "methodology": "Based on IBM Cost of Data Breach 2024 report"
        }
    
    @lru_cache(maxsize=256)
    def _calculate_attack_timeline_optimized(self, validated_techniques_tuple):
        """OPTIMIZED: Fast timeline calculation with caching"""
        validated_techniques = list(validated_techniques_tuple)
        
        if not validated_techniques:
            return {"min_days": 2, "max_days": 7, "range": "2-7 days", "methodology": "Default estimate"}
        
        # OPTIMIZATION: Batch get technique details with enhanced caching
        technique_details = self._get_techniques_batch_optimized(validated_techniques)
        
        # OPTIMIZATION: Vectorized complexity calculation
        total_complexity = 0
        tactic_count = set()
        
        # Pre-calculated tactic weights for performance
        tactic_weights = {
            'initial-access': 1,
            'persistence': 2,
            'lateral-movement': 3,
            'exfiltration': 1
        }
        
        for tech_id, details in technique_details.items():
            tactics = details.get('tactics', [])
            tactic_count.update(tactics)
            
            # Fast complexity calculation
            complexity = len(tactics)  # Base complexity
            for tactic in tactics:
                complexity += tactic_weights.get(tactic, 0)
            
            total_complexity += complexity
        
        # OPTIMIZATION: Fast timeline calculation
        base_days = max(total_complexity / 2, 1)
        tactic_bonus = len(tactic_count) * 0.5
        
        min_days = max(int(base_days), 2)
        max_days = min(int(base_days + tactic_bonus), 30)
        
        return {
            "min_days": min_days,
            "max_days": max_days,
            "range": f"{min_days}-{max_days} days",
            "methodology": "Dynamic calculation based on MITRE tactic complexity",
            "complexity_factors": {
                "total_complexity": total_complexity,
                "unique_tactics": len(tactic_count),
                "techniques_analyzed": len(technique_details)
            }
        }
    
    @lru_cache(maxsize=128)
    def _calculate_success_probability_optimized(self, scenario_context_tuple):
        """OPTIMIZED: Fast success probability calculation with caching"""
        scenario_context = self._convert_scenario_context_from_tuple(scenario_context_tuple)
        
        validated_techniques = scenario_context.get('validated_techniques', [])
        behavioral = scenario_context.get('behavioral_metrics', {})
        
        if not validated_techniques:
            return {"probability": 0.5, "percentage": "50%", "assessment": "Medium"}
        
        # OPTIMIZATION: Batch technique details
        technique_details = self._get_techniques_batch_optimized(validated_techniques)
        
        base_probability = 0.6  # 60% baseline
        
        # OPTIMIZATION: Pre-calculated tactic probability modifiers
        tactic_modifiers = {
            'initial-access': 0.08,
            'persistence': 0.05,
            'credential-access': 0.12,
            'lateral-movement': 0.06,
            'exfiltration': 0.04
        }
        
        # Fast probability calculation
        for tech_id, details in technique_details.items():
            tactics = details.get('tactics', [])
            for tactic in tactics:
                base_probability += tactic_modifiers.get(tactic, 0)
        
        # OPTIMIZATION: Fast behavioral factor application
        phishing_score = behavioral.get('phishing_susceptibility_score', 50)
        credential_score = behavioral.get('credential_hygiene_score', 50)
        
        if phishing_score > 70:
            base_probability += 0.10
        if credential_score < 40:
            base_probability += 0.08
        
        final_probability = min(max(base_probability, 0.2), 0.9)
        
        assessments = {True: "High", False: "Medium"} if final_probability >= 0.7 else {True: "Medium", False: "Low"}
        assessment = assessments[final_probability >= 0.5]
        
        return {
            "probability": final_probability,
            "percentage": f"{final_probability*100:.0f}%",
            "assessment": assessment
        }
    
    @lru_cache(maxsize=256)
    def _generate_attack_phases_optimized(self, validated_techniques_tuple):
        """OPTIMIZED: Fast attack phases generation with caching"""
        validated_techniques = list(validated_techniques_tuple)
        
        if not validated_techniques:
            return []
        
        # OPTIMIZATION: Cached tactic-to-phase mapping
        tactic_phases = self._get_tactic_phases_mapping_cached()
        technique_details = self._get_techniques_batch_optimized(validated_techniques)
        
        # OPTIMIZATION: Fast phase grouping
        phase_groups = {}
        for tech_id, details in technique_details.items():
            tactics = details.get('tactics', [])
            for tactic in tactics:
                phase = tactic_phases.get(tactic, tactic.replace('-', ' ').title())
                if phase not in phase_groups:
                    phase_groups[phase] = []
                phase_groups[phase].append({
                    'id': tech_id,
                    'name': details.get('name', ''),
                    'tactic': tactic
                })
        
        # OPTIMIZATION: Pre-defined phase order
        phase_order = [
            'Initial Access', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery',
            'Lateral Movement', 'Collection', 'Command and Control',
            'Exfiltration', 'Impact'
        ]
        
        # Fast phase creation
        ordered_phases = []
        day_counter = 1
        
        for phase_name in phase_order:
            if phase_name in phase_groups:
                techniques_in_phase = phase_groups[phase_name]
                timeline_days = max(len(techniques_in_phase), 1)
                
                ordered_phases.append({
                    "phase": phase_name,
                    "techniques": [t['id'] for t in techniques_in_phase],
                    "technique_details": techniques_in_phase,
                    "timeline": f"Days {day_counter}-{day_counter + timeline_days - 1}",
                    "duration_days": timeline_days,
                    "description": self._generate_phase_description_fast(phase_name, techniques_in_phase),
                    "business_impact": self._get_phase_business_impact_fast(phase_name)
                })
                day_counter += timeline_days
        
        return ordered_phases
    
    def _get_techniques_batch_optimized(self, technique_ids):
        """OPTIMIZED: Enhanced batch query with multi-level caching"""
        if not technique_ids:
            return {}
        
        # OPTIMIZATION: Batch cache key
        cache_key = '|'.join(sorted(technique_ids))
        if cache_key in self._technique_cache:
            return self._technique_cache[cache_key]
        
        # Check individual cache
        cached_results = {}
        uncached_ids = []
        
        for tech_id in technique_ids:
            individual_key = f"tech_{tech_id}"
            if individual_key in self._technique_cache:
                cached_results[tech_id] = self._technique_cache[individual_key]
            else:
                uncached_ids.append(tech_id)
        
        # Batch query uncached techniques
        if uncached_ids:
            try:
                placeholders = ','.join(['?' for _ in uncached_ids])
                query = f"SELECT id, name, tactic_ids, description FROM techniques WHERE id IN ({placeholders})"
                results = self.query_mitre_db(query, uncached_ids)
                
                for result in results:
                    tech_id = result[0]
                    tactics = json.loads(result[2]) if result[2] else []
                    tech_data = {
                        'name': result[1],
                        'tactics': tactics,
                        'description': result[3] or ''
                    }
                    # Cache individual and batch
                    self._technique_cache[f"tech_{tech_id}"] = tech_data
                    cached_results[tech_id] = tech_data
                    
            except Exception as e:
                print(f"Error in batch query: {e}")
        
        # Cache batch result
        self._technique_cache[cache_key] = cached_results
        
        return cached_results
    
    @lru_cache(maxsize=64)
    def _get_tactic_phases_mapping_cached(self):
        """OPTIMIZED: Cached tactic to phase mapping"""
        if self._tactic_sequence_cache is not None:
            return self._tactic_sequence_cache
        
        try:
            query = "SELECT short_name, name FROM tactics WHERE short_name IS NOT NULL"
            results = self.query_mitre_db(query)
            
            mapping = {}
            for result in results:
                short_name = result[0]
                name = result[1]
                mapping[short_name] = name
                
            self._tactic_sequence_cache = mapping
            return mapping
                
        except Exception as e:
            print(f"Error getting tactic phases: {e}")
            # Fallback mapping
            fallback = {
                'initial-access': 'Initial Access',
                'persistence': 'Persistence',
                'privilege-escalation': 'Privilege Escalation',
                'defense-evasion': 'Defense Evasion',
                'credential-access': 'Credential Access',
                'discovery': 'Discovery',
                'lateral-movement': 'Lateral Movement',
                'collection': 'Collection',
                'command-and-control': 'Command and Control',
                'exfiltration': 'Exfiltration',
                'impact': 'Impact'
            }
            self._tactic_sequence_cache = fallback
            return fallback
    
    @lru_cache(maxsize=256)
    def _generate_recommendations_optimized(self, validated_techniques_tuple, scenario_context_tuple):
        """OPTIMIZED: Fast recommendations generation with caching"""
        validated_techniques = list(validated_techniques_tuple)
        scenario_context = self._convert_scenario_context_from_tuple(scenario_context_tuple)
        
        if not validated_techniques:
            return ["Implement basic security monitoring and controls"]
        
        # OPTIMIZATION: Batch get technique details
        technique_details = self._get_techniques_batch_optimized(validated_techniques)
        
        # Collect all tactics
        all_tactics = set()
        for details in technique_details.values():
            all_tactics.update(details.get('tactics', []))
        
        # OPTIMIZATION: Pre-defined tactic recommendations
        tactic_recommendations = {
            'initial-access': 'Deploy network segmentation and access controls',
            'persistence': 'Implement endpoint detection and response (EDR) solutions',
            'privilege-escalation': 'Apply principle of least privilege and privilege access management',
            'defense-evasion': 'Deploy advanced threat detection and behavioral analysis',
            'credential-access': 'Implement multi-factor authentication and credential monitoring',
            'discovery': 'Deploy network monitoring and anomaly detection',
            'lateral-movement': 'Implement network segmentation and micro-segmentation',
            'collection': 'Deploy data loss prevention (DLP) and monitoring solutions',
            'command-and-control': 'Implement network traffic analysis and DNS filtering',
            'exfiltration': 'Deploy data loss prevention and network egress monitoring',
            'impact': 'Implement backup and recovery procedures with business continuity planning'
        }
        
        # Fast recommendation collection
        recommendations = []
        for tactic in all_tactics:
            if tactic in tactic_recommendations:
                recommendations.append(tactic_recommendations[tactic])
        
        # Add behavioral recommendations
        behavioral = scenario_context.get('behavioral_metrics', {})
        if behavioral.get('phishing_susceptibility_score', 0) > 70:
            recommendations.append("Implement advanced phishing simulation and training programs")
        
        if behavioral.get('credential_hygiene_score', 0) < 40:
            recommendations.append("Deploy multi-factor authentication and password management solutions")
        
        # Deduplicate and limit
        unique_recommendations = list(set(recommendations))
        return unique_recommendations[:8]
    
    def _create_executive_narrative_optimized(self, scenario_context):
        """OPTIMIZED: Fast executive narrative creation"""
        techniques = scenario_context.get('validated_techniques', [])
        risk_level = scenario_context.get('risk_level', 'Medium')
        
        # Fast narrative template
        narrative = f"""
        Executive Summary: Threat actors deploy {len(techniques)} validated attack techniques in {risk_level.lower()} risk scenario.
        
        This assessment leverages current threat intelligence and real-world attack patterns for strategic security planning.
        """
        
        return narrative.strip()
    
    def _create_executive_narrative_with_results(self, scenario_context, enhanced_results):
        """Create comprehensive narrative with calculated results"""
        techniques = scenario_context.get('validated_techniques', [])
        impact = enhanced_results.get('calculated_business_impact', {}).get('range', 'Significant')
        timeline = enhanced_results.get('calculated_timeline', {}).get('range', 'Several days')
        probability = enhanced_results.get('success_probability', {}).get('percentage', '50%')
        
        narrative = f"""
        Executive Summary: Sophisticated threat actors launch targeted campaign using {len(techniques)} validated attack techniques.
        
        Attack Timeline: The attack progresses over {timeline}, leveraging modern techniques for rapid system compromise.
        
        Business Impact: Estimated financial impact ranges from {impact}, including incident response costs, regulatory compliance, and business disruption.
        
        Success Probability: {probability} likelihood based on current security posture and validated threat intelligence.
        
        This assessment is based on real-world attack patterns and current threat landscape data from 2024 incident reports.
        """
        
        return narrative.strip()
    
    def _generate_phase_description_fast(self, phase_name, techniques):
        """OPTIMIZED: Fast phase description generation"""
        if not techniques:
            return f"Execute {phase_name} activities"
        
        technique_names = [t.get('name', t.get('id', '')) for t in techniques[:3]]
        technique_list = ', '.join(technique_names)
        
        if len(techniques) > 3:
            technique_list += f" and {len(techniques) - 3} other techniques"
        
        return f"Attackers execute {phase_name} using {technique_list}."
    
    @lru_cache(maxsize=32)
    def _get_phase_business_impact_fast(self, phase_name):
        """OPTIMIZED: Fast business impact lookup with caching"""
        impact_mappings = {
            'Initial Access': 'Establishes attacker foothold, potential for undetected access',
            'Persistence': 'Long-term system compromise, ongoing security risk',
            'Privilege Escalation': 'Increased access to sensitive systems and data',
            'Defense Evasion': 'Reduced visibility into attack activities',
            'Credential Access': 'Risk of account compromise and unauthorized access',
            'Discovery': 'Information gathering phase, maps network topology',
            'Lateral Movement': 'Expansion of attack scope across network systems',
            'Collection': 'Data aggregation phase, privacy and compliance concerns',
            'Command and Control': 'Remote control capabilities established',
            'Exfiltration': 'Data theft, regulatory violations, customer notification requirements',
            'Impact': 'Direct business disruption, system availability issues'
        }
        
        return impact_mappings.get(phase_name, f"Business impact from {phase_name} activities")
    
    def _convert_scenario_context_to_tuple(self, scenario_context):
        """Convert scenario context to tuple for caching"""
        return (
            tuple(scenario_context.get('validated_techniques', [])),
            scenario_context.get('risk_level', 'Medium'),
            scenario_context.get('confidence', 7),
            tuple(scenario_context.get('system_inventory', {}).items()),
            tuple(scenario_context.get('behavioral_metrics', {}).items())
        )
    
    def _convert_scenario_context_from_tuple(self, context_tuple):
        """Convert tuple back to scenario context"""
        if isinstance(context_tuple, dict):
            return context_tuple
        
        validated_techniques, risk_level, confidence, system_inventory_items, behavioral_items = context_tuple
        
        return {
            'validated_techniques': list(validated_techniques),
            'risk_level': risk_level,
            'confidence': confidence,
            'system_inventory': dict(system_inventory_items),
            'behavioral_metrics': dict(behavioral_items)
        }
    
    def _generate_no_data_response(self):
        """Generate response when no data is provided"""
        return {
            "executive_summary": {
                "title": "Insufficient Data for Scenario Generation",
                "overview": "Unable to generate attack scenarios without validated threat intelligence",
                "business_impact": "Cannot calculate without data",
                "timeline": "Unknown",
                "probability": "Cannot assess"
            },
            "calculated_business_impact": {
                "range": "Unable to calculate",
                "methodology": "Insufficient data"
            },
            "status": "insufficient_data"
        }

def test_scenario_generator_dynamics():
    """Test if ScenarioGenerator returns dynamic results based on input complexity"""
    
    try:
        from agents.scenario_generator import ScenarioGenerator
    except ImportError as e:
        print(f"Error importing ScenarioGenerator: {e}")
        return False
    
    generator = ScenarioGenerator()
    
    print("Testing Scenario Generator Dynamic Behavior...")
    print("=" * 60)
    
    # Test Case 1: High complexity input (many techniques, high risk)
    print("\n🧪 TEST 1: High Complexity Input (Many Techniques + High Risk)")
    high_complexity = {
        "mitre_validated_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1083", "name": "File and Directory Discovery"},
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1491", "name": "Defacement"}
        ],
        "risk_level": "VeryHigh",
        "overall_confidence": 9,
        "asset_analysis": {
            "quantitative_analysis": {
                "total_systems_analyzed": 8,
                "critical_systems_count": 6,
                "attack_surface_score": 85
            }
        },
        "evidence_analysis": {
            "behavioral_metrics": {
                "phishing_susceptibility_score": 75,
                "credential_hygiene_score": 35
            }
        }
    }
    
    result1 = generator.analyze(high_complexity)
    phases1 = len(result1.get('detailed_attack_phases', []))
    recommendations1 = len(result1.get('prioritized_recommendations', []))
    timeline1 = result1.get('calculated_timeline', {}).get('range', 'Unknown')
    impact1 = result1.get('calculated_business_impact', {}).get('range', 'Unknown')
    
    print(f"  Attack Phases: {phases1}")
    print(f"  Recommendations: {recommendations1}")
    print(f"  Timeline: {timeline1}")
    print(f"  Business Impact: {impact1}")
    
    # Test Case 2: Medium complexity input (moderate techniques, medium risk)
    print("\n🧪 TEST 2: Medium Complexity Input (Moderate Techniques + Medium Risk)")
    medium_complexity = {
        "mitre_validated_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1005", "name": "Data from Local System"}
        ],
        "risk_level": "Medium",
        "overall_confidence": 6,
        "asset_analysis": {
            "quantitative_analysis": {
                "total_systems_analyzed": 3,
                "critical_systems_count": 1,
                "attack_surface_score": 55
            }
        },
        "evidence_analysis": {
            "behavioral_metrics": {
                "phishing_susceptibility_score": 45,
                "credential_hygiene_score": 60
            }
        }
    }
    
    result2 = generator.analyze(medium_complexity)
    phases2 = len(result2.get('detailed_attack_phases', []))
    recommendations2 = len(result2.get('prioritized_recommendations', []))
    timeline2 = result2.get('calculated_timeline', {}).get('range', 'Unknown')
    impact2 = result2.get('calculated_business_impact', {}).get('range', 'Unknown')
    
    print(f"  Attack Phases: {phases2}")
    print(f"  Recommendations: {recommendations2}")
    print(f"  Timeline: {timeline2}")
    print(f"  Business Impact: {impact2}")
    
    # Test Case 3: Low complexity input (few techniques, low risk)
    print("\n🧪 TEST 3: Low Complexity Input (Few Techniques + Low Risk)")
    low_complexity = {
        "mitre_validated_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing"}
        ],
        "risk_level": "Low",
        "overall_confidence": 4,
        "asset_analysis": {
            "quantitative_analysis": {
                "total_systems_analyzed": 1,
                "critical_systems_count": 0,
                "attack_surface_score": 25
            }
        },
        "evidence_analysis": {
            "behavioral_metrics": {
                "phishing_susceptibility_score": 25,
                "credential_hygiene_score": 80
            }
        }
    }
    
    result3 = generator.analyze(low_complexity)
    phases3 = len(result3.get('detailed_attack_phases', []))
    recommendations3 = len(result3.get('prioritized_recommendations', []))
    timeline3 = result3.get('calculated_timeline', {}).get('range', 'Unknown')
    impact3 = result3.get('calculated_business_impact', {}).get('range', 'Unknown')
    
    print(f"  Attack Phases: {phases3}")
    print(f"  Recommendations: {recommendations3}")
    print(f"  Timeline: {timeline3}")
    print(f"  Business Impact: {impact3}")
    
    # Test Case 4: Empty/minimal input
    print("\n🧪 TEST 4: Empty/Minimal Input")
    minimal_input = {
        "mitre_validated_techniques": [],
        "risk_level": "Low",
        "overall_confidence": 2,
        "asset_analysis": {
            "quantitative_analysis": {
                "total_systems_analyzed": 0,
                "critical_systems_count": 0,
                "attack_surface_score": 0
            }
        }
    }
    
    result4 = generator.analyze(minimal_input)
    phases4 = len(result4.get('detailed_attack_phases', []))
    recommendations4 = len(result4.get('prioritized_recommendations', []))
    timeline4 = result4.get('calculated_timeline', {}).get('range', 'Unknown')
    impact4 = result4.get('calculated_business_impact', {}).get('range', 'Unknown')
    
    print(f"  Attack Phases: {phases4}")
    print(f"  Recommendations: {recommendations4}")
    print(f"  Timeline: {timeline4}")
    print(f"  Business Impact: {impact4}")
    
    # Analysis
    phases_results = [phases1, phases2, phases3, phases4]
    rec_results = [recommendations1, recommendations2, recommendations3, recommendations4]
    
    phases_unique = set(phases_results)
    rec_unique = set(rec_results)
    
    is_dynamic_phases = len(phases_unique) > 1
    is_dynamic_recs = len(rec_unique) > 1
    
    print(f"\n📊 RESULTS SUMMARY:")
    print(f"High Complexity: {phases1} phases, {recommendations1} recommendations")
    print(f"Medium Complexity: {phases2} phases, {recommendations2} recommendations")
    print(f"Low Complexity: {phases3} phases, {recommendations3} recommendations")
    print(f"Minimal Input: {phases4} phases, {recommendations4} recommendations")
    
    print(f"\n🎯 ANALYSIS:")
    print(f"Attack Phases: {phases_results} - Unique: {sorted(phases_unique)}")
    print(f"Recommendations: {rec_results} - Unique: {sorted(rec_unique)}")
    print(f"Phases Dynamic: {'✅ YES' if is_dynamic_phases else '❌ NO'}")
    print(f"Recommendations Dynamic: {'✅ YES' if is_dynamic_recs else '❌ NO'}")
    
    # Check logical progression (high complexity should have more phases/recommendations)
    if phases1 >= phases2 >= phases3 and recommendations1 >= recommendations2 >= recommendations3:
        print(f"✅ Logical progression - Higher complexity yields more content")
    else:
        print(f"⚠️ Unexpected progression in phases or recommendations")
    
    # Check timeline and impact variation
    timelines = [timeline1, timeline2, timeline3, timeline4]
    impacts = [impact1, impact2, impact3, impact4]
    
    timeline_unique = set(timelines)
    impact_unique = set(impacts)
    
    print(f"Timeline Variation: {'✅ YES' if len(timeline_unique) > 1 else '❌ NO'} - {sorted(timeline_unique)}")
    print(f"Impact Variation: {'✅ YES' if len(impact_unique) > 1 else '❌ NO'} - {sorted(impact_unique)}")
    
    # Overall dynamic assessment
    overall_dynamic = is_dynamic_phases and is_dynamic_recs and len(timeline_unique) > 1 and len(impact_unique) > 1
    
    return overall_dynamic

if __name__ == "__main__":
    is_dynamic = test_scenario_generator_dynamics()
    
    if is_dynamic:
        print(f"\n🎉 Scenario Generator is DYNAMIC - Ready for WorkflowExecutor Fix #3")
    else:
        print(f"\n🔧 Scenario Generator may need fixes - Check for hardcoded behavior")