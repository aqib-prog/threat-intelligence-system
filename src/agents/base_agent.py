import os
import json
import time
import sqlite3
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv
import re
from pathlib import Path  # NEW

# Load environment variables
load_dotenv()

class BaseAgent:
    def __init__(self, agent_name, agent_role):
        self.agent_name = agent_name
        self.agent_role = agent_role
        self.groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))
        self.model = 'llama3-70b-8192'
        self.db_path = self._resolve_db_path()  # CHANGED

    def _resolve_db_path(self):
        """
        Resolve absolute path to mitre_cache.db robustly.
        Priority: MITRE_DB_PATH env → common repo locations (relative to this file).
        """
        # 1) Env override
        env = os.getenv("MITRE_DB_PATH")
        if env and Path(env).is_file():
            print(f"[MITRE] Using DB from MITRE_DB_PATH={env}")
            return str(Path(env).resolve())

        here = Path(__file__).resolve()
        candidates = [
            here.parents[2] / "src" / "data" / "mitre_cache.db",  # .../src/agents/base_agent.py -> up to repo/src/data
            here.parents[1] / "data" / "mitre_cache.db",          # .../agents/data/...
            here.parents[1] / "db" / "mitre_cache.db",            # .../agents/db/...
            here.parent / "mitre_cache.db",                       # .../agents/mitre_cache.db
        ]
        for p in candidates:
            if p.is_file():
                print(f"[MITRE] Using DB at {p}")
                return str(p.resolve())

        # Last resort: original relative path (in case you run from repo root)
        fallback = Path("src/data/mitre_cache.db")
        if fallback.is_file():
            print(f"[MITRE] Using DB at {fallback.resolve()}")
            return str(fallback.resolve())

        raise FileNotFoundError(
            "mitre_cache.db not found. Set MITRE_DB_PATH or place the DB in one of: "
            + ", ".join(str(p) for p in candidates + [fallback])
        )

    def get_system_prompt(self):
        return f"You are a {self.agent_role} expert in cybersecurity threat intelligence"

    def query_mitre_db(self, query, params=None):
        """
        Query MITRE database (read-only, resilient).
        """
        try:
            # Open read-only with URI to avoid accidental writes
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute(query, params or [])
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            print(f"[MITRE][ERROR] {e} (path={self.db_path})")
            return []

    def search_techniques(self, search_terms):
        """
        Search for relevant MITRE techniques (case-insensitive, safe JSON decode).
        """
        if isinstance(search_terms, str):
            search_terms = [search_terms]

        techniques = []
        for term in search_terms:
            term_l = f"%{term.lower()}%"
            query = '''
                SELECT id, name, description, tactic_ids, platforms, domain
                FROM techniques
                WHERE lower(name) LIKE ? OR lower(description) LIKE ?
                LIMIT 10
            '''
            results = self.query_mitre_db(query, (term_l, term_l))

            for row in results:
                t_id, name, desc, tactic_ids, platforms, domain = row
                # tactic_ids/platforms are TEXT; attempt JSON parse, else fallback to comma-split
                def _safe_json_or_list(v):
                    if not v:
                        return []
                    try:
                        out = json.loads(v)
                        return out if isinstance(out, list) else [out]
                    except Exception:
                        return [x.strip() for x in v.split(',') if x.strip()]

                techniques.append({
                    'id': t_id,
                    'name': name,
                    'description': (desc or '')[:200] + '...' if desc else '',
                    'tactics': _safe_json_or_list(tactic_ids),
                    'platforms': _safe_json_or_list(platforms),
                    'domain': domain
                })
        return techniques

    def analyze_with_llm(self, prompt, context_data, max_retries=3):
        time.sleep(2)  # rate limiting (free tier)
        system_prompt = self.get_system_prompt()
        context_str = json.dumps(context_data, indent=2) if isinstance(context_data, dict) else str(context_data)
        full_prompt = f"""
Context Data:
{context_str}

Analysis Request:
{prompt}

Please provide structured analysis with:
1. Key findings
2. MITRE ATT&CK technique mappings (use technique IDs like T1566)
3. Risk assessment (High/Medium/Low)
4. Specific actionable recommendations
5. Confidence level (1-10)

Format your response as valid JSON with these keys:
- findings
- mitre_techniques
- risk_level
- recommendations
- confidence
"""
        for attempt in range(max_retries):
            try:
                completion = self.groq_client.chat.completions.create(
                    messages=[{"role": "system", "content": system_prompt},
                              {"role": "user", "content": full_prompt}],
                    model=self.model,
                    temperature=0.1,
                    max_tokens=4000
                )
                response_text = completion.choices[0].message.content
                try:
                    return json.loads(response_text)
                except json.JSONDecodeError:
                    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                    if m:
                        try:
                            return json.loads(m.group(1))
                        except json.JSONDecodeError:
                            pass
                    return {
                        "findings": response_text,
                        "mitre_techniques": [],
                        "risk_level": "Medium",
                        "recommendations": [],
                        "confidence": 7
                    }
            except Exception as e:
                print(f"LLM attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:
                    return self.fallback_analysis(prompt, context_data)
                time.sleep(5)

    def fallback_analysis(self, prompt, context_data):
        return {
            "findings": f"Analysis failed for {self.agent_name}. Using fallback logic.",
            "mitre_techniques": ["T1566"],
            "risk_level": "Medium",
            "recommendations": ["Implement basic security controls"],
            "confidence": 3,
            "fallback": True
        }

    def validate_mitre_techniques(self, technique_ids):
        if not technique_ids:
            return []
        valid = []
        for tech_item in technique_ids:
            tech_id = tech_item.get('id') if isinstance(tech_item, dict) else str(tech_item)
            if not tech_id or tech_id == '{}':
                continue
            rows = self.query_mitre_db('SELECT id, name FROM techniques WHERE id = ?', (tech_id,))
            if rows:
                valid.append({'id': tech_id, 'name': rows[0][1]})
        return valid

    def log_analysis(self, input_data, output_data):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": self.agent_name,
            "input_size": len(str(input_data)),
            "output_size": len(str(output_data)),
            "success": not output_data.get('fallback', False)
        }
        log_file = f"src/data/{self.agent_name}_log.json"
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
    def reset_caches(self):
        """
    Clear all known dict caches, nullable caches, and any @lru_cache
    on this agent. Safe to call even if attributes don't exist.
    """
    # 1) Clear dict-like caches (anything with 'cache' in the name)
        for name, val in list(self.__dict__.items()):
            if isinstance(val, dict) and ('cache' in name or name.endswith('_cache')):
                val.clear()
    
    # 2) Reset common None-able caches used by some agents
        for name in (
        '_tactic_sequence_cache',
        '_recommendation_templates_cache',
        '_system_analysis_cache',
        '_business_impact_cache',
    ):
            if hasattr(self, name):
                setattr(self, name, None)
    
    # 3) Clear @lru_cache functions if present on this instance
        for fn_name in (
        '_discover_mitre_techniques_dynamic',
        '_calculate_business_impact_optimized',
        '_calculate_attack_timeline_optimized',
        '_calculate_success_probability_optimized',
        '_generate_attack_phases_optimized',
        '_get_tactic_phases_mapping_cached',
        '_generate_recommendations_optimized',
    ):
            fn = getattr(self, fn_name, None)
            if fn is not None and hasattr(fn, 'cache_clear'):
                try:
                    fn.cache_clear()
                except Exception:
                    pass


if __name__ == "__main__":
    agent = BaseAgent("test_agent", "test role")
    techniques = agent.search_techniques("phishing")
    print(f"Found {len(techniques)} phishing techniques")
