import requests
import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

class RobustMITREManager:
    def __init__(self):
        self.db_path = "src/data/mitre_cache.db"
        self.data_dir = Path("src/data")
        self.data_dir.mkdir(exist_ok=True)
        
        # API endpoints
        self.static_urls = {
            'enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
            'mobile': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
            'ics': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json'
        }

        self.taxii_base = 'https://attack-taxii.mitre.org'

    def setup_database(self):
        """Create comprehensive MITRE database schema"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        #Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS techniques (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                tactic_ids TEXT,
                platforms TEXT,
                data_sources TEXT,
                detection TEXT,
                mitigation_ids TEXT,
                permissions_required TEXT,
                domain TEXT,
                version TEXT,
                created TEXT,
                modified TEXT,
                revoked BOOLEAN DEFAULT 0,
                external_references TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tactics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                short_name TEXT,
                domain TEXT,
                created TEXT,
                modified TEXT,
                external_references TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                aliases TEXT,
                techniques_used TEXT,
                domain TEXT,
                created TEXT,
                modified TEXT,
                external_references TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS software (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                type TEXT,
                platforms TEXT,
                techniques_used TEXT,
                domain TEXT,
                created TEXT,
                modified TEXT,
                external_references TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mitigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                techniques_mitigated TEXT,
                domain TEXT,
                created TEXT,
                modified TEXT,
                external_references TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                domain TEXT,
                updated_at TEXT
            )
        ''')
        
        # Create indexes for fast queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_techniques_name ON techniques(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_techniques_domain ON techniques(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_groups_name ON threat_groups(name)')
        
        conn.commit()
        conn.close()
        print("Database schema created with indexes")
    

    def download_domain_data(self, domain):
        """Download data for specific domain with fallbacks"""
        print(f"Downloading {domain} data...")
        
        # Try static API first
        try:
            url = self.static_urls[domain]
            response = requests.get(url, timeout=120)
            response.raise_for_status()
            
            data = response.json()
            
            # Save raw data
            with open(f"src/data/{domain}_raw.json", 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"PASSED Downloaded {domain}: {len(data.get('objects', []))} objects")
            return data
            
        except Exception as e:
            print(f"FAILED Static download failed for {domain}: {str(e)}")
            
            # Fallback to TAXII if available
            return self.download_from_taxii(domain)
    
    def download_from_taxii(self, domain):
        """Fallback: Download from TAXII API"""
        try:
            # Load collection IDs from test results
            with open('src/data/api_test_results.json', 'r') as f:
                test_results = json.load(f)
            
            collections = test_results['taxii_api']['collections']
            if domain not in collections:
                raise Exception(f"No TAXII collection for {domain}")
            
            collection_id = collections[domain]['id']
            headers = {'Accept': 'application/taxii+json;version=2.1'}
            
            # Download in chunks
            all_objects = []
            limit = 1000
            offset = 0
            
            while True:
                url = f"{self.taxii_base}/api/v21/collections/{collection_id}/objects?limit={limit}&offset={offset}"
                response = requests.get(url, headers=headers, timeout=60)
                
                if response.status_code != 200:
                    break
                
                data = response.json()
                objects = data.get('objects', [])
                
                if not objects:
                    break
                
                all_objects.extend(objects)
                offset += limit
                print(f"Downloaded {len(all_objects)} objects from TAXII...")
                
                if len(objects) < limit:
                    break
            
            result = {'objects': all_objects}
            
            # Save TAXII data
            with open(f"src/data/{domain}_taxii.json", 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"PASSED TAXII download {domain}: {len(all_objects)} objects")
            return result
            
        except Exception as e:
            print(f"FAILED TAXII download failed for {domain}: {str(e)}")
            return None
        
    
    def process_and_store(self, domain, data):
        """Process and store domain data in database"""
        if not data or 'objects' not in data:
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        counters = {'techniques': 0, 'tactics': 0, 'groups': 0, 'software': 0, 'mitigations': 0}
        
        for obj in data['objects']:
            try:
                obj_type = obj.get('type', '')
                
                if obj_type == 'attack-pattern':
                    self._store_technique(cursor, obj, domain)
                    counters['techniques'] += 1
                    
                elif obj_type == 'x-mitre-tactic':
                    self._store_tactic(cursor, obj, domain)
                    counters['tactics'] += 1
                    
                elif obj_type == 'intrusion-set':
                    self._store_group(cursor, obj, domain)
                    counters['groups'] += 1
                    
                elif obj_type in ['malware', 'tool']:
                    self._store_software(cursor, obj, domain)
                    counters['software'] += 1
                    
                elif obj_type == 'course-of-action':
                    self._store_mitigation(cursor, obj, domain)
                    counters['mitigations'] += 1
                    
            except Exception as e:
                print(f"Error processing {obj.get('id', 'unknown')}: {str(e)}")
                continue
        
        # Update metadata
        cursor.execute('''
            INSERT OR REPLACE INTO metadata VALUES (?, ?, ?, ?)
        ''', (f'{domain}_last_update', datetime.now().isoformat(), domain, datetime.now().isoformat()))
        
        for obj_type, count in counters.items():
            cursor.execute('''
                INSERT OR REPLACE INTO metadata VALUES (?, ?, ?, ?)
            ''', (f'{domain}_{obj_type}_count', str(count), domain, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        print(f"PASSED: Stored {domain}: {counters}")
        return True
    
    def _store_technique(self, cursor, obj, domain):
        """Store technique in database"""
        # Extract MITRE technique ID
        tech_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                break
        
        if not tech_id:
            return
        
        # Extract tactics
        tactic_ids = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic_ids.append(phase.get('phase_name', ''))
        
        cursor.execute('''
            INSERT OR REPLACE INTO techniques VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            tech_id,
            obj.get('name', ''),
            obj.get('description', ''),
            json.dumps(tactic_ids),
            json.dumps(obj.get('x_mitre_platforms', [])),
            json.dumps(obj.get('x_mitre_data_sources', [])),
            obj.get('x_mitre_detection', ''),
            json.dumps([]),  # mitigation_ids - populated later
            json.dumps(obj.get('x_mitre_permissions_required', [])),
            domain,
            obj.get('x_mitre_version', '1.0'),
            obj.get('created', ''),
            obj.get('modified', ''),
            obj.get('revoked', False),
            json.dumps(obj.get('external_references', []))
        ))
    
    def _store_tactic(self, cursor, obj, domain):
        """Store tactic in database"""
        tactic_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tactic_id = ref.get('external_id')
                break
        
        if not tactic_id:
            return
        
        cursor.execute('''
            INSERT OR REPLACE INTO tactics VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            tactic_id,
            obj.get('name', ''),
            obj.get('description', ''),
            obj.get('x_mitre_shortname', ''),
            domain,
            obj.get('created', ''),
            obj.get('modified', ''),
            json.dumps(obj.get('external_references', []))
        ))
    
    def _store_group(self, cursor, obj, domain):
        """Store threat group in database"""
        group_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                group_id = ref.get('external_id')
                break
        
        if not group_id:
            return
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_groups VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            group_id,
            obj.get('name', ''),
            obj.get('description', ''),
            json.dumps(obj.get('aliases', [])),
            json.dumps([]),  # techniques_used - populated later
            domain,
            obj.get('created', ''),
            obj.get('modified', ''),
            json.dumps(obj.get('external_references', []))
        ))
    
    def _store_software(self, cursor, obj, domain):
        """Store software/malware in database"""
        software_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                software_id = ref.get('external_id')
                break
        
        if not software_id:
            return
        
        cursor.execute('''
            INSERT OR REPLACE INTO software VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            software_id,
            obj.get('name', ''),
            obj.get('description', ''),
            obj.get('type', ''),
            json.dumps(obj.get('x_mitre_platforms', [])),
            json.dumps([]),  # techniques_used - populated later
            domain,
            obj.get('created', ''),
            obj.get('modified', ''),
            json.dumps(obj.get('external_references', []))
        ))
    
    def _store_mitigation(self, cursor, obj, domain):
        """Store mitigation in database"""
        mitigation_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitigation_id = ref.get('external_id')
                break
        
        if not mitigation_id:
            return
        
        cursor.execute('''
            INSERT OR REPLACE INTO mitigations VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            mitigation_id,
            obj.get('name', ''),
            obj.get('description', ''),
            json.dumps([]),  # techniques_mitigated - populated later
            domain,
            obj.get('created', ''),
            obj.get('modified', ''),
            json.dumps(obj.get('external_references', []))
        ))
    
    def sync_all_domains(self):
        """Download and process all MITRE domains"""
        print("🔄 Starting comprehensive MITRE sync...")
        
        # Setup database
        self.setup_database()
        
        # Process each domain
        success_count = 0
        for domain in ['enterprise', 'mobile', 'ics']:
            try:
                data = self.download_domain_data(domain)
                if data and self.process_and_store(domain, data):
                    success_count += 1
                else:
                    print(f"---- Failed to process {domain}")
            except Exception as e:
                print(f"---- Error with {domain}: {str(e)}")
        
        print(f"-- Sync complete: {success_count}/3 domains successful")
        return success_count > 0
    
    def get_stats(self):
        """Get database statistics"""
        if not os.path.exists(self.db_path):
            return {"status": "No database found"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {"status": "Ready", "domains": {}}
        
        for domain in ['enterprise', 'mobile', 'ics']:
            cursor.execute('SELECT COUNT(*) FROM techniques WHERE domain = ?', (domain,))
            techniques = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threat_groups WHERE domain = ?', (domain,))
            groups = cursor.fetchone()[0]
            
            cursor.execute('SELECT value FROM metadata WHERE key = ?', (f'{domain}_last_update',))
            last_update = cursor.fetchone()
            last_update = last_update[0] if last_update else "Never"
            
            stats["domains"][domain] = {
                "techniques": techniques,
                "groups": groups,
                "last_update": last_update
            }
        
        conn.close()
        return stats

def main():
    """Main sync function"""
    manager = RobustMITREManager()
    success = manager.sync_all_domains()
    
    if success:
        stats = manager.get_stats()
        print(f"\n📊 Final Stats: {stats}")
    else:
        print("-- Sync failed")

if __name__ == "__main__":
    main()
    

    
    



    







    

