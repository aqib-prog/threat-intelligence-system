import requests
import json
from datetime import datetime


class MITREAPITester:
    def __init__(self):
        # Static endpoints (GitHub)
        self.static_urls = {
            'enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
            'mobile': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
            'ics': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json'
        }

        # TAXII endpoints
        self.taxii_base = 'https://attack-taxii.mitre.org'
        self.taxii_discovery = f'{self.taxii_base}/taxii2/'
        self.taxii_collections = f'{self.taxii_base}/api/v21/collections/'

    def test_static_apis(self):
        """Test all static GitHub APIs"""
        results = {}

        for domain, url in self.static_urls.items():
            try:
                print(f"Testing {domain} API...")
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    object_count = len(data.get('objects', []))
                    
                    results[domain] = {
                        'status': 'SUCCESS',
                        'url': url,
                        'objects': object_count,
                        'size_mb': len(response.content) / 1024 / 1024
                    }
                    print(f" {domain}: {object_count} objects ({results[domain]['size_mb']:.1f}MB)")
                else:
                    results[domain] = {'status': 'FAILED', 'error': f'HTTP {response.status_code}'}
            except Exception as e:
                results[domain] = {'status': 'ERROR', 'error': str(e)}
                print(f" {domain}: {str(e)}")
        
        return results
    
    
    def test_taxii_api(self):
        """Test TAXII live API and get current collection IDs"""
        headers = {'Accept': 'application/taxii+json;version=2.1'}

        try:
            # Test discovery
            print("Testing TAXII discovery...")
            discovery = requests.get(self.taxii_discovery, headers=headers, timeout=10)
            
            if discovery.status_code != 200:
                return {'status': 'FAILED', 'error': f'Discovery failed: {discovery.status_code}'}
            
            # Get collections
            print("Getting TAXII collections...")
            collections = requests.get(self.taxii_collections, headers=headers, timeout=10)
            
            if collections.status_code != 200:
                return {'status': 'FAILED', 'error': f'Collections failed: {collections.status_code}'}
            
            collections_data = collections.json()
            
        # Extract current collection IDs
            current_collections = {}
            for collection in collections_data.get('collections', []):
                domain = collection['title'].lower().replace(' att&ck', '').replace('att&ck for ', '')
                current_collections[domain] = {
                    'id': collection['id'],
                    'title': collection['title'],
                    'can_read': collection['can_read']
                }
            
            # Test one collection for data
            if current_collections:
                test_collection = list(current_collections.values())[0]
                test_url = f"{self.taxii_collections}{test_collection['id']}/objects?limit=5"
                
                test_response = requests.get(test_url, headers=headers, timeout=10)
                object_count = len(test_response.json().get('objects', [])) if test_response.status_code == 200 else 0
                
                return {
                    'status': 'SUCCESS',
                    'collections': current_collections,
                    'test_objects': object_count
                }
            
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def run_full_test(self):
        """Run complete API test suite"""
        print("🔍 Testing MITRE ATT&CK APIs...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'static_apis': self.test_static_apis(),
            'taxii_api': self.test_taxii_api()
        }
        
        # Save results
        with open('src/data/api_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        print("\n📊 API Test Summary:")
        for domain, result in results['static_apis'].items():
            status = "PASSED" if result['status'] == 'SUCCESS' else "FAILED"
            print(f"{status} Static {domain}: {result['status']}")
        
        taxii_status = "PASSED" if results['taxii_api']['status'] == 'SUCCESS' else "❌"
        print(f"{taxii_status} TAXII Live API: {results['taxii_api']['status']}")
        
        return results
    
if __name__ == "__main__":
    tester = MITREAPITester()
    results = tester.run_full_test()


        
    
    
     
