import requests
import json
from urllib.parse import urljoin
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        logger.info("Testing for SQL injection vulnerabilities...")
        
        test_cases = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --",
            "admin' --",
            "1' OR '1' = '1"
        ]
        
        endpoints = ['/login', '/register']
        
        for endpoint in endpoints:
            for payload in test_cases:
                try:
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        data={'username': payload, 'password': 'test123'}
                    )
                    
                    if 'error' in response.text.lower() or 'sql' in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'endpoint': endpoint,
                            'payload': payload,
                            'response': response.text[:200]
                        })
                except Exception as e:
                    logger.error(f"Error testing SQL injection: {str(e)}")
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities...")
        
        test_cases = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>"
        ]
        
        endpoints = ['/profile']
        
        for endpoint in endpoints:
            for payload in test_cases:
                try:
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        data={
                            'full_name': payload,
                            'bio': payload,
                            'location': payload,
                            'interests': payload
                        }
                    )
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'endpoint': endpoint,
                            'payload': payload,
                            'response': response.text[:200]
                        })
                except Exception as e:
                    logger.error(f"Error testing XSS: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting implementation"""
        logger.info("Testing rate limiting...")
        
        endpoint = '/login'
        requests_count = 25  # Should be more than the rate limit
        
        start_time = time.time()
        responses = []
        
        for _ in range(requests_count):
            try:
                response = self.session.post(
                    urljoin(self.base_url, endpoint),
                    data={'username': 'test', 'password': 'test123'}
                )
                responses.append(response.status_code)
            except Exception as e:
                logger.error(f"Error testing rate limiting: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        if len([r for r in responses if r == 429]) > 0:
            logger.info("Rate limiting is working")
        else:
            self.vulnerabilities.append({
                'type': 'Rate Limiting',
                'endpoint': endpoint,
                'requests': requests_count,
                'duration': duration,
                'status_codes': responses
            })
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        logger.info("Testing for CSRF vulnerabilities...")
        
        endpoints = ['/profile']
        
        for endpoint in endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                
                if 'csrf_token' not in response.text:
                    self.vulnerabilities.append({
                        'type': 'CSRF',
                        'endpoint': endpoint,
                        'response': response.text[:200]
                    })
            except Exception as e:
                logger.error(f"Error testing CSRF: {str(e)}")
    
    def test_encryption(self):
        """Test if sensitive data is properly encrypted"""
        logger.info("Testing data encryption...")
        
        test_data = {
            'bio': 'Test bio',
            'location': 'Test location',
            'interests': 'Test interests'
        }
        
        try:
            # First, create a test profile
            response = self.session.post(
                urljoin(self.base_url, '/profile'),
                data=test_data
            )
            
            # Then try to access the data directly from the database
            # This is a simplified test - in reality, you'd need to check the database directly
            if any(value in response.text for value in test_data.values()):
                self.vulnerabilities.append({
                    'type': 'Encryption',
                    'data': test_data,
                    'response': response.text[:200]
                })
        except Exception as e:
            logger.error(f"Error testing encryption: {str(e)}")
    
    def run_all_tests(self):
        """Run all security tests"""
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_rate_limiting,
            self.test_csrf,
            self.test_encryption
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            executor.map(lambda test: test(), tests)
        
        return self.vulnerabilities

def main():
    tester = SecurityTester()
    vulnerabilities = tester.run_all_tests()
    
    print("\nSecurity Test Results:")
    print("=====================")
    
    if vulnerabilities:
        print(f"\nFound {len(vulnerabilities)} potential vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"\nType: {vuln['type']}")
            print(f"Endpoint: {vuln.get('endpoint', 'N/A')}")
            print(f"Details: {json.dumps(vuln, indent=2)}")
    else:
        print("\nNo vulnerabilities found in the basic tests.")
    
if __name__ == "__main__":
    main() 