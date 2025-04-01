import requests
import hashlib
import time
from datetime import datetime
import json
import os
from typing import Dict, Any, Optional

class BreachChecker:
    def __init__(self):
        self.api_key = os.getenv('HIBP_API_KEY', '')  # Get API key from environment variable
        self.base_url = 'https://haveibeenpwned.com/api/v3'
        self.headers = {
            'hibp-api-key': self.api_key,
            'user-agent': 'BarcCrypt-Password-Manager'
        }
        self.rate_limit_delay = 1.5  # Delay between requests to respect rate limits

    def _sha1_hash(self, password: str) -> str:
        """Generate SHA-1 hash of the password."""
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    def _k_anon_hash(self, password: str) -> tuple[str, str]:
        """Generate k-anonymity hash of the password."""
        sha1_hash = self._sha1_hash(password)
        return sha1_hash[:5], sha1_hash[5:]

    def check_password_leaked(self, password: str) -> Dict[str, Any]:
        """
        Check if a password has been exposed in data breaches using k-anonymity.
        """
        try:
            prefix, suffix = self._k_anon_hash(password)
            
            # Check if we have cached results
            cache_key = f"pwd_{prefix}_{suffix}"
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                return cached_result

            # Make API request
            response = requests.get(
                f'{self.base_url}/range/{prefix}',
                headers=self.headers
            )

            if response.status_code == 200:
                # Check if the suffix appears in the response
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return {
                            'leaked': True,
                            'count': int(count),
                            'message': f'This password has been found {count} times in data breaches'
                        }
                
                return {
                    'leaked': False,
                    'count': 0,
                    'message': 'This password has not been found in any known data breaches'
                }
            elif response.status_code == 429:
                return {
                    'leaked': None,
                    'message': 'Rate limit exceeded. Please try again later.'
                }
            else:
                return {
                    'leaked': None,
                    'message': f'Error checking password: {response.status_code}'
                }

        except Exception as e:
            return {
                'leaked': None,
                'message': f'Error checking password: {str(e)}'
            }

    def check_website_breaches(self, domain: str) -> Dict[str, Any]:
        """
        Check if a website has been involved in data breaches.
        """
        try:
            # Check cache first
            cache_key = f"site_{domain}"
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                return cached_result

            # Make API request
            response = requests.get(
                f'{self.base_url}/breaches?domain={domain}',
                headers=self.headers
            )

            if response.status_code == 200:
                breaches = response.json()
                if breaches:
                    # Get the most recent breach
                    latest_breach = max(breaches, key=lambda x: x.get('BreachDate', ''))
                    return {
                        'breached': True,
                        'breach_date': latest_breach.get('BreachDate'),
                        'pwn_count': latest_breach.get('PwnCount', 0),
                        'description': latest_breach.get('Description', ''),
                        'breach_name': latest_breach.get('Name', '')
                    }
                else:
                    return {
                        'breached': False,
                        'message': 'No known data breaches found for this website'
                    }
            elif response.status_code == 429:
                return {
                    'breached': None,
                    'message': 'Rate limit exceeded. Please try again later.'
                }
            else:
                return {
                    'breached': None,
                    'message': f'Error checking website: {response.status_code}'
                }

        except Exception as e:
            return {
                'breached': None,
                'message': f'Error checking website: {str(e)}'
            }

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired."""
        try:
            cache_file = 'breach_cache.json'
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cache = json.load(f)
                    if cache_key in cache:
                        result = cache[cache_key]
                        # Check if cache is not expired (24 hours)
                        if (datetime.now() - datetime.fromisoformat(result['timestamp'])).total_seconds() < 86400:
                            return result['data']
        except Exception:
            pass
        return None

    def _cache_result(self, cache_key: str, data: Dict[str, Any]):
        """Cache the result with timestamp."""
        try:
            cache_file = 'breach_cache.json'
            cache = {}
            
            # Load existing cache
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cache = json.load(f)
            
            # Update cache
            cache[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'data': data
            }
            
            # Save cache
            with open(cache_file, 'w') as f:
                json.dump(cache, f)
        except Exception:
            pass 