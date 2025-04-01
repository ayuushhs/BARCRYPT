import re
import hashlib
import requests
from typing import Dict, List, Any
import time

class PasswordStrengthAnalyzer:
    def __init__(self):
        self.common_passwords = set()
        self.load_common_passwords()

    def load_common_passwords(self):
        """Load a list of common passwords from a file or API"""
        try:
            # You can load from a file or API here
            # For now, we'll use a small set of common passwords
            self.common_passwords = {
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'monkey', 'letmein', 'dragon', '111111', 'baseball',
                'iloveyou', 'trustno1', 'sunshine', 'master', 'welcome',
                'shadow', 'ashley', 'football', 'jesus', 'michael',
                'ninja', 'mustang', 'password1'
            }
        except Exception as e:
            print(f"Error loading common passwords: {e}")
            self.common_passwords = set()

    def analyze_password_strength(self, password: str) -> Dict[str, Any]:
        """Analyze the strength of a password and return detailed metrics"""
        if not password:
            return {
                'strength': 0,
                'score': 0,
                'feedback': ['Password cannot be empty'],
                'crack_times': {
                    'offline_fast': 0,
                    'offline_slow': 0,
                    'online_no_throttling': 0,
                    'online_throttling': 0
                }
            }

        # Initialize metrics
        metrics = {
            'length': len(password),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_numbers': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^A-Za-z0-9]', password)),
            'is_common': password.lower() in self.common_passwords,
            'has_repeated_chars': bool(re.search(r'(.)\1{2,}', password)),
            'has_sequences': bool(re.search(r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()))
        }

        # Calculate strength score (0-100)
        score = 0
        feedback = []

        # Length contribution (up to 25 points)
        if metrics['length'] >= 12:
            score += 25
        elif metrics['length'] >= 8:
            score += 15
        elif metrics['length'] >= 6:
            score += 5
        else:
            feedback.append('Password is too short')

        # Character type contributions (up to 25 points each)
        if metrics['has_uppercase']:
            score += 25
        else:
            feedback.append('Add uppercase letters')

        if metrics['has_lowercase']:
            score += 25
        else:
            feedback.append('Add lowercase letters')

        if metrics['has_numbers']:
            score += 25
        else:
            feedback.append('Add numbers')

        if metrics['has_special']:
            score += 25
        else:
            feedback.append('Add special characters')

        # Penalties
        if metrics['is_common']:
            score = max(0, score - 50)
            feedback.append('This is a common password')

        if metrics['has_repeated_chars']:
            score = max(0, score - 20)
            feedback.append('Avoid repeated characters')

        if metrics['has_sequences']:
            score = max(0, score - 20)
            feedback.append('Avoid common sequences')

        # Calculate crack times
        crack_times = self.estimate_crack_times(password, metrics)

        return {
            'strength': score,
            'score': score,
            'feedback': feedback if feedback else ['Password is strong'],
            'crack_times': crack_times,
            'metrics': metrics
        }

    def estimate_crack_times(self, password: str, metrics: Dict[str, Any]) -> Dict[str, float]:
        """Estimate password crack times based on various attack scenarios"""
        # Calculate entropy (simplified)
        char_set_size = 0
        if metrics['has_uppercase']:
            char_set_size += 26
        if metrics['has_lowercase']:
            char_set_size += 26
        if metrics['has_numbers']:
            char_set_size += 10
        if metrics['has_special']:
            char_set_size += 32

        if char_set_size == 0:
            char_set_size = 1  # Prevent division by zero

        # Calculate base entropy
        entropy = metrics['length'] * (char_set_size ** 0.5)

        # Calculate crack times (simplified)
        base_time = 2 ** (entropy / 2)  # Base time in seconds

        return {
            'offline_fast': base_time / 1000000,  # Assuming 1M attempts per second
            'offline_slow': base_time / 1000,     # Assuming 1K attempts per second
            'online_no_throttling': base_time / 10,  # Assuming 10 attempts per second
            'online_throttling': base_time / 2      # Assuming 2 attempts per second
        }

    def check_breach_status(self, password: str) -> Dict[str, Any]:
        """Check if a password has been exposed in data breaches"""
        try:
            # Hash the password using SHA-1 (required by HIBP API)
            sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]

            # Check against HIBP API
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return {
                            'breached': True,
                            'breach_count': int(count),
                            'message': f'Password found in {count} data breaches'
                        }
                
                return {
                    'breached': False,
                    'breach_count': 0,
                    'message': 'Password not found in any known data breaches'
                }
            else:
                return {
                    'breached': None,
                    'breach_count': 0,
                    'message': 'Unable to check breach status'
                }

        except Exception as e:
            return {
                'breached': None,
                'breach_count': 0,
                'message': f'Error checking breach status: {str(e)}'
            }

    def generate_suggestions(self, password: str) -> List[str]:
        """Generate password improvement suggestions"""
        analysis = self.analyze_password_strength(password)
        suggestions = []

        if analysis['strength'] < 80:
            if not analysis['metrics']['has_uppercase']:
                suggestions.append('Add uppercase letters to increase complexity')
            if not analysis['metrics']['has_lowercase']:
                suggestions.append('Add lowercase letters to increase complexity')
            if not analysis['metrics']['has_numbers']:
                suggestions.append('Include numbers to increase complexity')
            if not analysis['metrics']['has_special']:
                suggestions.append('Add special characters to increase complexity')
            if analysis['metrics']['length'] < 12:
                suggestions.append('Make the password longer (at least 12 characters)')
            if analysis['metrics']['has_repeated_chars']:
                suggestions.append('Avoid repeated characters')
            if analysis['metrics']['has_sequences']:
                suggestions.append('Avoid common sequences')
            if analysis['metrics']['is_common']:
                suggestions.append('Choose a less common password')

        return suggestions 