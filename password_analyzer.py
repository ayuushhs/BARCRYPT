import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import hashlib
import re
import math
import time
import requests
import json
from transformers import pipeline
import random
import string

class PasswordAnalyzer:
    def __init__(self):
        # Load the pre-trained model for password strength prediction
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
        self.classifier = RandomForestClassifier()
        self.nlp_generator = pipeline('text-generation', model='gpt2')
        
        # Load common password patterns from RockYou dataset
        self.common_patterns = self._load_common_patterns()
        
    def _load_common_patterns(self):
        # TODO: Load and process RockYou dataset
        # For now, using a small sample of common patterns
        return [
            r'\d{4}$',  # Year at the end
            r'^[A-Z][a-z]+\d+$',  # Capitalized word followed by numbers
            r'password\d*',  # Variations of 'password'
            r'qwerty',  # Keyboard patterns
            r'abc123',  # Simple alphanumeric patterns
        ]
    
    def password_to_features(self, password):
        """Extract features from password for model input."""
        if len(password) == 0:
            return [0, 0, 0, 0, 0, 0]
        
        # Calculate entropy
        char_frequencies = {}
        for char in password:
            if char in char_frequencies:
                char_frequencies[char] += 1
            else:
                char_frequencies[char] = 1
        
        entropy = 0
        for char, freq in char_frequencies.items():
            p = freq / len(password)
            entropy -= p * math.log2(p)
        
        return [
            len(password),  # Password Length
            sum(char.isdigit() for char in password),  # Number of Digits
            sum(char.isupper() for char in password),  # Number of Uppercase Letters
            sum(char.islower() for char in password),  # Number of Lowercase Letters
            sum(char in "!@#$%^&*()-_+=<>?/|\\~`" for char in password),  # Special Characters
            entropy  # Entropy Metric
        ]
    
    def calculate_entropy(self, password):
        """Calculate password entropy based on character set and length."""
        features = self.password_to_features(password)
        return features[5]  # Return the entropy value
    
    def estimate_crack_time(self, password):
        """Estimate time to crack the password using different methods."""
        features = self.password_to_features(password)
        length = features[0]
        has_digits = features[1] > 0
        has_upper = features[2] > 0
        has_lower = features[3] > 0
        has_special = features[4] > 0
        entropy = features[5]
        
        # Calculate character set size
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digits:
            charset_size += 10
        if has_special:
            charset_size += 30
        
        if charset_size == 0:  # Edge case
            charset_size = 26
        
        # Estimate combinations
        combinations = charset_size ** length
        
        # Average cracking speed (guesses per second)
        speeds = {
            'online': 10,          # Online service with throttling
            'offline_slow': 1e6,   # Slow offline attack
            'offline_fast': 1e10,  # Fast offline attack
            'quantum': 1e15        # Theoretical quantum computer
        }
        
        # Calculate times for different scenarios
        times = {}
        for scenario, speed in speeds.items():
            seconds = combinations / speed
            times[scenario] = self.format_time(seconds)
        
        return times
    
    def format_time(self, seconds):
        """Convert seconds to a human-readable time format."""
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.2f} years"
        else:
            return "centuries"
    
    def check_common_patterns(self, password):
        """Check if password matches common patterns."""
        matches = []
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                matches.append(pattern)
        return matches
    
    def suggest_improved_password(self, password):
        """Generate suggestions for improving a password."""
        suggestions = []
        
        # Base on the original password but with enhancements
        suggestion1 = password
        
        # If password is too short, extend it
        if len(password) < 10:
            special_chars = "!@#$%^&*"
            digits = "0123456789"
            suggestion1 += random.choice(special_chars)
            suggestion1 += random.choice(digits)
            suggestion1 += random.choice(special_chars)
        
        # Ensure it has uppercase and lowercase
        if not any(c.isupper() for c in suggestion1):
            pos = random.randint(0, len(suggestion1) - 1)
            if suggestion1[pos].isalpha():
                suggestion1 = suggestion1[:pos] + suggestion1[pos].upper() + suggestion1[pos+1:]
            else:
                suggestion1 += random.choice(string.ascii_uppercase)
        
        if not any(c.islower() for c in suggestion1):
            pos = random.randint(0, len(suggestion1) - 1)
            if suggestion1[pos].isalpha():
                suggestion1 = suggestion1[:pos] + suggestion1[pos].lower() + suggestion1[pos+1:]
            else:
                suggestion1 += random.choice(string.ascii_lowercase)
        
        # Ensure it has a special character
        if not any(c in "!@#$%^&*()-_+=<>?/|\\~`" for c in suggestion1):
            suggestion1 += random.choice("!@#$%^&*")
        
        suggestions.append(suggestion1)
        
        # Create a second suggestion with character transformations
        suggestion2 = ""
        for char in password:
            if char.isalpha():
                if char.islower():
                    suggestion2 += char.upper()
                else:
                    suggestion2 += char.lower()
            elif char.isdigit():
                if char == '0':
                    suggestion2 += '@'
                elif char == '1':
                    suggestion2 += '!'
                elif char == '3':
                    suggestion2 += '#'
                elif char == '4':
                    suggestion2 += '$'
                elif char == '5':
                    suggestion2 += '%'
                elif char == '8':
                    suggestion2 += '*'
                else:
                    suggestion2 += char
            else:
                suggestion2 += char
        
        # Ensure suggestion2 is different from the original and has sufficient length
        if suggestion2 == password or len(suggestion2) < 10:
            suggestion2 += ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=3))
        
        suggestions.append(suggestion2)
        
        # Create a completely random strong password as third suggestion
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        suggestion3 = ''.join(random.choices(chars, k=12))
        suggestions.append(suggestion3)
        
        return suggestions
    
    def generate_improvement_suggestions(self, password):
        """Generate AI-powered suggestions to improve the password."""
        weaknesses = []
        suggestions = []
        
        # Check length
        if len(password) < 12:
            weaknesses.append("Password is too short")
            suggestions.append("Increase length to at least 12 characters")
        
        # Check character variety
        if not re.search(r'[A-Z]', password):
            weaknesses.append("Missing uppercase letters")
        if not re.search(r'[a-z]', password):
            weaknesses.append("Missing lowercase letters")
        if not re.search(r'\d', password):
            weaknesses.append("Missing numbers")
        if not re.search(r'[^a-zA-Z0-9]', password):
            weaknesses.append("Missing special characters")
        
        # Check common patterns
        pattern_matches = self.check_common_patterns(password)
        if pattern_matches:
            weaknesses.append("Contains common patterns")
            
        # Generate AI-powered suggestion
        if weaknesses:
            base = re.sub(r'\d', '9', password)  # Replace numbers with 9
            base = re.sub(r'[a-zA-Z]', 'x', base)  # Replace letters with x
            
            # Use GPT-2 to generate a pattern-based suggestion
            prompt = f"Generate a strong password based on the pattern: {base}"
            suggestion = self.nlp_generator(prompt, max_length=20, num_return_sequences=1)[0]['generated_text']
            suggestions.append(f"Consider using: {suggestion}")
        
        return {
            'weaknesses': weaknesses,
            'suggestions': suggestions,
            'crack_times': self.estimate_crack_time(password),
            'entropy': self.calculate_entropy(password)
        }
    
    def analyze_password(self, password):
        """Complete password analysis."""
        analysis = self.generate_improvement_suggestions(password)
        
        # Add attack vector analysis
        if analysis['entropy'] < 50:
            analysis['attack_vectors'] = ["Dictionary attack", "Brute force"]
        elif analysis['entropy'] < 80:
            analysis['attack_vectors'] = ["Advanced dictionary attack with rules"]
        else:
            analysis['attack_vectors'] = ["Resistant to most common attacks"]
            
        return analysis 