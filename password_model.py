import numpy as np
import hashlib
import time
import re
import random
import string
import math

def password_to_features(password):
    """
    Extract features from password for model input.
    Based on the feature extraction in the notebook.
    """
    # Check if password is empty to avoid division by zero
    if len(password) == 0:
        return [0, 0, 0, 0, 0, 0]  # Return zeros for empty passwords
    
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

def calculate_crack_time(password):
    """
    Estimate time to crack a password based on its complexity.
    This is a simulation, not actual cracking.
    """
    features = password_to_features(password)
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
    # Adjust these values based on real-world hardware
    speeds = {
        'online': 10,          # Online service with throttling (10 guesses per second)
        'offline_slow': 1e6,   # Slow offline attack (1 million guesses per second)
        'offline_fast': 1e10,  # Fast offline attack (10 billion guesses per second)
        'quantum': 1e15        # Theoretical quantum computer (1 quadrillion guesses per second)
    }
    
    # Calculate times for different scenarios
    times = {}
    for scenario, speed in speeds.items():
        seconds = combinations / speed
        times[scenario] = seconds
    
    return times, entropy

def format_time(seconds):
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

def suggest_improved_password(password):
    """
    Generate suggestions for improving a password.
    """
    # List to store suggestions
    suggestions = []
    
    # Base on the original password but with enhancements
    suggestion1 = password
    
    # If password is too short, extend it
    if len(password) < 10:
        # Add random special chars and digits
        special_chars = "!@#$%^&*"
        digits = "0123456789"
        suggestion1 += random.choice(special_chars)
        suggestion1 += random.choice(digits)
        suggestion1 += random.choice(special_chars)
        
    # Ensure it has uppercase and lowercase
    if not any(c.isupper() for c in suggestion1):
        # Convert a random position to uppercase
        pos = random.randint(0, len(suggestion1) - 1)
        if suggestion1[pos].isalpha():
            suggestion1 = suggestion1[:pos] + suggestion1[pos].upper() + suggestion1[pos+1:]
        else:
            suggestion1 += random.choice(string.ascii_uppercase)
    
    if not any(c.islower() for c in suggestion1):
        # Convert a random position to lowercase or add a lowercase letter
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
            # Alternate case and add substitutions
            if char.islower():
                suggestion2 += char.upper()
            else:
                suggestion2 += char.lower()
        elif char.isdigit():
            # Replace some digits with similar-looking special chars
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

def analyze_password(password):
    """
    Analyze a password and return comprehensive results.
    """
    # Get features
    features = password_to_features(password)
    
    # Calculate crack time
    crack_times, entropy = calculate_crack_time(password)
    
    # Determine strength level based on features and time to crack
    length_ok = features[0] >= 10
    has_digits = features[1] > 0
    has_upper = features[2] > 0
    has_lower = features[3] > 0
    has_special = features[4] > 0
    
    # Count criteria met
    criteria_met = sum([length_ok, has_digits, has_upper, has_lower, has_special])
    
    # Determine strength level
    if criteria_met <= 1:
        strength = 'very-weak'
        strength_label = 'Very Weak'
    elif criteria_met == 2:
        strength = 'weak'
        strength_label = 'Weak'
    elif criteria_met == 3:
        strength = 'medium'
        strength_label = 'Medium'
    elif criteria_met == 4:
        strength = 'strong'
        strength_label = 'Strong'
    else:
        strength = 'very-strong'
        strength_label = 'Very Strong'
    
    # Generate feedback based on strength
    if strength == 'very-weak':
        feedback = 'This password is extremely vulnerable to attacks.'
    elif strength == 'weak':
        feedback = 'This password could be easily cracked.'
    elif strength == 'medium':
        feedback = 'This password provides moderate security but could be improved.'
    elif strength == 'strong':
        feedback = 'This password is strong, but one more criterion would make it very strong.'
    else:
        feedback = 'Excellent! This password meets all security criteria.'
    
    # Add time to crack information
    offline_time = format_time(crack_times['offline_fast'])
    feedback += f" It would take approximately {offline_time} to crack with a high-end computer."
    
    # Generate improvement suggestions
    suggestions = []
    if not length_ok:
        suggestions.append('Increase length to at least 10 characters.')
    if not has_upper:
        suggestions.append('Add at least one uppercase letter (A-Z).')
    if not has_lower:
        suggestions.append('Add at least one lowercase letter (a-z).')
    if not has_digits:
        suggestions.append('Add at least one number (0-9).')
    if not has_special:
        suggestions.append('Add at least one special character (e.g., !@#$%^&*).')
    
    # Generate improved password suggestions
    improved_passwords = suggest_improved_password(password)
    
    # Return comprehensive analysis
    return {
        'strength_class': strength,
        'strength_label': strength_label,
        'feedback': feedback,
        'suggestions': suggestions,
        'entropy': entropy,
        'crack_times': {
            'online': format_time(crack_times['online']),
            'offline_slow': format_time(crack_times['offline_slow']),
            'offline_fast': format_time(crack_times['offline_fast']),
            'quantum': format_time(crack_times['quantum'])
        },
        'improved_passwords': improved_passwords
    } 