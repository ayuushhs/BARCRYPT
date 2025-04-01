import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import re
from datetime import datetime
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import requests
import json
from typing import List, Dict, Tuple, Optional
import logging

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

class PasswordDataset(Dataset):
    def __init__(self, passwords: List[str], labels: List[int], vectorizer: TfidfVectorizer):
        self.features = vectorizer.transform(passwords).toarray()
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return torch.FloatTensor(self.features[idx]), torch.LongTensor([self.labels[idx]])[0]

class PasswordStrengthModel(nn.Module):
    def __init__(self, input_size: int, hidden_size: int = 256):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size // 2, hidden_size // 4),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size // 4, 4)  # 4 strength levels
        )

    def forward(self, x):
        return self.layers(x)

class PasswordStrengthAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model_path = 'models/password_strength_model.pth'
        self.vectorizer_path = 'models/tfidf_vectorizer.pkl'
        self.gpt2_model = None
        self.gpt2_tokenizer = None
        self.setup_logging()

    def setup_logging(self):
        """Set up logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('password_analyzer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of the password"""
        if not password:
            return 0.0
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        length = len(password)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        return entropy

    def estimate_crack_time(self, password: str) -> str:
        """Estimate time to crack the password"""
        entropy = self.calculate_entropy(password)
        # Assuming 1000 attempts per second
        attempts = 2 ** entropy
        seconds = attempts / 1000
        
    if seconds < 60:
            return f"{int(seconds)} seconds"
    elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
            return f"{int(seconds/86400)} days"
        else:
            return f"{int(seconds/31536000)} years"

    def check_common_patterns(self, password: str) -> List[str]:
        """Check for common password patterns"""
        patterns = []
        
        # Check for sequential numbers
        if re.search(r'123|234|345|456|567|678|789', password):
            patterns.append("Contains sequential numbers")
            
        # Check for keyboard patterns
        if re.search(r'qwerty|asdfgh|zxcvbn', password.lower()):
            patterns.append("Contains keyboard pattern")
            
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Contains repeated characters")
            
        # Check for common substitutions
        if re.search(r'[p@ssw0rd]', password.lower()):
            patterns.append("Contains common character substitutions")
            
        return patterns

    def analyze_password_strength(self, password: str) -> Dict:
        """Analyze password strength and provide detailed feedback"""
        try:
            # Basic checks
            length = len(password)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            # Calculate metrics
            entropy = self.calculate_entropy(password)
            crack_time = self.estimate_crack_time(password)
            patterns = self.check_common_patterns(password)
            
            # Calculate strength score (0-100)
            strength_score = 0
            strength_score += min(length * 4, 40)  # Length contribution
            strength_score += 10 if has_upper else 0
            strength_score += 10 if has_lower else 0
            strength_score += 10 if has_digit else 0
            strength_score += 10 if has_special else 0
            strength_score += min(entropy * 2, 20)  # Entropy contribution
    
    # Determine strength level
            if strength_score >= 80:
                strength_level = "Very Strong"
            elif strength_score >= 60:
                strength_level = "Strong"
            elif strength_score >= 40:
                strength_level = "Medium"
    else:
                strength_level = "Weak"
    
    # Generate improvement suggestions
    suggestions = []
            if length < 12:
                suggestions.append("Make password longer (at least 12 characters)")
    if not has_upper:
                suggestions.append("Add uppercase letters")
    if not has_lower:
                suggestions.append("Add lowercase letters")
            if not has_digit:
                suggestions.append("Add numbers")
    if not has_special:
                suggestions.append("Add special characters")
            if patterns:
                suggestions.append("Avoid common patterns")
            
            return {
                "strength_score": strength_score,
                "strength_level": strength_level,
                "length": length,
                "has_upper": has_upper,
                "has_lower": has_lower,
                "has_digit": has_digit,
                "has_special": has_special,
                "entropy": entropy,
                "crack_time": crack_time,
                "patterns": patterns,
                "suggestions": suggestions
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing password: {str(e)}")
            return {
                "error": "Failed to analyze password",
                "details": str(e)
            }

    def generate_suggestions(self, password: str) -> List[str]:
        """Generate password improvement suggestions using GPT-2"""
        try:
            if not self.gpt2_model or not self.gpt2_tokenizer:
                self.gpt2_model = GPT2LMHeadModel.from_pretrained('gpt2')
                self.gpt2_tokenizer = GPT2Tokenizer.from_pretrained('gpt2')
            
            prompt = f"Suggest improvements for password: {password}\n"
            inputs = self.gpt2_tokenizer.encode(prompt, return_tensors='pt')
            
            outputs = self.gpt2_model.generate(
                inputs,
                max_length=100,
                num_return_sequences=1,
                temperature=0.7,
                top_p=0.9,
                do_sample=True
            )
            
            suggestions = self.gpt2_tokenizer.decode(outputs[0], skip_special_tokens=True)
            return suggestions.split('\n')[1:]  # Skip the prompt line
            
        except Exception as e:
            self.logger.error(f"Error generating suggestions: {str(e)}")
            return ["Failed to generate AI suggestions"]

    def check_breach_status(self, password: str) -> Dict:
        """Check if password has been exposed in data breaches"""
        try:
            # Hash the password (first 5 characters of SHA-1)
            import hashlib
            password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            
            # Check HIBP API
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return {
                            "breached": True,
                            "breach_count": int(count),
                            "last_checked": datetime.now().isoformat()
                        }
            
            return {
                "breached": False,
                "breach_count": 0,
                "last_checked": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error checking breach status: {str(e)}")
    return {
                "error": "Failed to check breach status",
                "details": str(e)
            }

    def train_model(self, passwords: List[str], labels: List[int]):
        """Train the password strength model"""
        try:
            # Create and fit TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 4),
                max_features=1000
            )
            X = self.vectorizer.fit_transform(passwords)
            
            # Create dataset and dataloader
            dataset = PasswordDataset(passwords, labels, self.vectorizer)
            dataloader = DataLoader(dataset, batch_size=128, shuffle=True)
            
            # Initialize model
            input_size = X.shape[1]
            self.model = PasswordStrengthModel(input_size).to(self.device)
            
            # Training setup
            criterion = nn.CrossEntropyLoss()
            optimizer = optim.Adam(self.model.parameters(), lr=0.001)
            
            # Training loop
            num_epochs = 10
            for epoch in range(num_epochs):
                self.model.train()
                total_loss = 0
                for batch_features, batch_labels in dataloader:
                    batch_features = batch_features.to(self.device)
                    batch_labels = batch_labels.to(self.device)
                    
                    optimizer.zero_grad()
                    outputs = self.model(batch_features)
                    loss = criterion(outputs, batch_labels)
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(dataloader)
                self.logger.info(f"Epoch {epoch+1}/{num_epochs}, Loss: {avg_loss:.4f}")
            
            # Save model and vectorizer
            os.makedirs('models', exist_ok=True)
            torch.save(self.model.state_dict(), self.model_path)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            
            self.logger.info("Model training completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            raise

    def load_model(self):
        """Load the trained model and vectorizer"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.vectorizer = joblib.load(self.vectorizer_path)
                input_size = len(self.vectorizer.get_feature_names_out())
                self.model = PasswordStrengthModel(input_size)
                self.model.load_state_dict(torch.load(self.model_path))
                self.model.to(self.device)
                self.model.eval()
                self.logger.info("Model loaded successfully")
            else:
                self.logger.warning("Model files not found")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            raise

    def predict_strength(self, password: str) -> int:
        """Predict password strength using the trained model"""
        try:
            if not self.model or not self.vectorizer:
                self.load_model()
            
            if not self.model or not self.vectorizer:
                raise ValueError("Model not loaded")
            
            # Transform password
            features = self.vectorizer.transform([password]).toarray()
            features_tensor = torch.FloatTensor(features).to(self.device)
            
            # Make prediction
            with torch.no_grad():
                outputs = self.model(features_tensor)
                _, predicted = torch.max(outputs, 1)
                return predicted.item()
            
        except Exception as e:
            self.logger.error(f"Error predicting strength: {str(e)}")
            return -1 