import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import joblib
import re
import requests
import gzip
import os
from tqdm import tqdm

class PasswordDataset(Dataset):
    def __init__(self, passwords, labels):
        self.passwords = passwords
        self.labels = labels
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=1000)
        self.features = self.vectorizer.fit_transform(passwords).toarray()
        
    def __len__(self):
        return len(self.passwords)
    
    def __getitem__(self, idx):
        return torch.FloatTensor(self.features[idx]), torch.FloatTensor([self.labels[idx]])

class PasswordStrengthModel(nn.Module):
    def __init__(self, input_size):
        super(PasswordStrengthModel, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(input_size, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.model(x)

def download_rockyou():
    """Download and extract the RockYou dataset."""
    if not os.path.exists('data'):
        os.makedirs('data')
    
    # Download the dataset
    if not os.path.exists('data/rockyou.txt'):
        print("Downloading RockYou dataset...")
        url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        
        with open('data/rockyou.txt', 'wb') as f, tqdm(
            desc="Downloading",
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
        ) as pbar:
            for data in response.iter_content(chunk_size=1024):
                size = f.write(data)
                pbar.update(size)
        print("Download complete!")

def load_data(max_samples=1000000):  # Limit to 1 million samples for faster training
    """Load and preprocess the RockYou dataset."""
    passwords = []
    labels = []
    
    print("Loading and preprocessing data...")
    with open('data/rockyou.txt', 'r', encoding='latin-1', errors='ignore') as f:
        for i, line in enumerate(tqdm(f)):
            if i >= max_samples:
                break
            password = line.strip()
            if password:
                # Calculate password strength based on multiple criteria
                strength = calculate_password_strength(password)
                passwords.append(password)
                labels.append(strength)
    
    return passwords, labels

def calculate_password_strength(password):
    """Calculate password strength score between 0 and 1."""
    score = 0
    
    # Length score (up to 0.3)
    length_score = min(len(password) / 20, 1) * 0.3
    
    # Character variety score (up to 0.3)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    variety_score = sum([has_lower, has_upper, has_digit, has_special]) * 0.075
    
    # Entropy score (up to 0.4)
    char_set_size = sum([
        bool(re.search(r'[a-z]', password)) * 26,
        bool(re.search(r'[A-Z]', password)) * 26,
        bool(re.search(r'\d', password)) * 10,
        bool(re.search(r'[^a-zA-Z0-9]', password)) * 32
    ])
    entropy = len(password) * np.log2(char_set_size) if char_set_size > 0 else 0
    entropy_score = min(entropy / 100, 1) * 0.4
    
    score = length_score + variety_score + entropy_score
    return min(score, 1)  # Ensure score is between 0 and 1

def train_model():
    """Train the password strength model using GPU acceleration."""
    print("Checking GPU availability...")
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load and prepare data
    passwords, labels = load_data()
    dataset = PasswordDataset(passwords, labels)
    
    # Split dataset
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_dataset, test_dataset = torch.utils.data.random_split(dataset, [train_size, test_size])
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=128)
    
    # Initialize model
    model = PasswordStrengthModel(dataset.features.shape[1]).to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # Training loop
    num_epochs = 10
    print("\nStarting training...")
    for epoch in range(num_epochs):
        model.train()
        total_loss = 0
        progress_bar = tqdm(train_loader, desc=f'Epoch {epoch+1}/{num_epochs}')
        
        for features, labels in progress_bar:
            features, labels = features.to(device), labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            progress_bar.set_postfix({'loss': total_loss/len(train_loader)})
    
    # Evaluate model
    print("\nEvaluating model...")
    model.eval()
    total_mse = 0
    with torch.no_grad():
        for features, labels in test_loader:
            features, labels = features.to(device), labels.to(device)
            outputs = model(features)
            mse = criterion(outputs, labels)
            total_mse += mse.item()
    
    avg_mse = total_mse / len(test_loader)
    print(f"Test MSE: {avg_mse:.4f}")
    
    # Save model and vectorizer
    print("\nSaving model...")
    if not os.path.exists('models'):
        os.makedirs('models')
    torch.save({
        'model_state_dict': model.state_dict(),
        'input_size': dataset.features.shape[1]
    }, 'models/password_strength_model.pth')
    joblib.dump(dataset.vectorizer, 'models/password_vectorizer.joblib')
    
    print("Training complete!")

if __name__ == '__main__':
    # Download dataset if not exists
    download_rockyou()
    
    # Train the model
    train_model() 