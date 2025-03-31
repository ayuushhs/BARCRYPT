from flask import Flask, render_template, request, redirect, url_for, flash
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flash messages

def validate_password_strength(password):
    """
    Validates password strength based on the following criteria:
    - At least 10 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    
    Returns a dictionary with validation results and feedback
    """
    # Initialize criteria checks
    criteria = {
        'length': len(password) >= 10,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'numbers': bool(re.search(r'[0-9]', password)),
        'special': bool(re.search(r'[^A-Za-z0-9]', password))
    }
    
    # Count how many criteria are met
    criteria_met = sum(criteria.values())
    
    # Determine strength level
    if criteria_met <= 1:
        strength = 'very-weak'
        label = 'Very Weak'
        feedback = 'This password is extremely vulnerable to attacks.'
    elif criteria_met == 2:
        strength = 'weak'
        label = 'Weak'
        feedback = 'This password could be easily cracked.'
    elif criteria_met == 3:
        strength = 'medium'
        label = 'Medium'
        feedback = 'This password provides moderate security but could be improved.'
    elif criteria_met == 4:
        strength = 'strong'
        label = 'Strong'
        feedback = 'This password is strong, but one more criterion would make it very strong.'
    else:
        strength = 'very-strong'
        label = 'Very Strong'
        feedback = 'Excellent! This password meets all security criteria.'
    
    # Generate suggestions for improvement
    suggestions = []
    if not criteria['length']:
        suggestions.append('Increase length to at least 10 characters.')
    if not criteria['uppercase']:
        suggestions.append('Add at least one uppercase letter (A-Z).')
    if not criteria['lowercase']:
        suggestions.append('Add at least one lowercase letter (a-z).')
    if not criteria['numbers']:
        suggestions.append('Add at least one number (0-9).')
    if not criteria['special']:
        suggestions.append('Add at least one special character (e.g., !@#$%^&*).')
    
    return {
        'criteria': criteria,
        'strength_class': strength,
        'strength_label': label,
        'feedback': feedback,
        'suggestions': suggestions
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Here you would typically validate the credentials
        # For now, just redirect back to home with a success message
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/register')
def register():
    # This will be implemented later
    return render_template('register.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        password = request.form.get('password')
        
        if not password:
            flash('Please enter a password to analyze.', 'danger')
            return render_template('analyze.html', password_checked=False)
        
        # Analyze password strength
        result = validate_password_strength(password)
        
        return render_template(
            'analyze.html',
            password_checked=True,
            strength_class=result['strength_class'],
            strength_label=result['strength_label'],
            feedback=result['feedback'],
            suggestions=result['suggestions']
        )
    
    return render_template('analyze.html', password_checked=False)

@app.route('/manage')
def manage():
    # This will be implemented later
    return render_template('manage.html')

if __name__ == '__main__':
    app.run(debug=True) 