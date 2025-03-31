from flask import Flask, render_template, request, redirect, url_for, flash
import re
import password_model

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flash messages

def validate_password_strength(password):
    """
    Validate password strength using the ML model and basic checks
    """
    # Get comprehensive analysis from the ML model
    analysis = password_model.analyze_password(password)
    
    # Return all analysis information
    return analysis

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
        
        # Analyze password strength using the ML model
        result = validate_password_strength(password)
        
        return render_template(
            'analyze.html',
            password_checked=True,
            strength_class=result['strength_class'],
            strength_label=result['strength_label'],
            feedback=result['feedback'],
            suggestions=result['suggestions'],
            entropy=result['entropy'],
            crack_times=result['crack_times'],
            improved_passwords=result['improved_passwords']
        )
    
    return render_template('analyze.html', password_checked=False)

@app.route('/manage')
def manage():
    # This will be implemented later
    return render_template('manage.html')

if __name__ == '__main__':
    app.run(debug=True) 