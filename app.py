from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import re
from models import db, User
from config import Config
import password_model

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate all fields
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields.', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
            
        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email address.', 'danger')
            return render_template('register.html')
            
        # Check password strength
        strength_result = validate_password_strength(password)
        if strength_result['strength_class'] in ['very-weak', 'weak']:
            flash('Password is too weak. Please choose a stronger password.', 'danger')
            return render_template('register.html')
            
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
            
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

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
@login_required
def manage():
    return render_template('manage.html')

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True) 