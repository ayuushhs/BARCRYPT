from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from flask_cors import CORS
import re
from models import db, User, Password
from config import Config
import password_model
from datetime import datetime, timedelta
from breach_checker import BreachChecker
import urllib.parse
from password_analyzer import PasswordAnalyzer
import json
from password_strength_analyzer import PasswordStrengthAnalyzer

app = Flask(__name__)
app.config.from_object(Config)

# Set session configuration
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure CORS with specific settings for the extension
CORS(app, resources={
    r"/api/*": {
        "origins": ["chrome-extension://*", "http://localhost:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Content-Type", "X-CSRFToken"],
        "send_wildcard": False
    }
})

# Initialize breach checker
breach_checker = BreachChecker()

# Initialize password analyzer
password_analyzer = PasswordAnalyzer()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

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
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
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
    # Get user's passwords
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    
    # Initialize statistics
    stats = {
        'total_passwords': len(passwords),
        'breached_sites': 0,
        'passwords_need_update': 0,
        'recent_breaches': [],
        'security_improvement': {
            'labels': [],
            'data': [],
            'average_strength': 0,
            'total_improvement': 0
        }
    }
    
    # Calculate security improvement over time
    if passwords:
        all_strengths = []
        for password in passwords:
            history = password.get_strength_history()
            if history:
                # Add each strength data point
                for entry in history:
                    all_strengths.append({
                        'date': entry['date'],
                        'strength': entry['strength']
                    })
        
        # Sort by date
        all_strengths.sort(key=lambda x: x['date'])
        
        # Calculate average strength and improvement
        if all_strengths:
            initial_strength = all_strengths[0]['strength']
            current_strength = all_strengths[-1]['strength']
            stats['security_improvement']['total_improvement'] = current_strength - initial_strength
            stats['security_improvement']['average_strength'] = sum(entry['strength'] for entry in all_strengths) / len(all_strengths)
            
            # Get monthly averages for the graph
            monthly_data = {}
            for entry in all_strengths:
                month = entry['date'][:7]  # Get YYYY-MM
                if month not in monthly_data:
                    monthly_data[month] = {'total': 0, 'count': 0}
                monthly_data[month]['total'] += entry['strength']
                monthly_data[month]['count'] += 1
            
            # Calculate monthly averages
            for month, data in monthly_data.items():
                stats['security_improvement']['labels'].append(month)
                stats['security_improvement']['data'].append(data['total'] / data['count'])
    
    # Check each password for breaches and age
    for password in passwords:
        # Check website breach status
        try:
            domain = urllib.parse.urlparse(password.website).netloc
            if not domain:
                domain = password.website.split('/')[0]
            
            breach_info = breach_checker.check_website_breaches(domain)
            
            if breach_info.get('breached'):
                stats['breached_sites'] += 1
                # Add to recent breaches if breach date is available
                if breach_info.get('breach_date'):
                    stats['recent_breaches'].append({
                        'website': password.website,
                        'breach_date': breach_info['breach_date'],
                        'pwn_count': breach_info.get('pwn_count', 'Unknown')
                    })
        except Exception as e:
            print(f"Error checking breach for {password.website}: {str(e)}")
        
        # Check password age
        password_age = (datetime.utcnow() - password.updated_at).days
        if password_age >= 180:  # Older than 6 months
            stats['passwords_need_update'] += 1
    
    # Sort recent breaches by date (newest first)
    stats['recent_breaches'].sort(key=lambda x: x['breach_date'], reverse=True)
    # Limit to 5 most recent breaches
    stats['recent_breaches'] = stats['recent_breaches'][:5]
    
    return render_template('dashboard.html', stats=stats)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password:
            analyzer = PasswordStrengthAnalyzer()
            analysis = analyzer.analyze_password_strength(password)
            breach_status = analyzer.check_breach_status(password)
            suggestions = analyzer.generate_suggestions(password)
            
            # Determine strength category and score
            strength_score = analysis['score']
            if strength_score >= 90:
                strength_class = 'bg-very-strong'
                strength_label = 'Very Strong'
            elif strength_score >= 75:
                strength_class = 'bg-strong'
                strength_label = 'Strong'
            elif strength_score >= 50:
                strength_class = 'bg-medium'
                strength_label = 'Medium'
            elif strength_score >= 25:
                strength_class = 'bg-weak'
                strength_label = 'Weak'
            else:
                strength_class = 'bg-very-weak'
                strength_label = 'Very Weak'
            
            # Determine password category
            metrics = analysis['metrics']
            if metrics['is_common']:
                password_category = 'Common Password'
            elif metrics['has_sequences']:
                password_category = 'Pattern-Based'
            elif metrics['has_repeated_chars']:
                password_category = 'Repetitive'
            elif all([metrics['has_uppercase'], metrics['has_lowercase'], 
                     metrics['has_numbers'], metrics['has_special']]):
                password_category = 'Complex'
            elif metrics['length'] >= 12:
                password_category = 'Long'
            else:
                password_category = 'Basic'
            
            return render_template('analyze.html', 
                                 analysis={
                                     'entropy': analysis['score'],
                                     'crack_time': format_crack_time(analysis['crack_times']['offline_slow']),
                                     'attack_vectors': analysis['feedback'],
                                     'weaknesses': [w for w in analysis['feedback'] if 'weak' in w.lower() or 'missing' in w.lower()],
                                     'suggestions': suggestions,
                                     'strength_score': strength_score,
                                     'strength_class': strength_class,
                                     'strength_label': strength_label,
                                     'password_category': password_category,
                                     'metrics': metrics
                                 })
    return render_template('analyze.html')

def format_crack_time(seconds):
    if seconds < 1:
        return "Less than a second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 2592000:
        return f"{int(seconds/86400)} days"
    elif seconds < 31536000:
        return f"{int(seconds/2592000)} months"
    else:
        return f"{int(seconds/31536000)} years"

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze_password():
        password = request.form.get('password')
        if not password:
        return jsonify({'error': 'Password is required'}), 400

    analyzer = PasswordStrengthAnalyzer()
    analysis = analyzer.analyze_password_strength(password)
    breach_status = analyzer.check_breach_status(password)
    suggestions = analyzer.generate_suggestions(password)

    return jsonify({
        'analysis': analysis,
        'breach_status': breach_status,
        'suggestions': suggestions
    })

@app.route('/manage')
@login_required
def manage():
    return render_template('manage.html')

@app.route('/api/passwords', methods=['POST'])
@login_required
def create_password():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['website', 'username', 'password']):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        # Check if password already exists for this website and username
        existing_password = Password.query.filter_by(
            user_id=current_user.id,
            website=data['website'],
            username=data['username']
        ).first()
        
        if existing_password:
            return jsonify({
                'success': False,
                'error': 'Password already exists for this website and username'
            }), 409
        
        # Create new password
        new_password = Password(
            website=data['website'],
            username=data['username'],
            notes=data.get('notes', ''),
            user_id=current_user.id,
            breach_status=False,
            breach_count=0,
            last_breach_check=datetime.utcnow()
        )
        
        # Set the password (this will handle encryption and hash)
        new_password.set_password(data['password'])
        
        # Check breach status
        try:
            breach_status = breach_checker.check_password_leaked(data['password'])
            new_password.breach_status = breach_status.get('leaked', False)
            new_password.breach_count = breach_status.get('count', 0)
            new_password.last_breach_check = datetime.utcnow()
        except Exception as e:
            app.logger.error(f"Error checking breach status: {str(e)}")
        
        db.session.add(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'id': new_password.id,
            'website': new_password.website,
            'username': new_password.username,
            'notes': new_password.notes,
            'breach_status': new_password.breach_status,
            'breach_count': new_password.breach_count,
            'last_breach_check': new_password.last_breach_check.isoformat() if new_password.last_breach_check else None,
            'created_at': new_password.created_at.isoformat(),
            'updated_at': new_password.updated_at.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating password: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/passwords/<int:password_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
def password_operations(password_id):
    try:
        password = Password.query.get_or_404(password_id)
        
        # Ensure the password belongs to the current user
        if password.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'id': password.id,
                'website': password.website,
                'username': password.username,
                'password': password.get_password(),
                'notes': password.notes,
                'breach_status': password.breach_status,
                'breach_count': password.breach_count,
                'last_breach_check': password.last_breach_check.isoformat() if password.last_breach_check else None,
                'created_at': password.created_at.isoformat(),
                'updated_at': password.updated_at.isoformat()
            })
            
        elif request.method == 'DELETE':
            db.session.delete(password)
            db.session.commit()
            return jsonify({'success': True})
            
        elif request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400
            
            # Update fields
            password.website = data['website']
            password.username = data['username']
            if 'password' in data and data['password']:
                password.set_password(data['password'])
            password.notes = data.get('notes', '')
            
            # Check breach status if password was updated
            if 'password' in data and data['password']:
                try:
                    breach_status = breach_checker.check_password_leaked(data['password'])
                    password.breach_status = breach_status.get('leaked', False)
                    password.breach_count = breach_status.get('count', 0)
                    password.last_breach_check = datetime.utcnow()
                except Exception as e:
                    app.logger.error(f"Error checking breach status: {str(e)}")
            
            db.session.commit()
            return jsonify({'success': True})
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in password operations: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'})
    
    if not current_user.check_password(current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'})
    
    # Check password strength
    strength_result = validate_password_strength(new_password)
    if strength_result['strength_class'] in ['very-weak', 'weak']:
        return jsonify({'success': False, 'message': 'New password is too weak. Please choose a stronger password.'})
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/check_breach_status/<int:password_id>')
@login_required
def check_breach_status(password_id):
    try:
        password = Password.query.get_or_404(password_id)
        
        # Verify ownership
        if password.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
        # Check password leak status
        leak_status = breach_checker.check_password_leaked(password.get_password())
        
        # Check website breach status
        domain = urllib.parse.urlparse(password.website).netloc
        if not domain:
            domain = password.website.split('/')[0]
        website_status = breach_checker.check_website_breaches(domain)
        
        # Update password breach status
        password.breach_status = leak_status.get('leaked', False) or website_status.get('breached', False)
        password.breach_count = leak_status.get('count', 0)
        password.last_breach_check = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'breach_status': {
                'breached': password.breach_status,
                'breach_count': password.breach_count,
                'leak_status': leak_status,
                'website_status': website_status,
                'last_checked': password.last_breach_check.isoformat()
            }
        })
    except Exception as e:
        app.logger.error(f"Error checking breach status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/check-password-leaked', methods=['POST'])
@login_required
def check_password_leaked():
    """Check if a password has been exposed in data breaches"""
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({
                'success': False,
                'error': 'No password provided'
            }), 400
        
        password = data['password']
        result = breach_checker.check_password_leaked(password)
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        print(f"Error checking password leak status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/check-breach/<website>')
@login_required
def check_website_breach(website):
    """Check if a website has been involved in any data breaches"""
    try:
        # Extract domain from website URL
        domain = urllib.parse.urlparse(website).netloc
        if not domain:
            domain = website.split('/')[0]
        
        result = breach_checker.check_website_breaches(domain)
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        print(f"Error checking website breach status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/passwords/search')
@login_required
def search_passwords():
    try:
        website = request.args.get('website', '')
        username = request.args.get('username', '')
        
        query = Password.query.filter_by(user_id=current_user.id)
        
        if website:
            query = query.filter(Password.website.ilike(f'%{website}%'))
        if username:
            query = query.filter(Password.username.ilike(f'%{username}%'))
            
        passwords = query.all()
        
        return jsonify({
            'success': True,
            'passwords': [{
                'id': p.id,
                'website': p.website,
                'username': p.username,
                'password': p.get_password(),
                'breach_status': p.breach_status,
                'breach_count': p.breach_count,
                'last_breach_check': p.last_breach_check.isoformat() if p.last_breach_check else None,
                'created_at': p.created_at.isoformat(),
                'updated_at': p.updated_at.isoformat()
            } for p in passwords]
        })
    except Exception as e:
        app.logger.error(f"Error searching passwords: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/check-login')
def check_login():
    try:
        if current_user.is_authenticated:
            return jsonify({
                'success': True,
                'logged_in': True,
                'user': {
                    'username': current_user.username,
                    'id': current_user.id
                }
            })
        return jsonify({
            'success': True,
            'logged_in': False,
            'message': 'User not logged in'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'logged_in': False,
            'message': str(e)
        }), 500

@app.route('/api/generate-password', methods=['GET'])
def generate_password():
    try:
        # Generate three suggestions and pick the strongest one
        suggestions = password_model.suggest_improved_password("")
        
        # Analyze each suggestion to find the strongest one
        best_password = None
        best_strength = 0
        
        for suggestion in suggestions:
            analysis = password_model.analyze_password(suggestion)
            crack_times = analysis.get('crack_times', {})
            
            # Use offline_slow time as a measure of strength
            strength = crack_times.get('offline_slow', 0)
            
            if strength > best_strength:
                best_strength = strength
                best_password = suggestion
        
        return jsonify({
            'success': True,
            'password': best_password,
            'analysis': password_model.analyze_password(best_password)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/edit_password', methods=['POST'])
@login_required
def edit_password():
    try:
        data = request.get_json()
        password_id = data.get('password_id')
        new_password = data.get('password')
        new_website = data.get('website')
        new_username = data.get('username')
        
        if not all([password_id, new_password, new_website, new_username]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        password = Password.query.filter_by(id=password_id, user_id=current_user.id).first()
        if not password:
            return jsonify({'success': False, 'error': 'Password not found'})
        
        # Update password details
        password.password = new_password
        password.website = new_website
        password.username = new_username
        password.last_modified = datetime.now()
        
        # Check breach status
        analyzer = PasswordStrengthAnalyzer()
        breach_status = analyzer.check_breach_status(new_password)
        password.breach_status = breach_status['breached']
        password.breach_count = breach_status['breach_count']
        password.last_breach_check = datetime.now()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password updated successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True) 