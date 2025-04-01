from flask import Flask
from models import db, Password
import json
from datetime import datetime
from sqlalchemy import text

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

def migrate():
    with app.app_context():
        # Add the new column without default value
        db.session.execute(text('ALTER TABLE passwords ADD COLUMN strength_history TEXT'))
        
        # Set default value for existing rows
        db.session.execute(text('UPDATE passwords SET strength_history = "[]" WHERE strength_history IS NULL'))
        
        # Update existing passwords with initial strength data
        passwords = Password.query.all()
        for password in passwords:
            try:
                # Calculate current strength
                current_strength = password.calculate_password_strength(password.get_password())
                
                # Create history entry
                history = [{
                    'date': password.created_at.isoformat(),
                    'strength': current_strength
                }]
                
                # Update the record
                password.strength_history = json.dumps(history)
                
            except Exception as e:
                print(f"Error updating password {password.id}: {str(e)}")
        
        db.session.commit()
        print("Migration completed successfully!")

if __name__ == '__main__':
    migrate() 