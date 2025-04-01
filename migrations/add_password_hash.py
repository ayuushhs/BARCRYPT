from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from models import db

def upgrade():
    try:
        # Add password_hash column
        db.session.execute(text('ALTER TABLE passwords ADD COLUMN password_hash VARCHAR(128) NOT NULL DEFAULT ""'))
        db.session.commit()
        print("Successfully added password_hash column")
    except Exception as e:
        print(f"Error during migration: {e}")
        db.session.rollback()

def downgrade():
    try:
        # Remove password_hash column
        db.session.execute(text('ALTER TABLE passwords DROP COLUMN password_hash'))
        db.session.commit()
        print("Successfully removed password_hash column")
    except Exception as e:
        print(f"Error during migration: {e}")
        db.session.rollback() 