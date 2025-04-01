from flask_migrate import Migrate
from models import db
from sqlalchemy import text

def upgrade():
    # Add new columns to passwords table
    db.session.execute(text('''
        ALTER TABLE passwords
        ADD COLUMN breach_status BOOLEAN DEFAULT FALSE,
        ADD COLUMN breach_count INTEGER DEFAULT 0,
        ADD COLUMN last_breach_check DATETIME
    '''))
    db.session.commit()

def downgrade():
    # Remove the columns if we need to roll back
    db.session.execute(text('''
        ALTER TABLE passwords
        DROP COLUMN breach_status,
        DROP COLUMN breach_count,
        DROP COLUMN last_breach_check
    '''))
    db.session.commit() 