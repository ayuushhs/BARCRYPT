from app import app, db
from migrations.add_password_hash import upgrade

with app.app_context():
    try:
        upgrade()
        print("Migration completed successfully!")
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        db.session.rollback() 