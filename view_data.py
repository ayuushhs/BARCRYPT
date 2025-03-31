from app import app, db
from models import User
from tabulate import tabulate
from sqlalchemy import text
import logging

# Configure SQLAlchemy logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sqlalchemy.engine')
logger.setLevel(logging.INFO)

def view_users():
    with app.app_context():
        # Get the database URL
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"\nDatabase URL: {db_url}")
        
        # Get database schema information
        print("\nDatabase Schema:")
        result = db.session.execute(text("SHOW TABLES"))
        tables = result.fetchall()
        for table in tables:
            print(f"\nTable: {table[0]}")
            # Get column information
            result = db.session.execute(text(f"DESCRIBE {table[0]}"))
            columns = result.fetchall()
            print("Columns:")
            for col in columns:
                print(f"  - {col[0]} ({col[1]})")
        
        # Query all users with SQL logging
        print("\nExecuting SQL Query:")
        users = User.query.all()
        
        # Prepare data for tabulate
        table_data = []
        for user in users:
            table_data.append([
                user.id,
                user.username,
                user.email,
                user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                user.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Define headers
        headers = ['ID', 'Username', 'Email', 'Created At', 'Updated At']
        
        # Print the table
        print("\nUsers Table:")
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal Users: {len(users)}")

if __name__ == '__main__':
    view_users() 