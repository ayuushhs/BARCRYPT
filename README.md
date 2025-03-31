# BARCRYPT - Password Security Application

A Flask-based web application for analyzing password strength and managing passwords securely.

## Features

- **Password Strength Analysis**: Real-time client-side and robust server-side analysis of password strength
- **Password Management**: Secure storage and management of passwords
- **Interactive UI**: Real-time visual feedback on password strength with detailed suggestions
- **Time-to-Crack Estimates**: Information about how long a password would take to crack

## Technology Stack

- **Backend**: Python with Flask
- **Frontend**: HTML, CSS, JavaScript
- **Password Analysis**: Custom algorithm based on entropy, pattern detection, and security best practices

## Setup and Installation

1. Clone the repository:
   ```
   git clone https://github.com/ayuushhs/BARCRYPT.git
   cd BARCRYPT
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the Flask application:
   ```
   python app.py
   ```

4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## Password Security Criteria

The system evaluates passwords based on the following criteria:
- Minimum length of 10 characters
- Presence of uppercase letters
- Presence of lowercase letters
- Presence of numbers
- Presence of special characters

## Routes

- `/` - Homepage
- `/login` - User login page
- `/register` - Account creation page
- `/analyze` - Analyze password strength
- `/manage` - Manage saved passwords

## Future Enhancements

- Machine learning model for improved password strength prediction
- Password generator with customizable parameters
- Browser extension for password analysis
- Two-factor authentication support

## Contributing

Contributions to improve BARCRYPT are welcome. Please feel free to submit a Pull Request. 