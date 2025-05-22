# Secure User Management System

A secure Flask-based web application for user management with encrypted data storage and robust security features.

## Features

- User registration and authentication
- Secure password hashing
- Encrypted user profile data
- Rate limiting for API endpoints
- CSRF protection
- Content Security Policy (CSP)
- Secure session management
- Comprehensive logging system
- Input sanitization and validation
- Docker support

## Prerequisites

- Python 3.7+
- pip (Python package manager)
- Docker (optional, for containerization)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <project-directory>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
```

## Configuration

The application uses the following environment variables:

- `SECRET_KEY`: Secret key for session management and CSRF protection
- `ENCRYPTION_KEY`: Key for encrypting sensitive user data

You can set these in your environment or create a `.env` file.

## Running the Application

### Development Mode
```bash
python app.py
```

### Using Docker
```bash
./containerize.sh
```

## Project Structure

```
.
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── Dockerfile         # Docker configuration
├── containerize.sh    # Docker build and run script
├── init_db.py         # Database initialization
├── security_test.py   # Security testing suite
├── analyze_logs.sh    # Log analysis script
├── templates/         # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── user_profile.html
│   ├── 404.html
│   └── 500.html
└── logs/             # Application logs
```

## Security Features

1. **Password Security**
   - Passwords are hashed using Werkzeug's security functions
   - Password validation requires:
     - Minimum 8 characters
     - At least one letter
     - At least one number
     - At least one special character

2. **Data Encryption**
   - Sensitive user data (bio, location, interests) is encrypted using Fernet symmetric encryption
   - Encryption key is configurable via environment variable

3. **Input Validation**
   - Username validation:
     - 3-20 characters
     - Alphanumeric and underscore only
   - Input sanitization for all user inputs
   - HTML escaping to prevent XSS

4. **Rate Limiting**
   - Login attempts: 20 per minute
   - Registration attempts: 20 per minute

5. **Session Security**
   - Secure session cookies
   - HTTP-only cookies
   - SameSite cookie policy
   - 1-hour session lifetime

6. **Content Security Policy**
   - Strict CSP headers
   - Frame protection
   - XSS protection

## API Endpoints

- `GET /`: Home page
- `GET/POST /register`: User registration
- `GET/POST /login`: User authentication
- `GET /dashboard`: User dashboard (protected)
- `GET /logout`: User logout
- `GET/POST /profile`: User profile management (protected)
- `GET /user/<username>`: Public user profile

## Logging

The application uses a rotating file logging system:
- Logs are stored in the `logs/` directory
- Maximum log file size: 2MB
- Keeps 5 backup files
- Logs include timestamp, level, and message

## Error Handling

- Custom 404 and 500 error pages
- Rate limit exceeded handling
- Comprehensive error logging
- User-friendly error messages

## Development

### Running Tests
```bash
python security_test.py
```

### Analyzing Logs
```bash
./analyze_logs.sh
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


## Security Considerations

- Always use HTTPS in production
- Regularly update dependencies
- Monitor logs for suspicious activity
- Keep encryption keys secure
- Regularly backup the database 

