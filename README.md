# Role-Based Authentication Web Application

A Flask-based web application that supports user authentication, role-based access control, and admin operations with proper backend and frontend separation.

## Features

### Authentication Features (Common for all users)
- Login
- Logout
- Change Password
- Register (as student only)
- Welcome Page upon successful login

### Roles
- Admin
- Student

### Admin Role Features
- Admin user is created during application initialization (seeding)
- Only admin can:
  - Create a new user
  - Delete an existing user
  - View a list of all users
- Admin can assign roles when creating a new user
- Admin has access to a dashboard with user management options

### Student Role Features
- Can only view a welcome page after login
- Cannot access user management screens

## Tech Stack
- Backend: Python Flask
- Database: SQLite with SQLAlchemy ORM
- Frontend: HTML, CSS with Flask templates
- Authentication: Flask-Login
- Form Handling: Flask-WTF

## Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
```
git clone <repository-url>
cd assignment_c
```

2. Create a virtual environment (optional but recommended):
```
python -m venv venv
```

3. Activate the virtual environment:
- On Windows:
```
venv\Scripts\activate
```
- On macOS/Linux:
```
source venv/bin/activate
```

4. Install dependencies:
```
pip install -r requirements.txt
```

5. Run the application:
```
python app.py
```

6. Access the application in your browser:
```
http://127.0.0.1:5000
```

## Default Admin Credentials
- Username: admin
- Password: admin123

## Edge Cases Handled
- Duplicate users during registration
- Wrong credentials error messages
- Strong password policies (minimum length)
- Protection of admin-only routes
- Empty fields and malformed inputs validation

## Project Structure
- `app.py`: Main application file with routes and configuration
- `models.py`: Database models for User and Role
- `forms.py`: Form classes for input validation
- `templates/`: HTML templates for the frontend
- `requirements.txt`: List of Python dependencies

## Contributors
- [Your Name/Team Member Names]

## License
This project is licensed under the MIT License - see the LICENSE file for details.
