# Attendance-Management-System
# Overview
The Attendance Management System is a web-based application developed using Flask, HTML, CSS, JavaScript, and SQLite. It is designed to simplify and automate attendance tracking, leave request management, and user role management for organizations such as educational institutions or workplaces. The system offers a secure and efficient way to manage attendance records and ensures smooth operations for both administrators and employees.

# Features
1. User Roles
Manager: Can manage employee records, view attendance, and approve leave requests.
Employee: Can view their own attendance, submit leave requests, and view their leave status.
Administrator: Has full access to manage all user roles, approve leave requests, and modify attendance records.
2. Leave Requests
Employees can submit leave requests, which are reviewed and approved by managers or administrators.
Managers and administrators can view, approve, or deny requests based on their role privileges.
3. Attendance Tracking
Admins and managers can mark attendance for employees.
Employees can view their attendance history and track their presence over time.
4. Secure Authentication
The system uses hashed password storage to securely authenticate users.
Users are required to log in with their credentials to access their role-specific functionalities.
5. Responsive Web Interface
Built using HTML, CSS, and JavaScript, the system provides a user-friendly, responsive interface for easy interaction.

# Technologies Used
Backend: Flask (Python)

Frontend: HTML, CSS, JavaScript

Database: SQLite

Authentication: Secure password hashing (using Flask extensions)

# Installation
Prerequisites:
Python 3.x

Flask

SQLite

# Usage
Once the application is running, navigate to the login page and sign in with the credentials assigned to your role. Depending on your role, you'll have access to different functionalities such as viewing and marking attendance, submitting or approving leave requests, and more.

# Contributing
Feel free to fork the repository, submit issues, or create pull requests to enhance the system. Contributions are welcome!
