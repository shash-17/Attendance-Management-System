from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


from datetime import datetime, timedelta, date
from calendar import monthrange, calendar, firstweekday, monthcalendar
import calendar
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function to establish database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for login page
@app.route('/')
def index():
    return render_template('login.html')

# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    userid = request.form['userid']
    password = request.form['password']
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE userid = ?', (userid,)).fetchone()
    conn.close()
    
    if user is None or not check_password_hash(user['password'], password):
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))
    
    # Store user information in session
    session['user'] = {
        'id': user['id'],
        'name': user['name'],
        'role': user['role']
    }
    
    # Redirect based on role
    if user['role'] == 'Admin':
        return redirect(url_for('admin'))
    elif user['role'] == 'Manager':
        return redirect(url_for('manager'))
    elif user['role'] == 'Employee':
        return redirect(url_for('employee'))
    else:
        flash('Unknown role', 'error')
        return redirect(url_for('index'))

# Route for admin dashboard - view records
@app.route('/admin')
def admin():
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    records = conn.execute('SELECT id, name, role, company, userid FROM users').fetchall()
    conn.close()
    
    return render_template('admin.html', user=session['user'], records=records)


# Route for adding new record
@app.route('/admin/add_record', methods=['GET', 'POST'])

def add_record():
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        
        id = request.form['id']
        name = request.form['name']
        role = request.form['role']
        userid = request.form['userid']
        company = request.form['company']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (id,name, role, userid, password, company) VALUES (?, ?, ?, ?, ?, ?)', 
                         (id,name, role, userid, hashed_password, company))
            conn.commit()
            conn.close()
            flash('Record added successfully', 'success')
        except sqlite3.Error as e:
            print(f"Error inserting record: {e}")
            flash('Failed to add record', 'error')
        return redirect(url_for('admin'))
    
    return render_template('add_record.html', user=session.get('user'))



# Route for modifying record
@app.route('/admin/edit_record/<int:id>', methods=['GET', 'POST'])
def edit_record(id):
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    record = conn.execute('SELECT id, name, role, company, userid FROM users WHERE id = ?', (id,)).fetchone()
    
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        role = request.form['role']
        userid = request.form['userid']
        
        # Update record in database
        conn.execute('UPDATE users SET name = ?, role = ?, userid = ? WHERE id = ?', 
                     (name, role, userid, id))
        conn.commit()
        conn.close()
        
        flash('Record updated successfully', 'success')
        return redirect(url_for('admin'))
    
    conn.close()
    return render_template('edit_record.html', user=session['user'], record=record)

# Route for deleting record
@app.route('/admin/delete_record/<int:id>', methods=['POST'])
def delete_record(id):
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('Record deleted successfully', 'success')
    return redirect(url_for('admin'))


# Function to get attendance data
def get_attendance_data(user_id):
    conn = get_db_connection()
    attendance = conn.execute('SELECT * FROM attendance WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return attendance

# Function to update attendance data
def update_attendance_records():
    today = date.today()
    conn = get_db_connection()
    employees = conn.execute('SELECT id FROM users WHERE role =?', ('Employee',)).fetchall()
    for employee in employees:
        employee_id = employee['id']
        existing_record = conn.execute('SELECT * FROM attendance WHERE user_id =? AND date =?', (employee_id, today)).fetchone()
        if not existing_record:
            # If no record exists, create a new one with status 'absent'
            conn.execute('INSERT INTO attendance (user_id, date, status) VALUES (?,?,?)',
                         (employee_id, today, 'absent'))
            conn.commit()
        elif existing_record['checkout_time'] is None:
            # If the employee didn't check out, update the status to 'absent'
            conn.execute('UPDATE attendance SET status =? WHERE user_id =? AND date =?',
                         ('absent', employee_id, today))

# Function to get leave requests data
def get_leave_requests_data(user_id):
    conn = get_db_connection()
    leave_requests = conn.execute('SELECT * FROM leave_requests WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return leave_requests

#function to update attendance system at scheduled time
scheduler = BackgroundScheduler()
scheduler.add_job(update_attendance_records, trigger=CronTrigger(hour=11, minute= 26))  
scheduler.start()

# Route for employee page
@app.route('/employee')
def employee():
    if 'user' not in session or session['user']['role'] != 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    attendance = get_attendance_data(user_id)
    leave_requests = get_leave_requests_data(user_id)

    today = date.today()
    calendar.setfirstweekday(calendar.SUNDAY)
    cal = calendar.monthcalendar(today.year, today.month)



    return render_template('employee.html', user=session['user'], cal=cal, attendance=attendance, leave_requests=leave_requests, today=today)

# Route for changing password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session or session['user']['role']!= 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        old_password = request.form['oldPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        conn = get_db_connection()
        user = conn.execute('SELECT password FROM users WHERE id =?', (session['user']['id'],)).fetchone()
        conn.close()

        if check_password_hash(user['password'], old_password):
            if new_password == confirm_password:
                hashed_password = generate_password_hash(new_password)
                conn = get_db_connection()
                conn.execute('UPDATE users SET password =? WHERE id =?', (hashed_password, session['user']['id']))
                conn.commit()
                conn.close()
                flash('Password changed successfully', 'success')
            else:
                flash('New password and confirm password do not match', 'error')
        else:
            flash('Old password is incorrect', 'error')

    return render_template('change_password.html', user=session['user'])

# Route for handling check-in
@app.route('/checkin', methods=['POST'])
def checkin():
    if 'user' not in session or session['user']['role']!= 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    today = date.today()

    conn = get_db_connection()
    existing_record = conn.execute('SELECT * FROM attendance WHERE user_id =? AND date =?', (user_id, today)).fetchone()
    if existing_record:
        if existing_record[2] is not None:
            
            return redirect(url_for('employee'))
    else:
        now = datetime.now().time()
        conn.execute('INSERT INTO attendance (user_id, date, checkin_time, status) VALUES (?,?,?,?)',
                     (user_id, today, now.strftime('%H:%M:%S'), 'checked-in'))
        conn.commit()
        conn.close()

    return redirect(url_for('employee'))


# Route for handling check-out
@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user' not in session or session['user']['role'] != 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    today = date.today()

    conn = get_db_connection()
    existing_record = conn.execute('SELECT * FROM attendance WHERE user_id =? AND date =?', (user_id, today)).fetchone()
    if not existing_record:
        
        return redirect(url_for('employee'))
    if existing_record['checkout_time'] is not None:  # Check if checkout time is already set
        
        return redirect(url_for('employee'))

    now = datetime.now().time()
    conn.execute('UPDATE attendance SET checkout_time =?, status =? WHERE user_id =? AND date =?', 
                 (now.strftime('%H:%M:%S'), 'present', user_id, today))
    conn.commit()
    conn.close()

    
    return redirect(url_for('employee'))

# Route for leave request
@app.route('/leave_request', methods=['POST'])
def leave_request():
    if 'user' not in session or session['user']['role'] != 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    leave_start = request.form['leaveStart']
    leave_end = request.form['leaveEnd']
    leave_reason = request.form['leaveReason']

    conn = get_db_connection()
    conn.execute('INSERT INTO leave_requests (user_id, leave_start, leave_end, leave_reason, status) VALUES (?, ?, ?, ?, ?)', 
                 (session['user']['id'], leave_start, leave_end, leave_reason, 'pending'))
    conn.commit()
    conn.close()

    
    return redirect(url_for('employee'))

@app.route('/manager_attendance', methods=['GET'])
def manager_attendance():
    if 'user' not in session or session['user']['role'] != 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    attendance = get_attendance_data(user_id)
    

    today = date.today()
    calendar.setfirstweekday(calendar.SUNDAY)
    cal = calendar.monthcalendar(today.year, today.month)



    return render_template('manager_attendance.html', user=session['user'], cal=cal, attendance=attendance, today=today)

# Route for changing manager password
@app.route('/change_mpassword', methods=['GET', 'POST'])
def change_mpassword():
    if 'user' not in session or session['user']['role']!= 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        old_password = request.form['oldPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        conn = get_db_connection()
        user = conn.execute('SELECT password FROM users WHERE id =?', (session['user']['id'],)).fetchone()
        conn.close()

        if check_password_hash(user['password'], old_password):
            if new_password == confirm_password:
                hashed_password = generate_password_hash(new_password)
                conn = get_db_connection()
                conn.execute('UPDATE users SET password =? WHERE id =?', (hashed_password, session['user']['id']))
                conn.commit()
                conn.close()
                flash('Password changed successfully', 'success')
            else:
                flash('New password and confirm password do not match', 'error')
        else:
            flash('Old password is incorrect', 'error')

    return render_template('change_mpassword.html', user=session['user'])

# Route for manager handling check-in
@app.route('/mcheckin', methods=['POST'])
def mcheckin():
    if 'user' not in session or session['user']['role']!= 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    today = date.today()

    conn = get_db_connection()
    existing_record = conn.execute('SELECT * FROM attendance WHERE user_id =? AND date =?', (user_id, today)).fetchone()
    if existing_record:
        if existing_record[2] is not None:
            
            return redirect(url_for('manager_attendance'))
    else:
        now = datetime.now().time()
        conn.execute('INSERT INTO attendance (user_id, date, checkin_time, status) VALUES (?,?,?,?)',
                     (user_id, today, now.strftime('%H:%M:%S'), 'checked-in'))
        conn.commit()
        conn.close()

    return redirect(url_for('manager_attendance'))


# Route for handling check-out
@app.route('/mcheckout', methods=['POST'])
def mcheckout():
    if 'user' not in session or session['user']['role'] != 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    today = date.today()

    conn = get_db_connection()
    existing_record = conn.execute('SELECT * FROM attendance WHERE user_id =? AND date =?', (user_id, today)).fetchone()
    if not existing_record:
        
        return redirect(url_for('manager_attendance'))
    if existing_record['checkout_time'] is not None:  # Check if checkout time is already set
        
        return redirect(url_for('manager_attendance'))

    now = datetime.now().time()
    conn.execute('UPDATE attendance SET checkout_time =?, status =? WHERE user_id =? AND date =?', 
                 (now.strftime('%H:%M:%S'), 'present', user_id, today))
    conn.commit()
    conn.close()

    
    return redirect(url_for('manager_attendance'))



@app.route('/manager', methods=['GET'])
def manager():
    if 'user' not in session or session['user']['role'] != 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    employees = conn.execute('SELECT * FROM users WHERE role = ?', ('Employee',)).fetchall()
    leave_requests = conn.execute('SELECT * FROM leave_requests ORDER BY id DESC').fetchall()
    conn.close()

    return render_template('manager.html', employees=employees, leave_requests=leave_requests)

@app.route('/attendance/<int:employee_id>', methods=['GET'])
def attendance(employee_id):
    conn = get_db_connection()
    attendance_records = conn.execute('''
        SELECT 
            date, 
            checkin_time, 
            checkout_time 
        FROM 
            attendance 
        WHERE 
            user_id =? 
        ORDER BY 
            date DESC
    ''', (employee_id,)).fetchall()
    conn.close()

    return render_template('attendance.html', attendance_records=attendance_records)

@app.route('/approve_leave/<int:request_id>', methods=['POST'])
def approve_leave(request_id):
    conn = get_db_connection()
    conn.execute('UPDATE leave_requests SET status = ? WHERE id = ?', ('approved', request_id))
    conn.commit()
    conn.close()

    
    return redirect(url_for('manager'))

@app.route('/deny_leave/<int:request_id>', methods=['POST'])
def deny_leave(request_id):
    conn = get_db_connection()
    conn.execute('UPDATE leave_requests SET status = ? WHERE id = ?', ('denied', request_id))
    conn.commit()
    conn.close()

    
    return redirect(url_for('manager'))

# Route for logging out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user', None)
    flash('You have been logged out')
    return redirect('/')


# Main section to run the Flask application
if __name__ == '__main__':
    app.run(debug=True)