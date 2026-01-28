from flask import Flask,send_file, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from functools import wraps
from datetime import datetime
from bson import ObjectId
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail
from datetime import datetime
from flask_mail import Message
from bson import ObjectId
from gridfs import GridFS
from bson.binary import Binary
from io import BytesIO
from flask import send_file, flash, redirect, url_for
import pytz
import json
from datetime import datetime
import pandas as pd
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import io
from dotenv import load_dotenv
from threading import Thread
from flask_mail import Message
load_dotenv()
ist = pytz.timezone('Asia/Kolkata')
app = Flask(__name__)
app.secret_key = os.getenv("secret_key")
serializer = URLSafeTimedSerializer(app.secret_key)
# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.audit_portal
users_col = db.users
audits_col = db.audits
# auditors_col = db.auditors  # Collection for auditor details
# auditees_col = db.auditees  # Collection for auditee details
fs = GridFS(db)



app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Use app password, not normal password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

# app.config['MAIL_SERVER'] = 'smtp.office365.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
# app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
# app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")


# app.config['SENDGRID_API_KEY'] = os.getenv("SENDGRID_API_KEY")
# app.config['DEFAULT_SENDER'] = os.getenv("DEFAULT_SENDER")

mail = Mail(app)



#Token generator
# s = URLSafeTimedSerializer(app.config['MAIL_PASSWORD'])



def create_initial_users():
    if not users_col.find_one({"username": "lead_auditor"}):
        lead_password = generate_password_hash("")
        lead_id = users_col.insert_one({
            "username": "lead_auditor",
            "password": lead_password,
            "role": "Lead Auditor",
            "email": "lead@example.com",
            "full_name": "Lead Auditor"
        }).inserted_id
        print("Lead Auditor created successfully")

create_initial_users()

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash("Access denied")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session['username'] = user['username']

            if user.get("must_change_password"):
                return redirect(url_for('change_password'))  # force password change

            if user['role'] == 'Lead Auditor':
                return redirect(url_for('lead_dashboard'))
            elif user['role'] == 'Auditor':
                return redirect(url_for('auditor_dashboard'))
            else:
                return redirect(url_for('auditee_dashboard'))

        flash("Invalid username or password")
    return render_template('login.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = users_col.find_one({"email": email})

        if user:
            token = serializer.dumps(str(user['_id']), salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message(
                subject='Password Reset Request',
                recipients=[email],
                body=f"Hi {user.get('full_name','')},\n\n"
                     f"Click below to reset your password:\n{reset_url}\n\n"
                     f"If you didn’t request this, please ignore."
            )
            Thread(target=send_async_email, args=(app, msg)).start()

            flash("Password reset link has been sent to your registered email.")
            return redirect(url_for('login'))
        else:
            flash("Email not found in our system.")
    return render_template('forgot_password.html')



def send_async_email(app, msg):
    try:
        with app.app_context():
            mail.send(msg)
    except Exception as e:
        # Log the error to console or file
        print(f"Email sending failed: {e}")

# from threading import Thread
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail as SGMail

# def send_async_sendgrid_email(to_emails, subject, content):
#     def _send():
#         try:
#             message = SGMail(
#                 from_email=app.config['DEFAULT_SENDER'],
#                 to_emails=to_emails,
#                 subject=subject,
#                 plain_text_content=content
#             )
#             sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
#             response = sg.send(message)
#             print(f"Email sent: {response.status_code}")
#         except Exception as e:
#             print(f"SendGrid email failed: {e}")
#     Thread(target=_send).start()


# from itsdangerous import URLSafeTimedSerializer

# # create serializer once, using your Flask app secret key


# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form['email'].strip().lower()
#         user = users_col.find_one({"email": email})

#         if user:
#             # Generate secure token
#             token = serializer.dumps(str(user['_id']), salt='password-reset-salt')

#             reset_link = url_for('reset_password', token=token, _external=True)

#             subject = "Password Reset Request"
#             body = f"Click the link to reset your password: {reset_link}"

#             send_async_sendgrid_email(email, subject, body)   # SendGrid function

#             flash('Password reset link sent to your email.', 'success')
#             return redirect(url_for('login'))

#         else:
#             flash('Email not found.', 'danger')
#     return render_template('forgot_password.html')




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The reset link is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("Invalid reset link.")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)
        users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password}})
        flash("Your password has been reset successfully. Please login.")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/lead-dashboard')
@role_required('Lead Auditor')
def lead_dashboard():
    from datetime import datetime, date

    today_str = date.today().strftime("%Y-%m-%dT%H:%M")
    auditors = list(users_col.find({"role": "Auditor"}))
    auditees = list(users_col.find({"role": "Auditee"}))

    # Filters
    filter_audit_type = request.args.get('filter_audit_type', '')
    filter_audit_area = request.args.get('filter_audit_area', '')
    filter_from_date = request.args.get('filter_from_date', '')
    filter_to_date = request.args.get('filter_to_date', '')
    filter_status = request.args.get('filter_status', '')  

    query = {}
    if filter_audit_type:
        query['audit_type'] = filter_audit_type
    if filter_audit_area:
        query['audit_area'] = {'$regex': filter_audit_area, '$options': 'i'}
    if filter_from_date and filter_to_date:
        query['audit_date'] = {
            '$gte': datetime.strptime(filter_from_date, "%Y-%m-%dT%H:%M"),
            '$lte': datetime.strptime(filter_to_date, "%Y-%m-%dT%H:%M")
        }
    elif filter_from_date:
        query['audit_date'] = {'$gte': datetime.strptime(filter_from_date, "%Y-%m-%dT%H:%M")}
    elif filter_to_date:
        query['audit_date'] = {'$lte': datetime.strptime(filter_to_date, "%Y-%m-%dT%H:%M")}
    if filter_status:
        query['status'] = filter_status  

    audits = list(audits_col.find(query).sort('audit_date', -1))

    for audit in audits:
        audit['_id'] = str(audit['_id'])

        
        for key, role, field in [
            ('auditor1', "Auditor", 'auditor1_name'),
            ('auditor2', "Auditor", 'auditor2_name'),
            ('auditee1', "Auditee", 'auditee1_name'),
            ('auditee2', "Auditee", 'auditee2_name'),
        ]:
            if audit.get(key):
                user = users_col.find_one({"_id": ObjectId(audit[key]), "role": role})
                audit[field] = user['full_name'] if user else "Unknown"
            else:
                audit[field] = "Not assigned"

        
        completed_count = 0
        pending_count = 0

        audit_date = audit.get('audit_date')
        audit_end_date = audit.get('audit_end_date')

        if isinstance(audit_date, str):
            audit_date = datetime.fromisoformat(audit_date)
        if isinstance(audit_end_date, str):
            audit_end_date = datetime.fromisoformat(audit_end_date)

        duration = "N/A"
        if audit_date and audit_end_date:
            delta = audit_end_date - audit_date
            days = delta.days
            seconds = delta.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            secs = seconds % 60
            audit['duration'] = f"{days}d {hours}h {minutes}m {secs}s"
        else:
            audit['duration'] = "N/A"




        for nc in audit.get('obc_details', []):
            # closed_date_str = None
            # closed_date = nc.get('obc_closed_date')

            # if isinstance(closed_date, datetime):
            #     closed_date_str = closed_date.strftime("%Y-%m-%dT%H:%M")
            # elif isinstance(closed_date, date):
            #     closed_date_str = closed_date.strftime("%Y-%m-%dT%H:%M")
            # elif isinstance(closed_date, str) and closed_date.strip():
            #     try:
            #         closed_date_str = datetime.strptime(closed_date, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%dT%H:%M")
            #     except ValueError:
            #         closed_date_str = None

            # nc['closed_date_str'] = closed_date_str

            # if nc.get('closure_status') == 'closed' and closed_date_str == today_str:

            if nc.get('closure_status') == 'closed':
                nc['status'] = 'Completed'
                completed_count += 1
            else:
                nc['status'] = 'Pending'
                pending_count += 1

        audit['completed_count'] = completed_count
        audit['pending_count'] = pending_count


        if audit.get("audit_date"):
            audit_date = audit["audit_date"]
            if isinstance(audit_date, str):
                audit_date = datetime.strptime(audit_date, "%Y-%m-%dT%H:%M")
            days_passed = (datetime.now().date() - audit_date.date()).days

            # Show actual aging for completed or ongoing audits
            audit["aging"] = max(0, days_passed - 4)
        else:
            audit["aging"] = None



    return render_template(
        'lead_dashboard.html',
        auditors=auditors,
        auditees=auditees,
        audits=audits,
        filters={
            'audit_type': filter_audit_type,
            'audit_area': filter_audit_area, 
            'from_date': filter_from_date,
            'to_date': filter_to_date,
            'status': filter_status  
        },
        today_str=today_str
    )

def parse_datetime(dt):
    if isinstance(dt, datetime):
        return dt
    if isinstance(dt, str):
        try:
            # Handles ISO 8601 with timezone like 2025-11-13T04:58:00.000+00:00
            return datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return None
    return None

@app.route('/update-audit/<audit_id>', methods=['POST'])
def update_audit(audit_id):
    data = request.form.to_dict()
    status = data.get("status")

    audit = audits_col.find_one({"_id": ObjectId(audit_id)})

    update_data = {"$set": data}

    if status and status.lower() == "completed":
        if audit and audit.get("audit_date"):
            audit_date = audit["audit_date"]
            if isinstance(audit_date, str):
                audit_date = datetime.strptime(audit_date, "%Y-%m-%dT%H:%M")
            days_passed = (datetime.now().date() - audit_date.date()).days
            update_data["$set"]["aging"] = max(0, days_passed - 4)

    audits_col.update_one({"_id": ObjectId(audit_id)}, update_data)

    return redirect(url_for("lead_dashboard"))

# def send_async_email(app, msg):
#     with app.app_context():
#         mail.send(msg)

@app.route('/schedule-audit', methods=['POST'])
@role_required('Lead Auditor')
def schedule_audit():
    try:
        audit_type = request.form['audit_type']
        audit_area = request.form['audit_area']
        audit_date = datetime.strptime(request.form['audit_date'], "%Y-%m-%dT%H:%M")
        audit_ref = request.form['audit_ref']
        status = request.form['status']
        auditor1 = request.form['auditor1']
        auditor2 = request.form.get('auditor2', '')
        auditee1 = request.form['auditee1']
        auditee2 = request.form.get('auditee2', '')

        # Create history entry
        history_entry = {
            "user": session['user_id'],
            "username": session['username'],
            "action": "Created audit",
            "timestamp": datetime.now()
        }

        # Insert audit
        audits_col.insert_one({
            "audit_type": audit_type,
            "audit_area": audit_area,
            "audit_date": audit_date,
            "audit_ref": audit_ref,
            "status": status,
            "auditor1": auditor1,
            "auditor2": auditor2,
            "auditee1": auditee1,
            "auditee2": auditee2,
            "NCs": [],
            "history": [history_entry]
        })

        # ✅ Collect email addresses
        recipients = []

        # Auditors
        auditor1_data = users_col.find_one({"_id": ObjectId(auditor1)})
        if auditor1_data and auditor1_data.get("email"):
            recipients.append(auditor1_data["email"])

        if auditor2:
            auditor2_data = users_col.find_one({"_id": ObjectId(auditor2)})
            if auditor2_data and auditor2_data.get("email"):
                recipients.append(auditor2_data["email"])

        # Auditees
        auditee1_data = users_col.find_one({"_id": ObjectId(auditee1)})
        if auditee1_data and auditee1_data.get("email"):
            recipients.append(auditee1_data["email"])

        if auditee2:
            auditee2_data = users_col.find_one({"_id": ObjectId(auditee2)})
            if auditee2_data and auditee2_data.get("email"):
                recipients.append(auditee2_data["email"])

        # ✅ Send notification email
        if recipients:
            subject = f"Audit Scheduled - {audit_type}"
            body = f"""
Dear Team,

A new audit has been scheduled.

📌 Audit Type: {audit_type}
🏢 Area: {audit_area}
📅 Date: {audit_date.strftime("%Y-%m-%dT%H:%M")}
🔖 Reference: {audit_ref}
🎯 Status: {status}

Please be prepared.

Regards,
Audit Management System
"""
            try:
                msg = Message(subject, recipients=recipients)
                msg.body = body
                # mail.send(msg)
                Thread(target=send_async_email, args=(app, msg)).start()
                flash(f"Audit scheduled and email sent to: {', '.join(recipients)}", "success")
            except Exception as e:
                flash(f"Audit scheduled but email failed: {str(e)}", "warning")
        else:
            flash("Audit scheduled but no emails found.", "info")

    except Exception as e:
        flash(f"Error scheduling audit: {str(e)}", "danger")

    return redirect(url_for('lead_dashboard'))



@app.route('/add-user', methods=['GET', 'POST'])
@role_required('Lead Auditor')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']
        full_name = request.form['full_name']

        # Check if username already exists
        if users_col.find_one({"username": username}):
            flash("Username already exists", "danger")
            return redirect(url_for('add_user'))

        # Insert user with must_change_password = True
        hashed_password = generate_password_hash(password)
        users_col.insert_one({
            "username": username,
            "password": hashed_password,
            "role": role,
            "email": email,
            "full_name": full_name,
            "created_date": datetime.now(),
            "must_change_password": True  # <-- this forces first-time password change
        })

        flash(f"User '{username}' with role '{role}' created successfully", "success")
        return redirect(url_for('lead_dashboard'))

    return render_template('add_user.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = users_col.find_one({"_id": ObjectId(session['user_id'])})

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('change_password'))

        # Password policy: 8-16 chars, at least 1 special character
        # pattern = r'^(?=.[!@#$%^&()_\-+=\[\]{}|\\;:\'",.<>/?]).{8,16}$'
        # if not re.match(pattern, new_password):
        #     flash("Password must be 8-16 characters long and include at least one special character", "danger")
        #     return redirect(url_for('change_password'))

        # Update password
        users_col.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {
                "password": generate_password_hash(new_password),
                "must_change_password": False
            }}
        )
        flash("Password changed successfully", "success")

        # Redirect to respective dashboard
        if user['role'] == 'Lead Auditor':
            return redirect(url_for('lead_dashboard'))
        elif user['role'] == 'Auditor':
            return redirect(url_for('auditor_dashboard'))
        else:
            return redirect(url_for('auditee_dashboard'))

    return render_template('change_password.html')

@app.route('/delete_person/<person_id>', methods=['DELETE'])
def delete_person(person_id):
    try:
        oid = ObjectId(person_id)
        result = users_col.delete_one({"_id": oid})
        if result.deleted_count > 0:
            return jsonify({"message": "Person deleted successfully"}), 200
        return jsonify({"message": "Person not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# View Audit Details
@app.route('/audit/<audit_id>')
@role_required('Lead Auditor')
def view_audit(audit_id):
    try:
        audit = audits_col.find_one({"_id": ObjectId(audit_id)})
        if not audit:
            flash("Audit not found")
            return redirect(url_for('lead_dashboard'))
        
        # Convert ObjectId to string for template rendering
        audit['_id'] = str(audit['_id'])
        
        # Get auditor and auditee names for display
        if audit.get('auditor1'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor1']),"role": "Auditor"})
            audit['auditor1_name'] = auditor['full_name'] if auditor else "Unknown"
            
        if audit.get('auditor2'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor2']),"role": "Auditor"})
            audit['auditor2_name'] = auditor['full_name'] if auditor else "Unknown"
            
        if audit.get('auditee1'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee1']),"role": "Auditor"})
            audit['auditee1_name'] = auditee['full_name'] if auditee else "Unknown"
            
        if audit.get('auditee2'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee2']),"role": "Auditor"})
            audit['auditee2_name'] = auditee['full_name'] if auditee else "Unknown"
            
        # NC ageing
        for nc in audit.get('NCs', []):
            nc_date = nc.get('date')
            if nc_date:
                nc["age_days"] = (datetime.now() - nc_date).days
            else:
                nc["age_days"] = None
        
        # Format history for display
        for entry in audit.get('history', []):
            if 'timestamp' in entry and isinstance(entry['timestamp'], datetime):
                entry['timestamp'] = entry['timestamp'].strftime('%Y-%m-%dT%H:%M')
        
        return render_template('audit_details.html', audit=audit)
    except Exception as e:
        
        return redirect(url_for('lead_dashboard'))

# Edit Audit - Show Form
@app.route('/edit-audit/<audit_id>', methods=['GET'])
@role_required('Lead Auditor')
def edit_audit_form(audit_id):
    try:
        audit = audits_col.find_one({"_id": ObjectId(audit_id)})
        if not audit:
            flash("Audit not found")
            return redirect(url_for('lead_dashboard'))
        
        # Convert ObjectId to string for template rendering
        audit['_id'] = str(audit['_id'])
        
        auditors = list(users_col.find({"role": "Auditor"}))
        auditees = list(users_col.find({"role": "Auditee"}))
        
        # Convert ObjectIds to strings for comparison in template
        for auditor in auditors:
            auditor['_id'] = str(auditor['_id'])
        for auditee in auditees:
            auditee['_id'] = str(auditee['_id'])
            
        # Format date for input field
        if audit.get('audit_date'):
            audit['audit_date_str'] = audit['audit_date'].strftime("%Y-%m-%dT%H:%M")
        
        return render_template('edit_audit.html', 
                             audit=audit, 
                             auditors=auditors, 
                             auditees=auditees)
    except Exception as e:
        
        return redirect(url_for('lead_dashboard'))

# Edit Audit - Process Form
@app.route('/edit-audit/<audit_id>', methods=['POST'])
@role_required('Lead Auditor')
def edit_audit(audit_id):
    try:
        audit_type = request.form['audit_type']
        audit_area = request.form['audit_area']
        audit_date = datetime.strptime(request.form['audit_date'], "%Y-%m-%dT%H:%M")
        audit_ref = request.form['audit_ref']
        status = request.form['status']
        auditor1 = request.form['auditor1']
        auditor2 = request.form.get('auditor2', '')
        auditee1 = request.form['auditee1']
        auditee2 = request.form.get('auditee2', '')
        cancel_reason = request.form.get('cancel_reason', '')  # <-- get cancellation reason

        # Optional: clear reason if status is not 'Cancelled'
        if status != 'Cancelled':
            cancel_reason = ''

        # Update audit details
        updates = {
            "audit_type": audit_type,
            "audit_area": audit_area,
            "audit_date": audit_date,
            "audit_ref": audit_ref,
            "status": status,
            "auditor1": auditor1,
            "auditor2": auditor2,
            "auditee1": auditee1,
            "auditee2": auditee2,
            "cancel_reason": cancel_reason  # <-- include here
        }

        audits_col.update_one(
            {"_id": ObjectId(audit_id)},
            {"$set": updates}
        )

        flash("Audit updated successfully")
        return redirect(url_for('edit_audit', audit_id=audit_id))
    except Exception as e:
        flash(f"Error updating audit: {str(e)}")
        return redirect(url_for('lead_dashboard'))
# Delete Audit
@app.route('/delete-audit/<audit_id>')
@role_required('Lead Auditor')
def delete_audit(audit_id):
    try:
        result = audits_col.delete_one({"_id": ObjectId(audit_id)})
        if result.deleted_count > 0:
            flash("Audit deleted successfully")
        else:
            flash("Audit not found")
    except Exception as e:
        flash(f"Error deleting audit: {str(e)}")
    return redirect(url_for('lead_dashboard'))


@app.route('/auditor-dashboard')
@role_required('Auditor', 'Lead Auditor')
def auditor_dashboard():
    user_id = session['user_id']
    
    # Filter audits where current user is assigned as auditor1 or auditor2
    query = {
        '$or': [
            {'auditor1': user_id},
            {'auditor2': user_id}
        ]
    }
    
    audits = list(audits_col.find(query).sort('audit_date', -1))
    
    for audit in audits:
        audit['_id'] = str(audit['_id'])

        # Auditor names
        if audit.get('auditor1'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor1'])})
            audit['auditor1_name'] = auditor['full_name'] if auditor else "Unknown"
            
        if audit.get('auditor2'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor2'])})
            audit['auditor2_name'] = auditor['full_name'] if auditor else "Unknown"
            
        # Auditee names
        if audit.get('auditee1'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee1'])})
            audit['auditee1_name'] = auditee['full_name'] if auditee else "Unknown"
            
        if audit.get('auditee2'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee2'])})
            audit['auditee2_name'] = auditee['full_name'] if auditee else "Unknown"
        
    return render_template('auditor_dashboard.html', audits=audits)




@app.route('/update_audit_details/<audit_id>', methods=['GET', 'POST'])
@role_required('Auditor', 'Auditee', 'Lead Auditor')
def update_audit_details(audit_id):
    audit = audits_col.find_one({'_id': ObjectId(audit_id)})
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for('auditor_dashboard'))

    audit['_id'] = str(audit['_id'])
    change_history = audit.get('change_history', [])
    user_role = session.get("role")
    current_user = session.get('username', 'Unknown')

    if request.method == 'POST':
        try:
            old_obc_details = audit.get('obc_details', [])

            # General fields
            audit_name = request.form.get('audit_name')
            audit_function = request.form.get('audit_function')
            audit_end_date = datetime.strptime(request.form['audit_end_date'], "%Y-%m-%dT%H:%M")

            # Core obc fields from form
            obc_list = request.form.getlist('obc[]')
            category_list = request.form.getlist('category[]')
            category_details_list = request.form.getlist('category_details[]')
            rca_list = request.form.getlist('rca[]')
            correction_date_list = request.form.getlist('correction_date[]')
            corrective_action_list = request.form.getlist('corrective_action[]')
            correction_list = request.form.getlist('correction[]')
            corrective_action_plan_list = request.form.getlist('corrective_action_plan[]')
            document_files = request.files.getlist('document[]')

            # Section 3 fields
            follow_up_date_list = request.form.getlist('follow_up_date[]')
            follow_up_by_list = request.form.getlist('follow_up_by[]')
            verification_details_list = request.form.getlist('verification_details[]')
            action_status_list = [
                request.form.get(f'action_status_{idx+1}')
                for idx in range(len(obc_list))
            ]
            remarks_list = request.form.getlist('remarks[]')

            # Section 4 fields
            obc_closed_date_list = request.form.getlist('obc_closed_date[]')
            obc_new_no_list = request.form.getlist('obc_new_no[]')
            closure_status_list = [
                request.form.get(f'closure_status_{idx+1}')
                for idx in range(len(obc_list))
            ]

            # Auditor decision
            auditor_decision_list = [
                request.form.get(f'auditor_decision_{idx+1}')
                for idx in range(len(obc_list))
            ]

            # Checkboxes
            documented_procedure_list = request.form.getlist('documented_procedure[]')
            iso_clause_list = request.form.getlist('iso_clause[]')
            naac_manual_list = request.form.getlist('naac_manual[]')
            nba_manual_list = request.form.getlist('nba_manual[]')
            abet_manual_list = request.form.getlist('abet_manual[]')
            aacsb_manual_list = request.form.getlist('aacsb_manual[]')

            obc_details_list = []

            for i in range(len(obc_list)):
                old_obc = old_obc_details[i] if i < len(old_obc_details) else {}

                # Handle file
                file = document_files[i] if i < len(document_files) else None
                document_id = old_obc.get('document_id')
                document_filename = old_obc.get('document_filename')
                if file and file.filename != '':
                    filename = secure_filename(file.filename)
                    document_id = fs.put(
                        file.read(),
                        filename=filename,
                        content_type=file.content_type
                    )
                    document_filename = filename

                # RCA/Correction logic
                if user_role == "Auditee":
                    # Only allow edit if not done before
                    if not old_obc.get("auditee_edit_done", False):
                        rca_val = rca_list[i] if i < len(rca_list) else old_obc.get('rca', '')
                        correction_val = correction_list[i] if i < len(correction_list) else old_obc.get('correction', '')
                        correction_date_val = correction_date_list[i] if i < len(correction_date_list) else old_obc.get('correction_date', '')
                        auditee_edit_done = True
                    else:
                        # Keep old values, disallow change
                        rca_val = old_obc.get('rca', '')
                        correction_val = old_obc.get('correction', '')
                        correction_date_val = old_obc.get('correction_date', '')
                        auditee_edit_done = True
                else:
                    # Auditor & Lead Auditor can always edit
                    rca_val = rca_list[i] if i < len(rca_list) else old_obc.get('rca', '')
                    correction_val = correction_list[i] if i < len(correction_list) else old_obc.get('correction', '')
                    correction_date_val = correction_date_list[i] if i < len(correction_date_list) else old_obc.get('correction_date', '')
                    auditee_edit_done = old_obc.get("auditee_edit_done", False)

                obc_details_list.append({
                    'obc': obc_list[i],
                    'category': category_list[i] if i < len(category_list) else old_obc.get('category', ''),
                    'category_details': category_details_list[i] if i < len(category_details_list) else old_obc.get('category_details', ''),
                    'rca': rca_val,
                    'correction_date': correction_date_val,
                    'corrective_action': corrective_action_list[i] if i < len(corrective_action_list) else old_obc.get('corrective_action', ''),
                    'corrective_action_plan': corrective_action_plan_list[i] if i < len(corrective_action_plan_list) else old_obc.get('corrective_action_plan', ''),
                    'correction': correction_val,
                    'document_id': document_id,
                    'document_filename': document_filename,
                    'documented_procedure': documented_procedure_list[i] if i < len(documented_procedure_list) else old_obc.get('documented_procedure', False),
                    'iso_clause': iso_clause_list[i] if i < len(iso_clause_list) else old_obc.get('iso_clause', False),
                    'naac_manual': naac_manual_list[i] if i < len(naac_manual_list) else old_obc.get('naac_manual', False),
                    'nba_manual': nba_manual_list[i] if i < len(nba_manual_list) else old_obc.get('nba_manual', False),
                    'abet_manual': abet_manual_list[i] if i < len(abet_manual_list) else old_obc.get('abet_manual', False),
                    'aacsb_manual': aacsb_manual_list[i] if i < len(aacsb_manual_list) else old_obc.get('aacsb_manual', False),
                    'follow_up_date': follow_up_date_list[i] if i < len(follow_up_date_list) else old_obc.get('follow_up_date', ''),
                    'follow_up_by': follow_up_by_list[i] if i < len(follow_up_by_list) else old_obc.get('follow_up_by', ''),
                    'verification_details': verification_details_list[i] if i < len(verification_details_list) else old_obc.get('verification_details', ''),
                    'action_status': action_status_list[i] if i < len(action_status_list) and action_status_list[i] else old_obc.get('action_status', ''),
                    'remarks': remarks_list[i] if i < len(remarks_list) else old_obc.get('remarks', ''),
                    'closure_status': closure_status_list[i] if i < len(closure_status_list) and closure_status_list[i] else old_obc.get('closure_status', ''),
                    'obc_closed_date': obc_closed_date_list[i] if i < len(obc_closed_date_list) else old_obc.get('obc_closed_date', ''),
                    'obc_new_no': obc_new_no_list[i] if i < len(obc_new_no_list) else old_obc.get('obc_new_no', ''),
                    'auditor_decision': auditor_decision_list[i] if i < len(auditor_decision_list) and auditor_decision_list[i] else old_obc.get('auditor_decision', ''),
                    'auditee_edit_done': auditee_edit_done,
                    'updated_at': datetime.now()
                })

            # Track changes
            changes_detected = []
            ist = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist).strftime('%Y-%m-%dT%H:%M')

            for i, new_obc in enumerate(obc_details_list):
                if i < len(old_obc_details):
                    old_obc = old_obc_details[i]
                    field_changes = []
                    for field in ['obc', 'category', 'category_details', 'rca', 'correction_date',
                                  'corrective_action', 'corrective_action_plan', 'correction',
                                  'follow_up_date', 'follow_up_by', 'verification_details',
                                  'action_status', 'remarks', 'closure_status', 'obc_closed_date', 'obc_new_no',
                                  'documented_procedure', 'iso_clause', 'naac_manual', 'nba_manual', 'abet_manual',
                                  'aacsb_manual', 'auditor_decision']:
                        old_value = old_obc.get(field, '')
                        new_value = new_obc.get(field, '')
                        if str(old_value) != str(new_value):
                            field_changes.append({
                                'field': field,
                                'old_value': old_value,
                                'new_value': new_value
                            })
                    if field_changes:
                        changes_detected.append({
                            'obc_index': i,
                            'obc_number': new_obc.get('obc', f'OBC {i+1}'),
                            'changes': field_changes,
                            'changed_by': current_user,
                            'changed_at': current_time
                        })
                else:
                    changes_detected.append({
                        'obc_index': i,
                        'obc_number': new_obc.get('obc', f'OBC {i+1}'),
                        'changes': [{'field': 'OBC Added', 'old_value': 'None', 'new_value': 'New OBC created'}],
                        'changed_by': current_user,
                        'changed_at': current_time
                    })

            if len(old_obc_details) > len(obc_details_list):
                for i in range(len(obc_details_list), len(old_obc_details)):
                    changes_detected.append({
                        'obc_index': i,
                        'obc_number': old_obc_details[i].get('obc', f'OBC {i+1}'),
                        'changes': [{'field': 'OBC Removed', 'old_value': 'OBC existed', 'new_value': 'OBC removed'}],
                        'changed_by': current_user,
                        'changed_at': current_time
                    })

            if changes_detected:
                change_history.extend(changes_detected)
                change_history = change_history[-50:]

            # today_str = datetime.now().strftime("%Y-%m-%dT%H:%M")
            all_closed_today = (
                all(
                    # obc.get('closure_status') == 'closed' and obc.get('obc_closed_date') == today_str
                    obc.get('closure_status') == 'closed' and audit.get('audit_end_date') 
                    for obc in obc_details_list
                )
                and obc_details_list
            )

            update_data = {
                'audit_name': audit_name,
                'audit_function': audit_function,
                'audit_end_date':audit_end_date,
                'obc_details': obc_details_list,
                'change_history': change_history,
                'status': 'Completed' if all_closed_today else 'In Progress'
            }

            audits_col.update_one({'_id': ObjectId(audit_id)}, {'$set': update_data})
            return redirect(url_for('update_audit_details', audit_id=audit_id))

        except Exception as e:
            flash(f"An error occurred while saving the report: {str(e)}", "danger")
            return redirect(url_for('update_audit_details', audit_id=audit_id))

    return render_template('update_audit_details.html', audit=audit, change_history=change_history)


@app.route('/download/<document_id>')
@role_required('Auditor', 'Lead Auditor', 'Auditee')
def download_file(document_id):
    try:
        file_data = fs.get(ObjectId(document_id))
        return send_file(
            BytesIO(file_data.read()),
            as_attachment=True,
            download_name=file_data.filename,
            mimetype=file_data.content_type
        )
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "danger")
        if session.get('role') == 'Auditee':
            return redirect(url_for('auditee_dashboard'))
        elif session.get('role') == 'Lead Auditor':
            return redirect(url_for('lead_dashboard'))
        return redirect(url_for('auditor_dashboard'))
    

@app.route('/view/<document_id>')
@role_required('Auditor', 'Lead Auditor', 'Auditee')
def view_file(document_id):
    try:
        file_data = fs.get(ObjectId(document_id))
        return send_file(
            BytesIO(file_data.read()),
            as_attachment=False,  # Display inline
            download_name=file_data.filename,
            mimetype=file_data.content_type
        )
    except Exception as e:
        flash(f"Error viewing file: {str(e)}", "danger")
        if session.get('role') == 'Auditee':
            return redirect(url_for('auditee_dashboard'))
        elif session.get('role') == 'Lead Auditor':
            return redirect(url_for('lead_dashboard'))
        return redirect(url_for('auditor_dashboard'))
    

@app.route('/auditee-dashboard')
@role_required('Auditee', 'Lead Auditor')
def auditee_dashboard():
    user_id = session['user_id']

    # Query audits where the current user is assigned as auditee1 or auditee2
    query = {
        '$or': [
            {'auditee1': user_id},
            {'auditee2': user_id}
        ]
    }

    audits = list(audits_col.find(query).sort('audit_date', -1))
    
    for audit in audits:
        audit['_id'] = str(audit['_id'])

        # Auditor names
        if audit.get('auditor1'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor1'])})
            audit['auditor1_name'] = auditor['full_name'] if auditor else "Unknown"
            
        if audit.get('auditor2'):
            auditor = users_col.find_one({"_id": ObjectId(audit['auditor2'])})
            audit['auditor2_name'] = auditor['full_name'] if auditor else "Unknown"
            
        # Auditee names
        if audit.get('auditee1'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee1'])})
            audit['auditee1_name'] = auditee['full_name'] if auditee else "Unknown"
            
        if audit.get('auditee2'):
            auditee = users_col.find_one({"_id": ObjectId(audit['auditee2'])})
            audit['auditee2_name'] = auditee['full_name'] if auditee else "Unknown"

    return render_template('auditee_dashboard.html', audits=audits)


@app.route('/get_edit_history/<audit_id>')
@role_required('Auditor', 'Auditee', 'Lead Auditor')
def get_edit_history(audit_id):
    try:
        audit = audits_col.find_one({'_id': ObjectId(audit_id)})
        if audit and 'edit_history' in audit:
            # Return the edit history in reverse chronological order
            history = audit['edit_history']
            history.sort(key=lambda x: x['changed_at'], reverse=True)
            return jsonify(history)
        return jsonify([])
    except Exception as e:
        print(f"Error fetching edit history: {e}")
        return jsonify([])






@app.route('/audit_checklist/<audit_id>', methods=['GET', 'POST'])
@role_required('Auditor', 'Auditee', 'Lead Auditor')
def audit_checklist(audit_id):
    # Get the audit document
    audit = audits_col.find_one({'_id': ObjectId(audit_id)})
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for('auditor_dashboard'))
    
    # Convert ObjectId to string for template rendering
    audit['_id'] = str(audit['_id'])
    
    # Get existing checklist data if available
    existing_checklist = audit.get('checklist_data', [])
    
    if request.method == 'POST':
        try:
            # Extract form data
            checklist_data = []
            
            # Get all the form fields
            item_ids = request.form.getlist('item_id[]')
            conformances = request.form.getlist('conformance[]')
         
            # Build the checklist data array
            for i in range(len(item_ids)):
                checklist_data.append({
                    'id': item_ids[i],
                    'conformance': conformances[i] if i < len(conformances) else '',
                })
            
            # Update the audit document
            update_data = {
                'checklist_data': checklist_data,
                'updated_at': datetime.now()
            }
            
            # Update the database
            audits_col.update_one({'_id': ObjectId(audit_id)}, {'$set': update_data})
            
            flash("Audit checklist saved successfully!", "success")
            # if session.get('role') == 'Auditee':
            #     return redirect(url_for('auditee_dashboard'))
            # elif session.get('role') == 'Lead Auditor':
            #     return redirect(url_for('lead_dashboard'))
            return redirect(url_for('audit_checklist', audit_id=audit_id))

        except Exception as e:
            flash(f"An error occurred while saving the report: {str(e)}", "danger")
            if session.get('role') == 'Auditee':
                return redirect(url_for('auditee_dashboard'))
            elif session.get('role') == 'Lead Auditor':
                return redirect(url_for('lead_dashboard'))
            return redirect(url_for('auditor_dashboard'))
   
    # For GET request, render the template with existing data
    return render_template('audit_checklist.html', 
                         audit=audit, 
                         checklist_data=existing_checklist)


@app.route('/process_manual/<audit_id>', methods=['GET', 'POST'])
@role_required('Auditor', 'Auditee', 'Lead Auditor')
def process_manual(audit_id):
    audit = audits_col.find_one({'_id': ObjectId(audit_id)})
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for('auditor_dashboard'))

    audit['_id'] = str(audit['_id'])
    existing_versions = audit.get('process_manual_versions', [])
    latest_version = existing_versions[-1]['details'] if existing_versions else {}

    if request.method == 'POST':
        try:
            new_details = {}
            fields = [
                'title', 'owner', 'purpose', 'scope', 'inputs-external',
                'inputs-internal', 'boundaries', 'workflow', 'output',
                'exceptions', 'controls', 'skills', 'references'
            ]

            for field in fields:
                key = field.replace('-', '_')
                new_details[key] = request.form.get(field, '').strip() or None

            new_version_number = (existing_versions[-1]['version_number'] + 1) if existing_versions else 1

            new_version = {
                'version_number': new_version_number,
                'author': session.get('username', 'Unknown'),
                'timestamp': datetime.now(),
                'details': new_details
            }

            # Append new version to list
            update_data = {
                '$push': {'process_manual_versions': new_version},
                '$set': {
                    'current_version_number': new_version_number
                    # 'status': 'Completed' if all([
                    #     new_details.get('title'),
                    #     new_details.get('owner'),
                    #     new_details.get('purpose'),
                    #     new_details.get('scope'),
                    #     new_details.get('workflow'),
                    #     new_details.get('output')
                    # ]) else 'In Progress'
                }
            }

            audits_col.update_one({'_id': ObjectId(audit_id)}, update_data)

            flash(f"Process manual version {new_version_number} saved successfully!", "success")
            # if session.get('role') == 'Auditee':
            #     return redirect(url_for('auditee_dashboard'))
            # elif session.get('role') == 'Lead Auditor':
            #     return redirect(url_for('lead_dashboard'))            
            return redirect(url_for('process_manual', audit_id=audit_id))

        except Exception as e:
            flash(f"An error occurred while saving the manual: {str(e)}", "danger")
            if session.get('role') == 'Auditee':
                return redirect(url_for('auditee_dashboard'))
            elif session.get('role') == 'Lead Auditor':
                return redirect(url_for('lead_dashboard'))
            return redirect(url_for('auditor_dashboard'))

    # Pass the latest version to the form
    process_manual_details = latest_version

    return render_template('process_manual.html', audit=audit, process_manual_details=process_manual_details)


@app.route('/process_manual_version/<audit_id>/<int:version_number>')
@role_required('Auditor', 'Auditee', 'Lead Auditor')
def view_process_manual_version(audit_id, version_number):
    audit = audits_col.find_one({'_id': ObjectId(audit_id)})
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for('auditor_dashboard'))

    version = next((v for v in audit.get('process_manual_versions', [])
                    if v['version_number'] == version_number), None)

    if not version:
        flash(f"Version {version_number} not found.", "danger")
        return redirect(url_for('process_manual', audit_id=audit_id))

    return render_template('process_manual_version.html', audit=audit, version=version)

# users_col.update_one(
#     {"username": "lead_auditor"},
#     {"$set": {"api_key": ""}}
# )

# users_col.insert_one({
#     "username": "lead_auditor",
#     "api_key": ""
# })


def require_login_or_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Option 1: Session login
        if "user_id" in session:
            user = users_col.find_one({"_id": ObjectId(session["user_id"])})
            if user:
                request.user = user
                return f(*args, **kwargs)

        # Option 2: API key
        api_key = request.headers.get("X-API-KEY")
        if api_key:
            user = users_col.find_one({"api_key": api_key})
            if user:
                request.user = user
                return f(*args, **kwargs)

        return jsonify({"error": "Unauthorized"}), 401
    return decorated


def convert_objectid(doc):
    if isinstance(doc, list):
        return [convert_objectid(d) for d in doc]
    if isinstance(doc, dict):
        return {k: convert_objectid(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc

@app.route("/api/audits", methods=["GET"])
@require_login_or_api_key
def get_audits():
    audits = list(audits_col.find({}))
    audits = convert_objectid(audits)
    return jsonify(audits)

@app.route("/api/audits/<audit_id>", methods=["GET"])
@require_login_or_api_key
def get_audit(audit_id):
    audit = audits_col.find_one({"_id": ObjectId(audit_id)})
    if not audit:
        return jsonify({"error": "Audit not found"}), 404
    audit = convert_objectid(audit)
    return jsonify(audit)

@app.route("/api/obcs", methods=["GET"])
@require_login_or_api_key
def get_all_obcs():
    audits = audits_col.find({})
    all_obcs = []

    for audit in audits:
        audit_id = str(audit["_id"])
        audit_ref = audit.get("audit_ref")
        audit_type = audit.get("audit_type")
        audit_area = audit.get("audit_area")
        obc_list = audit.get("obc_details", [])

        for obc in obc_list:
            obc_data = convert_objectid(obc)  # convert any nested ObjectIds
            # add audit-level info for context
            obc_data.update({
                "audit_id": audit_id,
                "audit_ref": audit_ref,
                "audit_type": audit_type,
                "audit_area": audit_area
            })
            all_obcs.append(obc_data)

    return jsonify(all_obcs)




@app.route('/upload_repository_link/<audit_id>', methods=['POST'])
@role_required('Lead Auditor')
def upload_repository_link(audit_id):
    repository_url = request.form.get('repository_url')
    filename = request.form.get('filename')

    if not repository_url or not filename:
        flash('Both URL and filename are required.', 'danger')
        return redirect(url_for('process_manual', audit_id=audit_id))

    # Create link record
    link_record = {
        'filename': filename,
        'url': repository_url,
        'uploaded_by': session.get('username'),
        'timestamp': datetime.now()
    }

    # Save under a new field (repository_links)
    audits_col.update_one(
        {'_id': ObjectId(audit_id)},
        {'$push': {'repository_links': link_record}}
    )

    flash('Repository link added successfully!', 'success')
    return redirect(url_for('process_manual', audit_id=audit_id))


@app.route('/delete_repository_link/<audit_id>/<filename>', methods=['POST'])
@role_required('Lead Auditor')
def delete_repository_link(audit_id, filename):
    try:
        audits_col.update_one(
            {'_id': ObjectId(audit_id)},
            {'$pull': {'repository_links': {'filename': filename}}}
        )
        flash('Link deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting link: {str(e)}', 'danger')

    return redirect(url_for('process_manual', audit_id=audit_id))


if __name__ == '__main__':
    app.run(debug=True)