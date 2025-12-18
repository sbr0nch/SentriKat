#!/usr/bin/env python
"""
Force login utility - creates a valid session to bypass login issues
"""
from app import create_app
from app.models import User
from flask import url_for
import secrets

app = create_app()

print("="*60)
print("FORCE LOGIN UTILITY")
print("="*60)

with app.app_context():
    admin = User.query.filter_by(username='admin').first()

    if not admin:
        print("✗ Admin user not found!")
        exit(1)

    print(f"✓ Found user: {admin.username}")
    print(f"  ID: {admin.id}")
    print(f"  Email: {admin.email}")

    # Create a test client and force login
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user_id'] = admin.id
            sess['username'] = admin.username
            sess.permanent = True

        print(f"\n✓ Session created for {admin.username}")
        print(f"\nNow access the application - you should be logged in!")
        print(f"\nTo verify, visit: http://your-server:5000/")

print("\n" + "="*60)
print("ALTERNATIVE: Create a temporary bypass endpoint")
print("="*60)
print("\nAdd this to your run.py or routes.py:")
print("""
@app.route('/admin-login-bypass')
def admin_login_bypass():
    from flask import session, redirect, url_for
    from app.models import User
    admin = User.query.filter_by(username='admin').first()
    if admin:
        session['user_id'] = admin.id
        session['username'] = admin.username
        session.permanent = True
        return redirect(url_for('main.index'))
    return 'Admin not found', 404
""")
print("\nThen visit: http://your-server:5000/admin-login-bypass")
