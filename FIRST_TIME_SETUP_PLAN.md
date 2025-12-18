# First-Time Setup Research & Implementation Plan

## How Other Software Handles First Deployment

### Research: Industry Best Practices

**1. GitLab / GitHub Enterprise**
- First user to access the system becomes admin
- Setup wizard on first launch
- No public registration until configured
- Admin must manually invite users or enable LDAP

**2. Jira / Confluence**
- Setup wizard with admin account creation
- Email verification required
- No self-registration by default
- Admin enables registration per project/space

**3. Jenkins / CI/CD Tools**
- First run creates unlock key
- Admin must enter key and create first user
- That first user is always admin
- Can later enable signup or use LDAP

**4. WordPress / CMS Systems**
- Installation wizard
- Creates admin account with chosen credentials
- No registration until admin enables it
- Clear distinction between setup mode and normal operation

**5. Docker Registry / Harbor**
- Default admin account (admin/Harbor12345)
- First login forces password change
- Admin then configures auth (local, LDAP, OIDC)
- No self-registration without explicit enabling

### Best Approach for SentriKat

Based on research, here's the recommended flow:

```
┌─────────────────────────────────────────┐
│  First Deployment Detection             │
│  (No users in database)                 │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Setup Wizard                           │
│  ┌───────────────────────────────────┐ │
│  │ Step 1: Create Super Admin        │ │
│  │  - Username                       │ │
│  │  - Email                          │ │
│  │  - Password (strong requirement)  │ │
│  │  - Confirm Password               │ │
│  └───────────────────────────────────┘ │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │ Step 2: Organization Setup        │ │
│  │  - Organization Name              │ │
│  │  - Default Email for Alerts       │ │
│  └───────────────────────────────────┘ │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │ Step 3: Optional LDAP (Skip)      │ │
│  │  - Configure now or later         │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Normal Operation                       │
│  - Login page shows                     │
│  - No registration link                 │
│  - Admin must create users manually     │
│  - Or configure LDAP for auth           │
└─────────────────────────────────────────┘
```

### Key Features

1. **First User Detection**
   - Check if any users exist in database
   - If none → Force setup wizard
   - If exists → Normal login

2. **Setup Wizard**
   - Clean, guided interface
   - Creates first super_admin user
   - Creates default organization
   - Optional LDAP configuration

3. **No Public Registration**
   - No "Sign Up" link on login page
   - Users created by:
     - Super admin manually
     - LDAP auto-provisioning
     - API (for integrations)

4. **Security Requirements**
   - Strong password for first admin (min 12 chars, complexity)
   - Email verification optional but recommended
   - Setup wizard accessible only when no users exist
   - After setup, wizard route is disabled

5. **Admin User Management**
   - Only super_admin can create users
   - Org admins can create users in their org
   - Managers cannot create users
   - LDAP auto-provisions based on group mapping

## Implementation Checklist

### Backend Changes

- [ ] Add `is_setup_complete()` check in app/__init__.py
- [ ] Create `/setup` route (GET) - Display wizard
- [ ] Create `/api/setup/init` (POST) - Create first admin
- [ ] Modify login route to check setup status
- [ ] Remove any registration endpoints
- [ ] Add setup completion flag in database (SystemSettings)

### Frontend Changes

- [ ] Create `setup.html` template - Wizard UI
- [ ] Remove "Register" link from login.html (if exists)
- [ ] Add setup wizard JavaScript
- [ ] Style setup wizard to match application

### Security

- [ ] Password strength validation (12+ chars, uppercase, lowercase, number, special)
- [ ] Rate limiting on setup endpoint
- [ ] CSRF protection on setup form
- [ ] Setup wizard only accessible when no users exist

### User Experience

- [ ] Clear progress indicator (Step 1 of 3)
- [ ] Helpful tooltips and guidance
- [ ] Validation feedback inline
- [ ] Success message with next steps

## Session Management Fix

**Current Issue:** Users stay logged in after server restart

**Root Cause:** Session data persists in files/cookies

**Solution:**
```python
# In config.py
PERMANENT_SESSION_LIFETIME = timedelta(hours=8)  # Current
SESSION_COOKIE_SAMESITE = 'Lax'  # Current
SESSION_COOKIE_HTTPONLY = True  # Current

# Add:
SESSION_REFRESH_EACH_REQUEST = True  # Refresh session on activity
SESSION_TYPE = 'filesystem'  # Or 'redis' for production
```

**Best Practice:**
- 8 hours for active session
- 30 minutes idle timeout
- Show "Session expires in X minutes" warning
- Auto-logout on server restart (use Redis/Memcached)

## Implementation Plan

1. **Phase 1: Setup Wizard (High Priority)**
   - Create setup wizard backend
   - Create setup wizard frontend
   - Disable after first user created
   - Test flow

2. **Phase 2: Session Management**
   - Implement idle timeout
   - Add session expiry warning
   - Test session behavior

3. **Phase 3: Remove Registration**
   - Remove any registration routes
   - Remove registration UI elements
   - Add user invitation system (optional)

Would you like me to implement this step by step?
