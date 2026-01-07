-- Migration: Add password expiration and 2FA columns to users table
-- This enables password expiration policies and TOTP-based two-factor authentication

-- Password expiration tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;

-- Two-Factor Authentication (TOTP)
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(32) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;

-- Create index for efficient 2FA queries
CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON users(totp_enabled);

-- Update existing users to have password_changed_at set to their created_at or now
UPDATE users SET password_changed_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE password_changed_at IS NULL;
