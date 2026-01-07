-- Migration: Add failed login tracking columns to users table
-- This enables account lockout after too many failed login attempts

-- Add failed_login_attempts column (default 0)
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0;

-- Add locked_until column (nullable timestamp for when lockout expires)
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL;

-- Create index for efficient lockout queries
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
