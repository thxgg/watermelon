CREATE TABLE IF NOT EXISTS user_email_verifications(
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token UUID NOT NULL
);
-- Create a trigger function
CREATE OR REPLACE FUNCTION set_is_verified_to_false()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.email IS DISTINCT FROM NEW.email THEN
    NEW.is_verified = FALSE;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- Create a trigger that fires before an update on the users table
CREATE TRIGGER trigger_set_is_verified_to_false
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_is_verified_to_false();
---- create above / drop below ----
DROP
  TRIGGER trigger_set_is_verified_to_false ON users;
DROP
  FUNCTION set_is_verified_to_false();
DROP
  TABLE IF EXISTS user_email_verifications;
