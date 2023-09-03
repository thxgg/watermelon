CREATE TABLE IF NOT EXISTS forgotten_passwords(
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token UUID NOT NULL,
  expires_at TIMESTAMP NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);
-- Create a trigger function to delete expired rows
CREATE
OR REPLACE FUNCTION delete_expired_forgotten_password_tokens() RETURNS TRIGGER AS $$ BEGIN
DELETE FROM
  forgotten_passwords
WHERE
  expires_at < NOW();
RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- Create a trigger that fires before INSERT or UPDATE
CREATE TRIGGER delete_expired_forgotten_password_tokens_trigger BEFORE INSERT
OR
UPDATE
  ON forgotten_passwords FOR EACH ROW EXECUTE FUNCTION delete_expired_forgotten_password_tokens();
---- create above / drop below ----
DROP
  TRIGGER delete_expired_forgotten_password_tokens_trigger ON forgotten_passwords;
DROP
  FUNCTION delete_expired_forgotten_password_tokens();
DROP
  TABLE IF EXISTS forgotten_passwords;
