CREATE TABLE IF NOT EXISTS user_email_verifications(
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token UUID NOT NULL
);
---- create above / drop below ----
DROP TABLE IF EXISTS user_email_verifications;
