DROP TYPE IF EXISTS user_role;
CREATE TYPE user_role AS ENUM ('USER', 'ADMIN');

CREATE TABLE IF NOT EXISTS users(
  id UUID PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'USER',
  username TEXT NOT NULL UNIQUE,
  verified BOOLEAN DEFAULT FALSE
);

---- create above / drop below ----

DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS user_role;
