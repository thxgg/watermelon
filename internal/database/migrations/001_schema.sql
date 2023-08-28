CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users(
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  verified BOOLEAN DEFAULT FALSE
);

---- create above / drop below ----

DROP TABLE IF EXISTS users;
DROP EXTENSION IF EXISTS "uuid-ossp";
