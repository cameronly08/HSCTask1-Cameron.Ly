-- database: database.db
-- CREATE TABLE id7-tusers(id INTEGER PRIMARY KEY autoincrement,username TEXT NOT NULL UNIQUE, password TEXT NOT NULL);

-- INSERT INTO id7-tusers(username,password) VALUES ("","");

-- SELECT * FROM extension;

-- CREATE TABLE users (
  -- id INTEGER PRIMARY KEY AUTOINCREMENT,
  --  email TEXT NOT NULL,
--   username TEXT NOT NULL,
  --  password TEXT NOT NULL );

-- ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

--CREATE TABLE IF NOT EXISTS users (
    --id INTEGER PRIMARY KEY AUTOINCREMENT,
    --email TEXT NOT NULL,
  -- username TEXT NOT NULL,
  -- password TEXT NOT NULL,
  --  role TEXT NOT NULL
-- );

-- ALTER TABLE users ADD COLUMN totp_secret TEXT;   


--CREATE TABLE IF NOT EXISTS logs (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--    date TEXT NOT NULL,
--    developer_name TEXT NOT NULL,
--    project TEXT NOT NULL,
--    content TEXT NOT NULL,
--    code_snippet TEXT);


--ALTER TABLE users ADD COLUMN verification_token TEXT;
--ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;

--ALTER TABLE logs ADD COLUMN is_approved BOOLEAN DEFAULT FALSE;
--ALTER TABLE logs ADD COLUMN is_archived BOOLEAN DEFAULT FALSE;
--ALTER TABLE logs ADD COLUMN last_edited TIMESTAMP;