CREATE TABLE pastes (
  id               INTEGER PRIMARY KEY,          -- random in [0, 2^33); encodes the three words
  kind             TEXT NOT NULL CHECK (kind IN ('text','url')),
  privacy          TEXT NOT NULL CHECK (privacy IN ('public','unlisted','readonly','private','secret')),
  content          BLOB NOT NULL,                -- UTF-8 text, or a crypto container (§5)
  syntax           TEXT,                         -- syntect token, NULL = plain
  editable         INTEGER NOT NULL DEFAULT 0,
  wrapped_key      BLOB,                         -- private: DEK wrapped by the password KEK (§5)
  verifier_hash    BLOB,                         -- secret: salt(16) ‖ SHA-256 of the browser-derived verifier (§5)
  burn_after_reads INTEGER NOT NULL DEFAULT 0,   -- 0 = off
  read_count       INTEGER NOT NULL DEFAULT 0,
  last_read_at     INTEGER,
  burned_at        INTEGER,                      -- set on the burning read; row purged 10 min later
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER                       -- NULL = never
);
CREATE INDEX pastes_public_created ON pastes (created_at) WHERE privacy = 'public';
CREATE INDEX pastes_expires ON pastes (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE paste_files (
  paste_id   INTEGER NOT NULL REFERENCES pastes(id) ON DELETE CASCADE,
  position   INTEGER NOT NULL,
  name       TEXT NOT NULL,                      -- sanitised display/download name (secret: file-N placeholder)
  size       INTEGER NOT NULL,                   -- plaintext bytes (secret: ciphertext bytes)
  mime       TEXT NOT NULL,
  PRIMARY KEY (paste_id, position)
);
