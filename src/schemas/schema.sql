-- Posts table - メイン投稿テーブル
CREATE TABLE posts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  user_name TEXT,
  x_id TEXT,
  password_hash TEXT NOT NULL,
  trip_hash TEXT,
  gender TEXT NOT NULL CHECK(gender IN ('male', 'female')),
  allow_promotion BOOLEAN NOT NULL DEFAULT FALSE,
  audio_file_key TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_type TEXT NOT NULL,
  play_count INTEGER DEFAULT 0,
  client_ip TEXT,
  user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Posts table indexes
CREATE INDEX idx_posts_created_at ON posts(created_at DESC);
CREATE INDEX idx_posts_gender ON posts(gender);
CREATE INDEX idx_posts_allow_promotion ON posts(allow_promotion);

-- Likes table - いいね機能
CREATE TABLE likes (
  post_id TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

-- Tags table - タグ機能
CREATE TABLE tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Post-Tags relation table - 投稿とタグの関連
CREATE TABLE post_tags (
  post_id TEXT NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (post_id, tag_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Play records table - 再生履歴
CREATE TABLE play_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

-- Play records indexes
CREATE INDEX idx_play_records_post_id ON play_records(post_id);
CREATE INDEX idx_play_records_ip_time ON play_records(client_ip, created_at);
