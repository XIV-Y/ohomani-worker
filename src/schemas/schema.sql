-- Posts table - メイン投稿テーブル
CREATE TABLE IF NOT EXISTS posts (
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
CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_gender ON posts(gender);
CREATE INDEX IF NOT EXISTS idx_posts_allow_promotion ON posts(allow_promotion);

-- Likes table - いいね機能
CREATE TABLE IF NOT EXISTS likes (
  post_id TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

-- Tags table - タグ機能
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Post-Tags relation table - 投稿とタグの関連
CREATE TABLE IF NOT EXISTS post_tags (
  post_id TEXT NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (post_id, tag_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- 初期タグデータ
INSERT OR IGNORE INTO tags (name) VALUES 
('オホ声'),
('ゴリオホ');

-- Comments table - コメント機能
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  parent_comment_id TEXT NULL,
  user_name TEXT,
  x_id TEXT,
  trip_hash TEXT,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
);

-- Comments table indexes
CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_comments_parent_id ON comments(parent_comment_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at DESC);
