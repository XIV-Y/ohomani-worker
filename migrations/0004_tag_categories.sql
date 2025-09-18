-- Migration number: 0004 	 2025-01-xx 
-- 既存タグと関連データを削除
DELETE FROM post_tags;
DELETE FROM tags;

-- タグカテゴリテーブル作成
CREATE TABLE IF NOT EXISTS tag_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  display_order INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- tagsテーブルにcategory_idカラム追加
ALTER TABLE tags ADD COLUMN category_id INTEGER;

-- 外部キー制約追加（SQLiteの制限により新テーブル作成＆データ移行）
CREATE TABLE IF NOT EXISTS tags_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  category_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES tag_categories(id) ON DELETE SET NULL
);

-- データ移行（既存タグは削除済みなので空のまま）
INSERT INTO tags_new (id, name, created_at) 
SELECT id, name, created_at FROM tags;

-- テーブル置換
DROP TABLE tags;
ALTER TABLE tags_new RENAME TO tags;

-- インデックス再作成
CREATE INDEX IF NOT EXISTS idx_tags_category_id ON tags(category_id);

-- 初期カテゴリデータ
INSERT OR IGNORE INTO tag_categories (name, display_order) VALUES 
('人気', 1),
('プレイ', 2),
('声タイプ', 3),
('ワード', 4);
