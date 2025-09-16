/* eslint-disable @typescript-eslint/no-explicit-any */
export interface D1Result {
  success: boolean;
  error?: string;
  meta: {
    changed_db: boolean;
    changes: number;
    duration: number;
    last_row_id: number;
    rows_read: number;
    rows_written: number;
    size_after: number;
  };
}

export interface Post {
  id: string;
  title: string;
  x_id: string | null;
  password_hash: string;
  gender: 'male' | 'female';
  allow_promotion: boolean;
  audio_file_key: string;
  file_size: number;
  file_type: string;
  client_ip: string | null;
  user_agent: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreatePostData {
  id: string;
  title: string;
  x_id: string | null;
  password_hash: string;
  gender: 'male' | 'female';
  allow_promotion: boolean;
  audio_file_key: string;
  file_size: number;
  file_type: string;
  client_ip: string | null;
  user_agent: string | null;
}

export interface Comment {
  id: string;
  post_id: string;
  parent_comment_id: string | null;
  user_name: string | null;
  x_id: string | null;
  trip_hash: string | null;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface CreateCommentData {
  id: string;
  post_id: string;
  parent_comment_id: string | null;
  user_name: string | null;
  x_id: string | null;
  trip_hash: string | null;
  content: string;
}

/**
 * 投稿を作成
 */
export async function createPost(db: any, data: CreatePostData): Promise<D1Result> {
  const query = `
    INSERT INTO posts (
      id, title, x_id, password_hash, gender, allow_promotion,
      audio_file_key, file_size, file_type, client_ip, user_agent
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  return await db.prepare(query).bind(
    data.id,
    data.title,
    data.x_id,
    data.password_hash,
    data.gender,
    data.allow_promotion,
    data.audio_file_key,
    data.file_size,
    data.file_type,
    data.client_ip,
    data.user_agent
  ).run();
}

/**
 * 投稿を取得
 */
export async function getPost(db: any, id: string): Promise<Post | null> {
  const result = await db.prepare('SELECT * FROM posts WHERE id = ?').bind(id).first();
  return result as Post | null;
}

/**
 * 投稿を削除
 */
export async function deletePost(db: any, id: string): Promise<D1Result> {
  return await db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
}

/**
 * コメントを作成
 */
export async function createComment(db: any, data: CreateCommentData): Promise<D1Result> {
  const query = `
    INSERT INTO comments (
      id, post_id, parent_comment_id, user_name, x_id, trip_hash, content
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  return await db.prepare(query).bind(
    data.id,
    data.post_id,
    data.parent_comment_id,
    data.user_name,
    data.x_id,
    data.trip_hash,
    data.content
  ).run();
}

/**
 * 投稿のコメント一覧を取得（親コメントのみ）
 */
export async function getCommentsByPost(db: any, postId: string): Promise<Comment[]> {
  const result = await db.prepare(`
    SELECT * FROM comments 
    WHERE post_id = ? AND parent_comment_id IS NULL 
    ORDER BY created_at ASC
  `).bind(postId).all();
  
  return result.results as Comment[];
}

/**
 * 親コメントの子コメント一覧を取得
 */
export async function getRepliesByParent(db: any, parentCommentId: string): Promise<Comment[]> {
  const result = await db.prepare(`
    SELECT * FROM comments 
    WHERE parent_comment_id = ? 
    ORDER BY created_at ASC
  `).bind(parentCommentId).all();
  
  return result.results as Comment[];
}

/**
 * コメントを取得
 */
export async function getComment(db: any, id: string): Promise<Comment | null> {
  const result = await db.prepare('SELECT * FROM comments WHERE id = ?').bind(id).first();
  return result as Comment | null;
}
