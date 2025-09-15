/* eslint-disable @typescript-eslint/no-explicit-any */
import { deletePost, getPost } from './database';
import { verifyPassword } from './utils/password';

export interface Env {
  OHO_AUDIO_BUCKET: any; 
  DB: any;
  ALLOWED_ORIGINS?: string;
  MAX_FILE_SIZE?: string;
  ALLOWED_FILE_TYPES?: string;
  ENVIRONMENT?: string;
  SECRET_SALT?: string;
}

class EnvironmentConfig {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  get allowedOrigins(): string {
    return this.env.ALLOWED_ORIGINS || "*";
  }

  get secretSalt(): string {
    return this.env.SECRET_SALT || "OhoMani_Secret_Salt_2025_v1";
  }

  get maxFileSize(): number {
    return parseInt(this.env.MAX_FILE_SIZE || "52428800");
  }

  get allowedFileTypes(): string[] {
    return (this.env.ALLOWED_FILE_TYPES || "audio/mp3,audio/mpeg,audio/wav,audio/m4a,audio/mp4").split(',');
  }

  get environment(): string {
    return this.env.ENVIRONMENT || "development";
  }

  get isDevelopment(): boolean {
    return this.environment === "development";
  }

  get isStaging(): boolean {
    return this.environment === "staging";
  }

  get isProduction(): boolean {
    return this.environment === "production";
  }
}

function getJSTTimestamp(): string {
  const now = new Date();
  return now.toLocaleString("sv-SE", { timeZone: "Asia/Tokyo" }).replace(' ', 'T') + 'Z';
}

async function generateTrip(input: string, secretSalt: string) {
  let hash = input + secretSalt;
  
  for (let i = 0; i < 3; i++) {
    const encoder = new TextEncoder();
    const data = encoder.encode(hash);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let trip = '';
  
  for (let i = 0; i < 10; i++) {
    const index = parseInt(hash.substring(i * 2, i * 2 + 2), 16) % chars.length;
    trip += chars[index];
  }
  
  return trip;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // 環境設定の初期化
    const config = new EnvironmentConfig(env);

    // 環境変数から設定を取得
    const ALLOWED_ORIGINS = config.allowedOrigins;
    const MAX_FILE_SIZE = config.maxFileSize;

    if (config.isDevelopment) {
      console.log('Development environment');
    }

    // CORS設定
    const origin = request.headers.get('Origin');
    const allowedOrigins = ALLOWED_ORIGINS === "*" ? "*" : ALLOWED_ORIGINS.split(',');
    const corsOrigin = ALLOWED_ORIGINS === "*" ? "*" : 
      (allowedOrigins.includes(origin || "") ? origin : null);

    const corsHeaders = {
      'Access-Control-Allow-Origin': corsOrigin || allowedOrigins[0],
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    try {
      // ユーザー投稿取得APIを修正
      if (request.method === 'GET' && url.pathname.startsWith('/api/user/') && url.pathname.endsWith('/posts')) {
        const pathParts = url.pathname.split('/')
        let userName = pathParts[3]
        
        try {
          userName = decodeURIComponent(userName)
          
          const searchParams = url.searchParams
          const page = Math.max(1, parseInt(searchParams.get('page') || '1'))
          const limit = Number(searchParams.get('limit')) || 15
          const offset = (page - 1) * limit
          
          const cleanUserName = userName.startsWith('@') ? userName.slice(1) : userName

          const existsQuery = `
            SELECT COUNT(*) as count FROM posts p
            WHERE (p.x_id = ? OR p.user_name = ?)
          `
          
          const existsResult = await env.DB.prepare(existsQuery).bind(cleanUserName, cleanUserName).first()
          
          if (!existsResult || existsResult.count === 0) {
            return new Response(JSON.stringify({
              success: false,
              error: 'ユーザーが見つかりません'
            }), {
              status: 404,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            })
          }
          
          const query = `
            SELECT DISTINCT p.*, 
                  COALESCE(l.count, 0) as likes_count,
                  COALESCE(p.play_count, 0) as play_count
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id
            WHERE (p.x_id = ? OR p.user_name = ?)
            ORDER BY p.created_at DESC LIMIT ? OFFSET ?
          `

          const countQuery = `
            SELECT COUNT(DISTINCT p.id) as total FROM posts p
            WHERE (p.x_id = ? OR p.user_name = ?)
          `

          const params = [cleanUserName, cleanUserName]
          const queryParams = [...params, limit, offset]
          
          const totalResult = await env.DB.prepare(countQuery).bind(...params).first()
          const total = totalResult?.total || 0
          
          const result = await env.DB.prepare(query).bind(...queryParams).all()
          
          const postsWithData = result.results.map((post: any) => ({
            id: post.id,
            title: post.title,
            xId: post.x_id,
            userName: post.user_name,
            tripHash: post.trip_hash,
            gender: post.gender,
            allowPromotion: post.allow_promotion,
            createdAt: post.created_at,
            audioUrl: `${url.origin}/api/audio/${post.audio_file_key}`,
            likesCount: post.likes_count || 0,
            playCount: post.play_count || 0,
          }))

          const totalPages = Math.ceil(total / limit)
          
          return new Response(JSON.stringify({
            success: true,
            posts: postsWithData,
            pagination: {
              currentPage: page,
              totalPages,
              totalItems: total,
              itemsPerPage: limit,
              hasNext: page < totalPages,
              hasPrev: page > 1
            }
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          })
          
        } catch (error) {
          console.error('ユーザー投稿取得エラー:', error)
          
          return new Response(JSON.stringify({
            success: false,
            error: 'ユーザー投稿取得に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          })
        }
      }

      if (request.method === 'GET' && url.pathname === '/api/tags') {
        try {
          const result = await env.DB.prepare('SELECT * FROM tags ORDER BY name ASC').all();
          
          return new Response(JSON.stringify({
            success: true,
            tags: result.results
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
          
        } catch {
          return new Response(JSON.stringify({
            success: false,
            error: 'タグ取得に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'GET' && url.pathname === '/api/posts') {
        try {
          const searchParams = url.searchParams;
          const page = Math.max(1, parseInt(searchParams.get('page') || '1'));
          const limit = Number(searchParams.get('limit')) || 15;
          const offset = (page - 1) * limit;

          const keyword = searchParams.get('keyword') || '';
          const gender = searchParams.get('gender') || '';
          const tagId = searchParams.get('tagId') ? parseInt(searchParams.get('tagId') as string) : null;

          let query = `
            SELECT DISTINCT p.*, 
                  COALESCE(l.count, 0) as likes_count,
                  COALESCE(p.play_count, 0) as play_count
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id
          `;

          let countQuery = `
            SELECT COUNT(DISTINCT p.id) as total FROM posts p
          `;
          
          if (tagId) {
            query += ' INNER JOIN post_tags pt ON p.id = pt.post_id';
            countQuery += ' INNER JOIN post_tags pt ON p.id = pt.post_id';
          }
          
          query += ' WHERE 1=1';
          countQuery += ' WHERE 1=1';
          
          const params = [] as any;
          
          if (keyword) {
            query += ' AND (p.title LIKE ? OR p.x_id LIKE ? OR p.user_name LIKE ?)';
            countQuery += ' AND (p.title LIKE ? OR p.x_id LIKE ? OR p.user_name LIKE ?)';
            const keywordParam = `%${keyword}%`;
            params.push(keywordParam, keywordParam, keywordParam);
          }
          
          if (gender && ['male', 'female'].includes(gender)) {
            query += ' AND p.gender = ?';
            countQuery += ' AND p.gender = ?';
            params.push(gender);
          }
          
          if (tagId) {
            query += ' AND pt.tag_id = ?';
            countQuery += ' AND pt.tag_id = ?';
            params.push(tagId);
          }
          
          query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
          const queryParams = [...params, limit, offset];
          
          const totalResult = await env.DB.prepare(countQuery).bind(...params).first();
          const total = totalResult?.total || 0;
          
          const result = await env.DB.prepare(query).bind(...queryParams).all();
          
          const postsWithTags = await Promise.all(
            result.results.map(async (post: any) => {
              return {
                id: post.id,
                title: post.title,
                xId: post.x_id,
                userName: post.user_name,
                tripHash: post.trip_hash,
                gender: post.gender,
                allowPromotion: post.allow_promotion,
                createdAt: post.created_at,
                audioUrl: `${url.origin}/api/audio/${post.audio_file_key}`,
                likesCount: post.likes_count || 0,
                playCount: post.play_count || 0,
              };
            })
          );

          const totalPages = Math.ceil(total / limit);
          
          return new Response(JSON.stringify({
            success: true,
            posts: postsWithTags,
            pagination: {
              currentPage: page,
              totalPages,
              totalItems: total,
              itemsPerPage: limit,
              hasNext: page < totalPages,
              hasPrev: page > 1
            }
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
          
        } catch {
          return new Response(JSON.stringify({
            success: false,
            error: '投稿一覧の取得に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      // 音声アップロード
      if (request.method === 'POST' && url.pathname === '/api/upload-audio') {
        try {
          const formData = await request.formData();
          
          const audioFile = formData.get('audioFile') as File;
          const postTitle = formData.get('postTitle') as string;
          const xId = formData.get('xId') as string || null;
          const userName = formData.get('userName') as string || null;
          const passwordHash = formData.get('passwordHash') as string;
          const allowPromotion = formData.get('allowPromotion') === 'true';
          const gender = formData.get('gender') as string;
          const tagsJson = formData.get('tags') as string;
          const tripKey = formData.get('tripKey') as string || null; 
          
          let selectedTags: number[] = [];
          if (tagsJson) {
            try {
              selectedTags = JSON.parse(tagsJson);
            } catch {
              selectedTags = [];
            }
          }

          let tripHash = null;
          if ((xId || userName) && tripKey) {
            tripHash = await generateTrip(tripKey, config.secretSalt);
          }

          if (!audioFile || !postTitle || !passwordHash || !gender) {
            return new Response(JSON.stringify({
              success: false,
              error: '必須項目が入力されていません'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          if (xId && !tripKey) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Xアカウントを入力した場合、トリップキーは必須です'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          if (!['male', 'female'].includes(gender)) {
            return new Response(JSON.stringify({
              success: false,
              error: '性別の値が無効です'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          const allowedTypes = ['audio/mp3', 'audio/mpeg', 'audio/wav', 'audio/m4a', 'audio/mp4'];
          if (!allowedTypes.includes(audioFile.type)) {
            return new Response(JSON.stringify({
              success: false,
              error: 'サポートされていないファイル形式です'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          if (audioFile.size > MAX_FILE_SIZE) {
            return new Response(JSON.stringify({
              success: false,
              error: 'ファイルサイズが上限を超えています'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          const postId = crypto.randomUUID();
          
          const fileExtension = audioFile.name.split('.').pop() || 'mp3';
          const fileKey = `audio/${postId}.${fileExtension}`;
          const arrayBuffer = await audioFile.arrayBuffer();
          
          await env.OHO_AUDIO_BUCKET.put(fileKey, arrayBuffer, {
            httpMetadata: {
              contentType: audioFile.type,
            },
          });

          try {
            await env.DB.prepare(`
              INSERT INTO posts (
                id, title, x_id, user_name, password_hash, gender, allow_promotion,
                audio_file_key, file_size, file_type, client_ip, user_agent, created_at, trip_hash
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
              postId,
              postTitle,
              xId,
              userName,
              passwordHash,
              gender,
              allowPromotion,
              fileKey,
              audioFile.size,
              audioFile.type,
              clientIP,
              userAgent,
              getJSTTimestamp(),
              tripHash
            ).run();


            for (const tagId of selectedTags) {
              const tagExists = await env.DB.prepare('SELECT id FROM tags WHERE id = ?').bind(tagId).first();
              if (tagExists) {
                await env.DB.prepare(`
                  INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)
                `).bind(postId, tagId).run();
              }
            }

            return new Response(JSON.stringify({
              success: true,
              message: '投稿が完了しました',
              postId: postId
            }), {
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });

          } catch {
            await env.OHO_AUDIO_BUCKET.delete(fileKey);
            
            return new Response(JSON.stringify({
              success: false,
              error: 'データベース保存に失敗しました'
            }), {
              status: 500,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
          
        } catch {
          return new Response(JSON.stringify({
            success: false,
            error: '音声アップロードに失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      // 投稿削除
      if (request.method === 'DELETE' && url.pathname.startsWith('/api/delete-post/')) {
        const postId = url.pathname.replace('/api/delete-post/', '');
        
        let requestData;
        try {
          requestData = await request.json();
        } catch {
          return new Response(JSON.stringify({
            success: false,
            error: 'Invalid request body'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const { password } = requestData as any;

        if (!password) {
          return new Response(JSON.stringify({
            success: false,
            error: 'パスワードが必要です'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const post = await getPost(env.DB, postId);
        if (!post) {
          return new Response(JSON.stringify({
            success: false,
            error: '投稿が見つかりません'
          }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const isValidPassword = await verifyPassword(password, post.password_hash);
        if (!isValidPassword) {
          return new Response(JSON.stringify({
            success: false,
            error: 'パスワードが間違っています'
          }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        try {
          await env.OHO_AUDIO_BUCKET.delete(post.audio_file_key);
          
          await deletePost(env.DB, postId);

          return new Response(JSON.stringify({
            success: true,
            message: '投稿が削除されました'
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });

        } catch (error) {
          console.error('Delete error:', error);
          return new Response(JSON.stringify({
            success: false,
            error: '削除に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'POST' && url.pathname.startsWith('/api/posts/') && url.pathname.endsWith('/like')) {
        const postId = url.pathname.split('/')[3];
        
        try {
          const post = await env.DB.prepare('SELECT id FROM posts WHERE id = ?').bind(postId).first();
          if (!post) {
            return new Response(JSON.stringify({
              success: false,
              error: '投稿が見つかりません'
            }), {
              status: 404,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          await env.DB.prepare(`
            INSERT INTO likes (post_id, count) VALUES (?, 1)
            ON CONFLICT(post_id) DO UPDATE SET 
              count = count + 1,
              updated_at = CURRENT_TIMESTAMP
          `).bind(postId).run();

          const likesResult = await env.DB.prepare(`
            SELECT count FROM likes WHERE post_id = ?
          `).bind(postId).first();

          return new Response(JSON.stringify({
            success: true,
            message: 'いいねしました',
            likesCount: likesResult?.count || 0
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });

        } catch (error) {
          console.error('いいね追加エラー:', error);
          return new Response(JSON.stringify({
            success: false,
            error: 'いいねの処理に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'GET' && url.pathname.startsWith('/api/post/')) {
        const pathParts = url.pathname.split('/');
        const postId = pathParts[3];
        
        if (pathParts[4] === 'related') {
          try {
            const currentPost = await env.DB.prepare(`
              SELECT gender FROM posts WHERE id = ?
            `).bind(postId).first();

            if (!currentPost) {
              return new Response(JSON.stringify({
                success: false,
                error: '投稿が見つかりません'
              }), {
                status: 404,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
              });
            }
  
            const relatedPosts = await env.DB.prepare(`
              SELECT p.*, 
                    COALESCE(l.count, 0) as likes_count,
                    COALESCE(p.play_count, 0) as play_count
              FROM posts p
              LEFT JOIN likes l ON p.id = l.post_id
              WHERE p.gender = ? AND p.id != ?
              ORDER BY RANDOM()
              LIMIT 5
            `).bind(currentPost.gender, postId).all();

            const postsWithData = relatedPosts.results.map((post: any) => ({
              id: post.id,
              title: post.title,
              xId: post.x_id,
              userName: post.user_name,
              tripHash: post.trip_hash,
              gender: post.gender,
              allowPromotion: post.allow_promotion,
              createdAt: post.created_at,
              audioUrl: `${url.origin}/api/audio/${post.audio_file_key}`,
              likesCount: post.likes_count || 0,
              playCount: post.play_count || 0,
            }));

            return new Response(JSON.stringify({
              success: true,
              posts: postsWithData
            }), {
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });

          } catch (error) {
            console.error('関連投稿取得エラー:', error);
            return new Response(JSON.stringify({
              success: false,
              error: '関連投稿の取得に失敗しました'
            }), {
              status: 500,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
        }

        try {
          const post = await env.DB.prepare(`
            SELECT p.*, 
                  COALESCE(l.count, 0) as likes_count,
                  COALESCE(p.play_count, 0) as play_count
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id
            WHERE p.id = ?
          `).bind(postId).first();

          if (!post) {
            return new Response(JSON.stringify({
              success: false,
              error: '投稿が見つかりません'
            }), {
              status: 404,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          const tagsResult = await env.DB.prepare(`
            SELECT t.id, t.name, t.created_at
            FROM tags t
            INNER JOIN post_tags pt ON t.id = pt.tag_id
            WHERE pt.post_id = ?
            ORDER BY t.name ASC
          `).bind(postId).all();

          return new Response(JSON.stringify({
            success: true,
            post: {
              id: post.id,
              title: post.title,
              xId: post.x_id || null,
              userName: post.user_name || null,
              tripHash: post.trip_hash || null, 
              gender: post.gender,
              allowPromotion: post.allow_promotion,
              fileSize: post.file_size,
              createdAt: post.created_at,
              audioUrl: `${url.origin}/api/audio/${post.audio_file_key}`,
              likesCount: post.likes_count || 0,
              playCount: post.play_count || 0,
              tags: tagsResult.results || []
            }
          }), {
            headers: { 'Content-Type': 'application/json', "Accept-Ranges": "bytes", ...corsHeaders }
          });
        } catch (error) {
          console.error('投稿詳細取得エラー:', error);
          return new Response(JSON.stringify({
            success: false,
            error: 'データ取得に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'GET' && url.pathname.startsWith('/api/audio/')) {
        const filename = url.pathname.replace('/api/audio/', '');
        
        try {
          const object = await env.OHO_AUDIO_BUCKET.get(filename);
          if (!object) {
            return new Response('Audio file not found', { status: 404, headers: corsHeaders });
          }

          const range = request.headers.get('Range');
          const contentLength = object.size;
          const contentType = object.httpMetadata?.contentType || 'audio/mpeg';

          if (!range) {
            return new Response(object.body, {
              status: 200,
              headers: {
                'Content-Type': contentType,
                'Content-Length': contentLength.toString(),
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=3600',
                ...corsHeaders
              }
            });
          }

          const rangeMatch = range.match(/bytes=(\d+)-(\d*)/);
          if (!rangeMatch) {
            return new Response('Invalid range', { 
              status: 416,
              headers: {
                'Content-Range': `bytes */${contentLength}`,
                ...corsHeaders
              }
            });
          }

          const start = parseInt(rangeMatch[1], 10);
          const end = rangeMatch[2] ? parseInt(rangeMatch[2], 10) : contentLength - 1;

          if (start >= contentLength || end >= contentLength || start > end) {
            return new Response('Requested range not satisfiable', {
              status: 416,
              headers: {
                'Content-Range': `bytes */${contentLength}`,
                ...corsHeaders
              }
            });
          }

          const rangeObject = await env.OHO_AUDIO_BUCKET.get(filename, {
            range: { offset: start, length: end - start + 1 }
          });

          if (!rangeObject) {
            return new Response('Range not available', { status: 416, headers: corsHeaders });
          }

          const contentRange = `bytes ${start}-${end}/${contentLength}`;

          return new Response(rangeObject.body, {
            status: 206,
            headers: {
              'Content-Type': contentType,
              'Content-Length': (end - start + 1).toString(),
              'Content-Range': contentRange,
              'Accept-Ranges': 'bytes',
              'Cache-Control': 'public, max-age=3600',
              ...corsHeaders
            }
          });
        } catch (error) {
          console.error('Audio serving error:', error);
          return new Response('Internal server error', { status: 500, headers: corsHeaders });
        }
      }

      if (request.method === 'GET' && url.pathname === '/api/debug/posts') {
        try {
          const posts = await env.DB.prepare('SELECT * FROM posts ORDER BY created_at DESC').all();
          return new Response(JSON.stringify({
            success: true,
            posts: posts.results || []
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'POST' && url.pathname.startsWith('/api/posts/') && url.pathname.endsWith('/play')) {
        const postId = url.pathname.split('/')[3];
        
        try {
          const post = await env.DB.prepare('SELECT id FROM posts WHERE id = ?').bind(postId).first();
          if (!post) {
            return new Response(JSON.stringify({
              success: false,
              error: '投稿が見つかりません'
            }), {
              status: 404,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          const twelveHoursAgo = new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString();
          const existingPlay = await env.DB.prepare(`
            SELECT id FROM play_records 
            WHERE post_id = ? AND client_ip = ? AND created_at > ?
          `).bind(postId, clientIP, twelveHoursAgo).first();

          if (existingPlay) {
            const playCount = await env.DB.prepare(`
              SELECT play_count FROM posts WHERE id = ?
            `).bind(postId).first();

            return new Response(JSON.stringify({
              success: true,
              alreadyPlayed: true,
              playCount: playCount?.play_count || 0
            }), {
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }

          await env.DB.prepare(`
            INSERT INTO play_records (post_id, client_ip, created_at) VALUES (?, ?, ?)
          `).bind(postId, clientIP, getJSTTimestamp()).run();

          await env.DB.prepare(`
            UPDATE posts SET play_count = play_count + 1 WHERE id = ?
          `).bind(postId).run();

          const updatedPost = await env.DB.prepare(`
            SELECT play_count FROM posts WHERE id = ?
          `).bind(postId).first();

          return new Response(JSON.stringify({
            success: true,
            message: '再生が記録されました',
            playCount: updatedPost?.play_count || 0
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });

        } catch (error) {
          console.error('再生記録エラー:', error);
          return new Response(JSON.stringify({
            success: false,
            error: '再生記録に失敗しました'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (request.method === 'GET' && url.pathname === '/api/health') {
        return new Response(JSON.stringify({
          success: true,
          message: 'Audio Upload API is running',
          timestamp: new Date().toISOString()
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      return new Response(JSON.stringify({
        success: false,
        error: 'Not found'
      }), { 
        status: 404, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        success: false,
        error: 'サーバーエラーが発生しました'
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }
};
