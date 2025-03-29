import { Context, Next } from 'hono';
import { verifyToken } from '../auth/jwt';

// 認証ミドルウェア
export const authMiddleware = async (c: Context, next: Next) => {
  // Authorizationヘッダーの取得
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  
  // トークンの抽出
  const token = authHeader.replace('Bearer ', '');
  
  try {
    // トークンの検証
    const payload = await verifyToken(c, token);
    
    if (!payload) {
      return c.json({ error: 'Invalid or expired token' }, 401);
    }
    
    // 認証済みユーザー情報をリクエストオブジェクトに設定
    // @ts-ignore - TypeScriptエラーを回避するためのアノテーション
    c.req.user = {
      id: payload.sub,
      username: payload.username,
      roles: payload.roles
    };
    
    // レート制限やアクセスログの記録などをここで実装可能
    
    await next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return c.json({ 
      error: 'Authentication failed', 
      details: c.env.DEBUG === 'true' ? String(err) : undefined 
    }, 401);
  }
};