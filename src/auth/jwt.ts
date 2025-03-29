import { Context } from 'hono';
import { sign, verify } from 'hono/jwt';

// JWTペイロードの型定義
export interface JWTPayload {
  sub: string; // ユーザーID
  username: string;
  roles: string[];
  type?: string; // リフレッシュトークン用
  iat?: number; // 発行時間
  exp?: number; // 有効期限
  [key: string]: any; // インデックスシグネチャを追加
}

// アクセストークンの生成
export const generateAccessToken = async (
  c: Context,
  payload: Omit<JWTPayload, 'iat' | 'exp'>
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // JWT Claims の設定
  const tokenPayload = {
    ...payload,
    iat: now,
    exp: now + 3600, // 1時間の有効期限
  };
  
  // JWTの署名と発行
  return await sign(tokenPayload, c.env.JWT_SECRET);
};

// リフレッシュトークンの生成
export const generateRefreshToken = async (
  c: Context,
  userId: string
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // リフレッシュトークン用のペイロード
  const tokenPayload = {
    sub: userId,
    iat: now,
    exp: now + 2592000, // 30日の有効期限
    type: 'refresh'
  };
  
  return await sign(tokenPayload, c.env.JWT_SECRET);
};

// トークンの検証
export const verifyToken = async (
  c: Context,
  token: string
): Promise<JWTPayload | null> => {
  try {
    const verified = await verify(token, c.env.JWT_SECRET);
    return verified as JWTPayload;
  } catch (err) {
    console.error('Token verification error:', err);
    return null;
  }
};

// トークンのリフレッシュハンドラ
export const refreshTokenHandler = async (c: Context) => {
  try {
    // リクエストからリフレッシュトークンを取得
    const { refreshToken } = await c.req.json();
    
    if (!refreshToken) {
      return c.json({ error: 'リフレッシュトークンが必要です' }, 400);
    }
    
    // リフレッシュトークンの検証
    const payload = await verifyToken(c, refreshToken);
    
    if (!payload || payload.type !== 'refresh') {
      return c.json({ error: '無効なリフレッシュトークンです' }, 401);
    }
    
    // ユーザー情報の取得（実際はDBからの取得などが必要）
    const userKey = `user:${payload.sub}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const user = JSON.parse(userJson);
    
    // 新しいアクセストークンの生成
    const newAccessToken = await generateAccessToken(c, {
      sub: user.id,
      username: user.username,
      roles: user.roles
    });
    
    // 新しいリフレッシュトークンの生成（セキュリティのため）
    const newRefreshToken = await generateRefreshToken(c, user.id);
    
    return c.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });
  } catch (err) {
    console.error('Refresh token error:', err);
    return c.json({ error: 'トークンの更新に失敗しました' }, 500);
  }
};