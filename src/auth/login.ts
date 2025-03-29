import { Context } from 'hono';
import { sign } from 'hono/jwt';
import { generateAccessToken, generateRefreshToken, verifyToken } from './jwt';
import { hashPassword, verifyPassword } from './user';
import { verifyTOTPCode, verifyAndConsumeRecoveryCode } from './mfa';

// ユーザー登録ハンドラ
export const registerHandler = async (c: Context) => {
  try {
    const { username, password, email } = await c.req.json();
    
    // 入力値の検証
    if (!username || !password || !email) {
      return c.json({ error: 'ユーザー名、パスワード、メールアドレスは必須です' }, 400);
    }
    
    // ユーザー存在チェック
    const userKey = `user:${username}`;
    const existingUser = await c.env.AUTH_STORE.get(userKey);
    
    if (existingUser) {
      return c.json({ error: 'このユーザー名は既に使用されています' }, 409);
    }
    
    // メールアドレス存在チェック
    const emailKey = `email:${email}`;
    const existingEmail = await c.env.AUTH_STORE.get(emailKey);
    
    if (existingEmail) {
      return c.json({ error: 'このメールアドレスは既に使用されています' }, 409);
    }
    
    // パスワードのハッシュ化
    const hashedPassword = await hashPassword(password);
    
    // ユーザーIDの生成
    const userId = crypto.randomUUID();
    
    // ユーザー情報の作成
    const user = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      roles: ['user'],
      createdAt: new Date().toISOString()
    };
    
    // KVへの保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(user));
    await c.env.AUTH_STORE.put(emailKey, userId);
    await c.env.AUTH_STORE.put(`id:${userId}`, JSON.stringify(user));
    
    // ユーザー情報（パスワードを除く）を返す
    const { password: _, ...userWithoutPassword } = user;
    
    return c.json({ 
      message: 'ユーザー登録が完了しました',
      user: userWithoutPassword 
    }, 201);
  } catch (err) {
    console.error('Registration error:', err);
    return c.json({ error: 'ユーザー登録に失敗しました' }, 500);
  }
};

// ログインハンドラを修正（MFA対応）
export const loginHandler = async (c: Context) => {
  try {
    const { username, password, totpCode } = await c.req.json();
    
    // 入力値の検証
    if (!username || !password) {
      return c.json({ error: 'ユーザー名とパスワードは必須です' }, 400);
    }
    
    // ユーザー情報の取得
    const userKey = `user:${username}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザー名またはパスワードが無効です' }, 401);
    }
    
    const user = JSON.parse(userJson);
    
    // パスワードの検証
    const isValidPassword = await verifyPassword(password, user.password);
    
    if (!isValidPassword) {
      return c.json({ error: 'ユーザー名またはパスワードが無効です' }, 401);
    }
    
    // MFAが有効か確認
    const hasMFA = user.mfa && user.mfa.enabled === true;
    
    // MFAが有効だがTOTPコードが提供されていない場合
    if (hasMFA && !totpCode) {
      return c.json({
        message: 'MFA認証が必要です',
        requireMFA: true,
        mfaType: user.mfa.type,
        userId: user.id,
        // 一時的にセッショントークンを発行（MFA完了前の一時的な状態を管理）
        temporaryToken: await generateTemporaryToken(c, user.id)
      }, 200);
    }
    
    // MFAが有効でTOTPコードが提供された場合、TOTPを検証
    if (hasMFA && totpCode) {
      const isValidTOTP = await verifyTOTPCode(totpCode, user.mfa.secret);
      
      if (!isValidTOTP) {
        return c.json({ error: '無効な認証コードです。もう一度試してください。' }, 401);
      }
    }
    
    // 認証成功 - JWTの生成
    const accessToken = await generateAccessToken(c, {
      sub: user.id,
      username: user.username,
      roles: user.roles
    });
    
    // リフレッシュトークンの生成
    const refreshToken = await generateRefreshToken(c, user.id);
    
    // ログイン情報の保存（セキュリティ監査用など）
    await c.env.AUTH_STORE.put(`login:${user.id}:${Date.now()}`, JSON.stringify({
      userId: user.id,
      username: user.username,
      timestamp: new Date().toISOString(),
      ip: c.req.header('CF-Connecting-IP') || 'unknown',
      usedMFA: hasMFA
    }));
    
    return c.json({
      message: 'ログインに成功しました',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
        mfaEnabled: hasMFA
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return c.json({ error: 'ログインに失敗しました' }, 500);
  }
};

// 一時的なトークンを生成（MFA検証のために使用）
const generateTemporaryToken = async (c: Context, userId: string): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // 一時的なトークン用のペイロード（5分間有効）
  const tokenPayload = {
    sub: userId,
    iat: now,
    exp: now + 300, // 5分間有効
    type: 'temporary-mfa'
  };
  
  return await sign(tokenPayload, c.env.JWT_SECRET);
};

// MFA検証を完了してアクセストークンを発行するハンドラ
export const completeMFAHandler = async (c: Context) => {
  try {
    const { temporaryToken, totpCode } = await c.req.json();
    
    if (!temporaryToken || !totpCode) {
      return c.json({ error: '一時トークンと認証コードは必須です' }, 400);
    }
    
    // 一時トークンの検証
    const payload = await verifyToken(c, temporaryToken);
    
    if (!payload || payload.type !== 'temporary-mfa') {
      return c.json({ error: '無効または期限切れの一時トークンです' }, 401);
    }
    
    // ユーザー情報の取得
    const userId = payload.sub;
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const user = JSON.parse(userJson);
    
    // MFAが有効か確認
    if (!user.mfa || !user.mfa.enabled) {
      return c.json({ error: 'このユーザーにはMFAが設定されていません' }, 400);
    }
    
    // TOTPコードの検証
    const isValidTOTP = await verifyTOTPCode(totpCode, user.mfa.secret);
    
    if (!isValidTOTP) {
      return c.json({ error: '無効な認証コードです。もう一度試してください。' }, 401);
    }
    
    // 認証成功 - JWTの生成
    const accessToken = await generateAccessToken(c, {
      sub: user.id,
      username: user.username,
      roles: user.roles
    });
    
    // リフレッシュトークンの生成
    const refreshToken = await generateRefreshToken(c, user.id);
    
    // ログイン情報の保存
    await c.env.AUTH_STORE.put(`login:${user.id}:${Date.now()}`, JSON.stringify({
      userId: user.id,
      username: user.username,
      timestamp: new Date().toISOString(),
      ip: c.req.header('CF-Connecting-IP') || 'unknown',
      usedMFA: true,
      mfaType: user.mfa.type
    }));
    
    return c.json({
      message: 'MFA認証に成功しました',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
        mfaEnabled: true
      }
    });
  } catch (err) {
    console.error('Complete MFA error:', err);
    return c.json({ error: 'MFA認証に失敗しました' }, 500);
  }
};

// リカバリーコードによるログインハンドラ
export const loginWithRecoveryCodeHandler = async (c: Context) => {
  try {
    const { username, password, recoveryCode } = await c.req.json();
    
    // 入力値の検証
    if (!username || !password || !recoveryCode) {
      return c.json({ error: 'ユーザー名、パスワード、リカバリーコードは必須です' }, 400);
    }
    
    // ユーザー情報の取得
    const userKey = `user:${username}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザー名またはパスワードが無効です' }, 401);
    }
    
    const user = JSON.parse(userJson);
    
    // パスワードの検証
    const isValidPassword = await verifyPassword(password, user.password);
    
    if (!isValidPassword) {
      return c.json({ error: 'ユーザー名またはパスワードが無効です' }, 401);
    }
    
    // MFAが有効か確認
    if (!user.mfa || !user.mfa.enabled) {
      return c.json({ error: 'このアカウントにはMFAが設定されていません' }, 400);
    }
    
    // リカバリーコードの検証と消費
    const isValidRecoveryCode = await verifyAndConsumeRecoveryCode(c, user.id, recoveryCode);
    
    if (!isValidRecoveryCode) {
      return c.json({ error: '無効なリカバリーコードです' }, 401);
    }
    
    // 認証成功 - JWTの生成
    const accessToken = await generateAccessToken(c, {
      sub: user.id,
      username: user.username,
      roles: user.roles
    });
    
    // リフレッシュトークンの生成
    const refreshToken = await generateRefreshToken(c, user.id);
    
    // ログイン情報の保存
    await c.env.AUTH_STORE.put(`login:${user.id}:${Date.now()}`, JSON.stringify({
      userId: user.id,
      username: user.username,
      timestamp: new Date().toISOString(),
      ip: c.req.header('CF-Connecting-IP') || 'unknown',
      usedMFA: true,
      mfaType: 'recovery-code'
    }));
    
    return c.json({
      message: 'リカバリーコードを使用したログインに成功しました',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
        mfaEnabled: true
      },
      recoveryCodeUsed: true
    });
  } catch (err) {
    console.error('Login with recovery code error:', err);
    return c.json({ error: 'リカバリーコードによるログインに失敗しました' }, 500);
  }
};

// ログアウトハンドラ
export const logoutHandler = async (c: Context) => {
  try {
    // ここでは簡易的な実装。実際にはリフレッシュトークンのブラックリスト登録などが必要
    // クライアント側でトークンを破棄する前提の実装
    
    return c.json({ message: 'ログアウトしました' });
  } catch (err) {
    console.error('Logout error:', err);
    return c.json({ error: 'ログアウト処理に失敗しました' }, 500);
  }
};