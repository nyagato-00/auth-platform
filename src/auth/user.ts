// Cloudflare Workersの環境でCryptoを使用してパスワードをハッシュ化
// 注意: 本番環境では、より強力なパスワードハッシュアルゴリズム（bcryptなど）の使用を検討してください

// src/auth/user.ts に追加するMFA関連の関数

// パスワードのハッシュ化
export const hashPassword = async (password: string): Promise<string> => {
  // パスワードをエンコード
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  
  // SHA-256を使用してハッシュ化
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  // バッファを16進数の文字列に変換
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  // ソルトを追加（本番環境ではより複雑なソルト方法を使用）
  return `sha256:${hashHex}`;
};

// パスワードの検証
export const verifyPassword = async (
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> => {
  // ハッシュ方法の確認
  if (!hashedPassword.startsWith('sha256:')) {
    throw new Error('サポートされていないハッシュ方式です');
  }
  
  // 入力されたパスワードをハッシュ化
  const hashedPlainPassword = await hashPassword(plainPassword);
  
  // ハッシュを比較
  return hashedPassword === hashedPlainPassword;
};

// ユーザープロファイルの取得
export const getUserProfile = async (c: any, userId: string) => {
  try {
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return null;
    }
    
    const user = JSON.parse(userJson);
    
    // パスワードなど機密情報を除外
    const { password, ...userProfile } = user;
    
    return userProfile;
  } catch (err) {
    console.error('Get user profile error:', err);
    return null;
  }
};

// ユーザーロールの更新
export const updateUserRoles = async (
  c: any,
  userId: string,
  roles: string[]
) => {
  try {
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return false;
    }
    
    const user = JSON.parse(userJson);
    
    // ロールを更新
    user.roles = roles;
    user.updatedAt = new Date().toISOString();
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(user));
    await c.env.AUTH_STORE.put(`user:${user.username}`, JSON.stringify(user));
    
    return true;
  } catch (err) {
    console.error('Update user roles error:', err);
    return false;
  }
};

/**
 * ユーザーのMFA設定を有効化
 * @param c コンテキスト
 * @param userId ユーザーID
 * @param totpSecret TOTPシークレット
 * @returns 処理結果
 */
export const enableUserMFA = async (
  c: any,
  userId: string,
  totpSecret: string
): Promise<boolean> => {
  try {
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return false;
    }
    
    const user = JSON.parse(userJson);
    
    // MFA情報を更新
    user.mfa = {
      enabled: true,
      type: 'totp',
      secret: totpSecret,
      activatedAt: new Date().toISOString()
    };
    user.updatedAt = new Date().toISOString();
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(user));
    await c.env.AUTH_STORE.put(`user:${user.username}`, JSON.stringify(user));
    
    return true;
  } catch (err) {
    console.error('Enable user MFA error:', err);
    return false;
  }
};

/**
 * ユーザーのMFA設定を無効化
 * @param c コンテキスト
 * @param userId ユーザーID
 * @returns 処理結果
 */
export const disableUserMFA = async (
  c: any,
  userId: string
): Promise<boolean> => {
  try {
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return false;
    }
    
    const user = JSON.parse(userJson);
    
    // MFA情報を無効化
    user.mfa = {
      enabled: false,
      type: null,
      secret: null,
      deactivatedAt: new Date().toISOString()
    };
    user.updatedAt = new Date().toISOString();
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(user));
    await c.env.AUTH_STORE.put(`user:${user.username}`, JSON.stringify(user));
    
    return true;
  } catch (err) {
    console.error('Disable user MFA error:', err);
    return false;
  }
};

/**
 * ユーザーのMFA状態を確認
 * @param c コンテキスト
 * @param userId ユーザーID
 * @returns MFA有効状態
 */
export const checkUserMFAStatus = async (
  c: any,
  userId: string
): Promise<{ enabled: boolean; type?: string }> => {
  try {
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return { enabled: false };
    }
    
    const user = JSON.parse(userJson);
    
    if (user.mfa && user.mfa.enabled) {
      return {
        enabled: true,
        type: user.mfa.type
      };
    }
    
    return { enabled: false };
  } catch (err) {
    console.error('Check user MFA status error:', err);
    return { enabled: false };
  }
};
