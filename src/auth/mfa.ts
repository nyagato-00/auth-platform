// src/auth/mfa.ts
import { Context } from 'hono';
import { sign, verify } from 'hono/jwt';
import { verifyPassword } from './user';
import { generateAccessToken, generateRefreshToken } from './jwt';
import {
  generateTOTPSecret,
  generateTOTPCode,
  verifyTOTPCode,
  generateTOTPUri,
  debugTOTPCodes
} from './optimized-totp';

// 必要な関数を再エクスポート（login.tsなど他のモジュールから使用するため）
export { generateTOTPSecret, generateTOTPCode, verifyTOTPCode, generateTOTPUri };

// リカバリーコードの生成
export const generateRecoveryCodes = (count: number = 8): string[] => {
  const codes: string[] = [];
  
  for (let i = 0; i < count; i++) {
    // 16バイトのランダムデータを生成
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    
    // バイトを16進文字列に変換し、ダッシュで区切って読みやすくする
    const codeChars = Array.from(randomBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    // 8-4-4-4-12形式に整形（UUID風）
    const formattedCode = [
      codeChars.substring(0, 8),
      codeChars.substring(8, 12),
      codeChars.substring(12, 16),
      codeChars.substring(16, 20),
      codeChars.substring(20, 32)
    ].join('-');
    
    codes.push(formattedCode);
  }
  
  return codes;
};

// リカバリーコードのハッシュ化
export const hashRecoveryCode = async (code: string): Promise<string> => {
  // リカバリーコードのダッシュを削除して正規化
  const normalizedCode = code.replace(/-/g, '').toLowerCase();
  
  // エンコード
  const encoder = new TextEncoder();
  const data = encoder.encode(normalizedCode);
  
  // SHA-256ハッシュを計算
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  // バッファを16進数の文字列に変換
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return `rc256:${hashHex}`;
};

// リカバリーコードの検証と使用済みマーク
export const verifyAndConsumeRecoveryCode = async (
  c: any,
  userId: string,
  recoveryCode: string
): Promise<boolean> => {
  try {
    // ユーザー情報の取得
    const userKey = `id:${userId}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return false;
    }
    
    const user = JSON.parse(userJson);
    
    // MFAが有効で、リカバリーコードが存在するか確認
    if (!user.mfa || !user.mfa.enabled || !user.mfa.recoveryCodes || user.mfa.recoveryCodes.length === 0) {
      return false;
    }
    
    // 入力されたリカバリーコードをハッシュ化
    const normalizedCode = recoveryCode.replace(/-/g, '').toLowerCase();
    const hashedInputCode = await hashRecoveryCode(recoveryCode);
    
    // リカバリーコードを検索
    const recoveryCodeIndex = user.mfa.recoveryCodes.findIndex(
      (rc: { code: string; used: boolean }) => rc.code === hashedInputCode && !rc.used
    );
    
    if (recoveryCodeIndex === -1) {
      return false;
    }
    
    // リカバリーコードを使用済みにマーク
    user.mfa.recoveryCodes[recoveryCodeIndex].used = true;
    user.mfa.recoveryCodes[recoveryCodeIndex].usedAt = new Date().toISOString();
    
    // ユーザー情報を更新
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(user));
    await c.env.AUTH_STORE.put(`user:${user.username}`, JSON.stringify(user));
    
    return true;
  } catch (err) {
    console.error('Verify recovery code error:', err);
    return false;
  }
};

// MFA設定を初期化するハンドラ
export const initMFAHandler = async (c: Context) => {
  try {
    // ユーザーを認証（保護されたAPIなのでユーザー情報は既にある）
    // @ts-ignore
    const user = c.req.user;
    
    if (!user) {
      return c.json({ error: '認証が必要です' }, 401);
    }
    
    // ユーザーの完全な情報を取得
    const userKey = `id:${user.id}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const fullUser = JSON.parse(userJson);
    
    // 既にMFAが有効化されているか確認
    if (fullUser.mfa && fullUser.mfa.enabled) {
      return c.json({ 
        error: 'MFAは既に有効です', 
        mfaEnabled: true 
      }, 400);
    }
    
    // 新しいTOTPシークレットを生成
    const totpSecret = generateTOTPSecret();
    console.log('新しいTOTPシークレット:', totpSecret);
    
    // 仮のMFA情報を記録
    fullUser.mfa = {
      enabled: false,
      type: 'totp',
      secret: totpSecret,
      pendingSetup: true,
      setupInitiatedAt: new Date().toISOString()
    };
    
    // ユーザー情報を更新
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(fullUser));
    await c.env.AUTH_STORE.put(`user:${fullUser.username}`, JSON.stringify(fullUser));
    
    // QRコードURIを生成
    const totpUri = generateTOTPUri(fullUser.username, totpSecret);
    
    // デバッグ用に現在の有効なコードを生成
    let debugInfo = '';
    if (c.env.DEBUG === 'true') {
      const currentCode = await generateTOTPCode(totpSecret);
      debugInfo = `現在の有効なコード: ${currentCode}`;
      console.log(debugInfo);
      
      // デバッグ用に複数の時間窓のコードを表示
      await debugTOTPCodes(totpSecret);
    }
    
    return c.json({
      message: 'MFA設定の初期化が完了しました',
      secret: totpSecret,
      qrCodeUri: totpUri,
      setupPending: true,
      debug: c.env.DEBUG === 'true' ? debugInfo : undefined
    });
  } catch (err) {
    console.error('Init MFA error:', err);
    return c.json({ error: 'MFA設定の初期化に失敗しました' }, 500);
  }
};

// MFA設定を確認して有効化するハンドラ
export const verifyAndEnableMFAHandler = async (c: Context) => {
  try {
    // リクエストからユーザー情報と認証コードを取得
    // @ts-ignore
    const user = c.req.user;
    const { totpCode } = await c.req.json();
    
    if (!user) {
      return c.json({ error: '認証が必要です' }, 401);
    }
    
    if (!totpCode) {
      return c.json({ error: '認証コードは必須です' }, 400);
    }
    
    // ユーザーの完全な情報を取得
    const userKey = `id:${user.id}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const fullUser = JSON.parse(userJson);
    
    // MFA設定の初期化が行われているか確認
    if (!fullUser.mfa || !fullUser.mfa.pendingSetup || !fullUser.mfa.secret) {
      return c.json({ error: 'MFA設定が初期化されていません' }, 400);
    }
    
    console.log('検証リクエスト受信:', { totpCode, user: user.id });
    console.log('ユーザーMFA設定:', fullUser.mfa);
    
    // デバッグのために現在の有効なコードを生成
    if (c.env.DEBUG === 'true') {
      console.log('検証に使用するシークレット:', fullUser.mfa.secret);
      const currentCode = await generateTOTPCode(fullUser.mfa.secret);
      console.log('サーバーで生成した現在の有効なコード:', currentCode);
      console.log('ユーザーが入力したコード:', totpCode);
      
      // デバッグ用に複数の時間窓のコードを表示
      await debugTOTPCodes(fullUser.mfa.secret);
    }
    
    // TOTPコードの検証
    const isValidTOTP = await verifyTOTPCode(totpCode, fullUser.mfa.secret);
    console.log('TOTPコード検証:', { isValidTOTP });
    
    if (!isValidTOTP) {
      return c.json({ error: '無効な認証コードです。もう一度試してください。' }, 401);
    }
    
    // MFAを有効化
    fullUser.mfa.enabled = true;
    fullUser.mfa.pendingSetup = false;
    fullUser.mfa.activatedAt = new Date().toISOString();
    
    // ユーザー情報を更新
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(fullUser));
    await c.env.AUTH_STORE.put(`user:${fullUser.username}`, JSON.stringify(fullUser));
    
    // リカバリーコード（バックアップコード）を生成して返す
    const recoveryCodes = generateRecoveryCodes(8); // 8個のリカバリーコードを生成
    
    // リカバリーコードのハッシュをユーザー情報に保存
    fullUser.mfa.recoveryCodes = await Promise.all(recoveryCodes.map(async (code) => {
      return {
        code: await hashRecoveryCode(code),
        used: false,
        createdAt: new Date().toISOString()
      };
    }));
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(fullUser));
    await c.env.AUTH_STORE.put(`user:${fullUser.username}`, JSON.stringify(fullUser));
    
    return c.json({
      message: 'MFAが正常に有効化されました',
      recoveryCodes: recoveryCodes, // プレーンテキストのリカバリーコードを返す（これは一度だけ表示）
      mfaEnabled: true
    });
  } catch (err) {
    console.error('Verify and enable MFA error:', err);
    return c.json({ error: 'MFA設定の有効化に失敗しました' }, 500);
  }
};

// MFAを無効化するハンドラ
export const disableMFAHandler = async (c: Context) => {
  try {
    // @ts-ignore
    const user = c.req.user;
    const { totpCode, recoveryCode, password } = await c.req.json();
    
    if (!user) {
      return c.json({ error: '認証が必要です' }, 401);
    }
    
    // パスワードは必須
    if (!password) {
      return c.json({ error: 'パスワードは必須です' }, 400);
    }
    
    // TOTPコードかリカバリーコードのいずれかが必要
    if (!totpCode && !recoveryCode) {
      return c.json({ error: '認証コードまたはリカバリーコードが必要です' }, 400);
    }
    
    // ユーザーの完全な情報を取得
    const userKey = `id:${user.id}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const fullUser = JSON.parse(userJson);
    
    // MFAが有効か確認
    if (!fullUser.mfa || !fullUser.mfa.enabled) {
      return c.json({ error: 'MFAは有効になっていません' }, 400);
    }
    
    // パスワードの検証
    const isValidPassword = await verifyPassword(password, fullUser.password);
    
    if (!isValidPassword) {
      return c.json({ error: 'パスワードが無効です' }, 401);
    }
    
    let isValidAuth = false;
    
    // TOTPコードの検証
    if (totpCode) {
      isValidAuth = await verifyTOTPCode(totpCode, fullUser.mfa.secret);
    }
    
    // リカバリーコードの検証
    if (!isValidAuth && recoveryCode) {
      isValidAuth = await verifyAndConsumeRecoveryCode(c, fullUser.id, recoveryCode);
    }
    
    if (!isValidAuth) {
      return c.json({ error: '認証に失敗しました。コードが無効です。' }, 401);
    }
    
    // MFAを無効化
    fullUser.mfa = {
      enabled: false,
      type: null,
      secret: null,
      deactivatedAt: new Date().toISOString()
    };
    fullUser.updatedAt = new Date().toISOString();
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(fullUser));
    await c.env.AUTH_STORE.put(`user:${fullUser.username}`, JSON.stringify(fullUser));
    
    return c.json({
      message: 'MFAが正常に無効化されました',
      mfaEnabled: false
    });
  } catch (err) {
    console.error('Disable MFA error:', err);
    return c.json({ error: 'MFA設定の無効化に失敗しました' }, 500);
  }
};

// リカバリーコードの再生成
export const regenerateRecoveryCodesHandler = async (c: Context) => {
  try {
    // @ts-ignore
    const user = c.req.user;
    const { totpCode, password } = await c.req.json();
    
    if (!user) {
      return c.json({ error: '認証が必要です' }, 401);
    }
    
    // 入力値の検証
    if (!totpCode || !password) {
      return c.json({ error: 'TOTPコードとパスワードは必須です' }, 400);
    }
    
    // ユーザーの完全な情報を取得
    const userKey = `id:${user.id}`;
    const userJson = await c.env.AUTH_STORE.get(userKey);
    
    if (!userJson) {
      return c.json({ error: 'ユーザーが見つかりません' }, 404);
    }
    
    const fullUser = JSON.parse(userJson);
    
    // MFAが有効か確認
    if (!fullUser.mfa || !fullUser.mfa.enabled) {
      return c.json({ error: 'MFAは有効になっていません' }, 400);
    }
    
    // パスワードの検証
    const isValidPassword = await verifyPassword(password, fullUser.password);
    
    if (!isValidPassword) {
      return c.json({ error: 'パスワードが無効です' }, 401);
    }
    
    // TOTPコードの検証
    const isValidTOTP = await verifyTOTPCode(totpCode, fullUser.mfa.secret);
    
    if (!isValidTOTP) {
      return c.json({ error: '無効な認証コードです' }, 401);
    }
    
    // 新しいリカバリーコードを生成
    const newRecoveryCodes = generateRecoveryCodes(8);
    
    // リカバリーコードのハッシュをユーザー情報に保存
    fullUser.mfa.recoveryCodes = await Promise.all(newRecoveryCodes.map(async (code) => {
      return {
        code: await hashRecoveryCode(code),
        used: false,
        createdAt: new Date().toISOString()
      };
    }));
    
    // 更新したユーザー情報を保存
    await c.env.AUTH_STORE.put(userKey, JSON.stringify(fullUser));
    await c.env.AUTH_STORE.put(`user:${fullUser.username}`, JSON.stringify(fullUser));
    
    return c.json({
      message: 'リカバリーコードが再生成されました',
      recoveryCodes: newRecoveryCodes // プレーンテキストのリカバリーコードを返す（これは一度だけ表示）
    });
  } catch (err) {
    console.error('Regenerate recovery codes error:', err);
    return c.json({ error: 'リカバリーコードの再生成に失敗しました' }, 500);
  }
};