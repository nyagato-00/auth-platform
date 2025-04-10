// src/oidc/token.ts
// OIDC トークン関連の機能

import { Context } from 'hono';
import { sign, verify } from 'hono/jwt';
import { 
  IDTokenClaims, 
  AccessTokenClaims, 
  TokenRequest, 
  GrantType,
  AuthorizationCode
} from './types';
import { getClient, authenticateClient } from './client';
import { getUserProfile } from '../auth/user';

// アクセストークンの生成
export const generateAccessToken = async (
  c: Context,
  sub: string,
  clientId: string,
  scope: string
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // アクセストークンのペイロード
  const payload: AccessTokenClaims = {
    iss: getIssuer(c),
    sub,
    aud: ['resource_servers'],
    iat: now,
    exp: now + 3600, // 1時間の有効期限
    client_id: clientId,
    scope
  };
  
  // JWTの署名と発行
  return await sign(payload, c.env.JWT_SECRET);
};

// IDトークンの生成
export const generateIdToken = async (
  c: Context,
  sub: string,
  clientId: string,
  nonce?: string
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // ユーザープロファイルの取得
  const user = await getUserProfile(c, sub);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // IDトークンのペイロード
  const payload: IDTokenClaims = {
    iss: getIssuer(c),
    sub,
    aud: clientId,
    iat: now,
    exp: now + 3600, // 1時間の有効期限
    auth_time: now,
    // Optional claims
    name: user.username,
    email: user.email,
  };
  
  // nonceが提供された場合に追加
  if (nonce) {
    payload.nonce = nonce;
  }
  
  // MFAが有効な場合、amrクレームを追加
  if (user.mfaEnabled) {
    payload.amr = ['mfa'];
    payload.acr = '2'; // LoA2 - 多要素認証
  } else {
    payload.amr = ['pwd'];
    payload.acr = '1'; // LoA1 - 単一要素認証
  }
  
  // JWTの署名と発行
  return await sign(payload, c.env.JWT_SECRET);
};

// リフレッシュトークンの生成
export const generateRefreshToken = async (
  c: Context,
  sub: string,
  clientId: string,
  scope: string
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  
  // リフレッシュトークン用のペイロード
  const payload = {
    iss: getIssuer(c),
    sub,
    client_id: clientId,
    scope,
    iat: now,
    exp: now + 2592000, // 30日の有効期限
    type: 'refresh'
  };
  
  // トークンの生成
  const refreshToken = await sign(payload, c.env.JWT_SECRET);
  
  // KVストアに保存（オプション：取り消し機能のため）
  const refreshTokenKey = `refresh_token:${refreshToken}`;
  await c.env.AUTH_STORE.put(refreshTokenKey, JSON.stringify({
    userId: sub,
    clientId,
    scope,
    expiresAt: now + 2592000
  }));
  
  return refreshToken;
};

// 認可コードの生成と保存
export const generateAuthorizationCode = async (
  c: Context,
  authorizationData: Omit<AuthorizationCode, 'code' | 'expires_at'>
): Promise<string> => {
  // ランダムな認可コードを生成
  const codeBytes = new Uint8Array(32);
  crypto.getRandomValues(codeBytes);
  const code = Array.from(codeBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  // 有効期限（10分）
  const expires_at = Math.floor(Date.now() / 1000) + 600;
  
  // 認可コード情報を作成
  const authorizationCode: AuthorizationCode = {
    ...authorizationData,
    code,
    expires_at
  };
  
  // Cloudflare KVに保存
  const codeKey = `auth_code:${code}`;
  await c.env.AUTH_STORE.put(codeKey, JSON.stringify(authorizationCode), { expirationTtl: 600 });
  
  return code;
};

// 認可コードの検証と交換
export const exchangeAuthorizationCode = async (
  c: Context,
  code: string,
  client_id: string,
  redirect_uri: string,
  code_verifier?: string
): Promise<AuthorizationCode | null> => {
  // 認可コードをKVから取得
  const codeKey = `auth_code:${code}`;
  const codeData = await c.env.AUTH_STORE.get(codeKey);
  
  if (!codeData) {
    return null;
  }
  
  const authCode = JSON.parse(codeData) as AuthorizationCode;
  
  // コードの有効期限を確認
  const now = Math.floor(Date.now() / 1000);
  if (authCode.expires_at < now) {
    await c.env.AUTH_STORE.delete(codeKey);
    return null;
  }
  
  // クライアントIDとリダイレクトURIを検証
  if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
    return null;
  }
  
  // PKCE検証（コードチャレンジが設定されている場合）
  if (authCode.code_challenge && code_verifier) {
    const method = authCode.code_challenge_method || 'plain';
    
    let verifierHash = code_verifier;
    if (method === 'S256') {
      // SHA-256でハッシュ化
      const encoder = new TextEncoder();
      const data = encoder.encode(code_verifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      
      // Base64URLエンコード
      verifierHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    }
    
    if (authCode.code_challenge !== verifierHash) {
      return null;
    }
  }
  
  // 一度だけ使用できるように、認可コードを削除
  await c.env.AUTH_STORE.delete(codeKey);
  
  return authCode;
};

// トークンエンドポイントリクエストの処理
export const handleTokenRequest = async (c: Context): Promise<any> => {
  try {
    // リクエストからトークンパラメータを取得
    const body = await c.req.parseBody();
    const tokenReq = body as unknown as TokenRequest;
    
    // grant_typeの確認
    if (!tokenReq.grant_type) {
      return c.json({ error: 'invalid_request', error_description: 'grant_type is required' }, 400);
    }
    
    // クライアント認証
    let clientAuthenticated = false;
    
    // Basic認証からクライアント認証情報を取得
    const authHeader = c.req.header('Authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
      const base64Credentials = authHeader.slice('Basic '.length);
      const credentials = atob(base64Credentials);
      const [clientId, clientSecret] = credentials.split(':');
      
      clientAuthenticated = await authenticateClient(c, clientId, clientSecret);
      
      if (clientAuthenticated) {
        tokenReq.client_id = clientId;
      }
    }
    
    // POST パラメータでのクライアント認証（Basic認証が失敗した場合）
    if (!clientAuthenticated && tokenReq.client_id && tokenReq.client_secret) {
      clientAuthenticated = await authenticateClient(c, tokenReq.client_id, tokenReq.client_secret);
    }
    
    // クライアント情報の取得
    const client = await getClient(c, tokenReq.client_id);
    if (!client) {
      return c.json({ error: 'invalid_client', error_description: 'Client not found' }, 401);
    }
    
    // 認証が必要なクライアントの場合、認証を確認
    if (client.token_endpoint_auth_method !== 'none' && !clientAuthenticated) {
      return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
    }
    
    // クライアントがrequested grant_typeをサポートしているか確認
    if (!client.grant_types.includes(tokenReq.grant_type)) {
      return c.json({ error: 'unauthorized_client', error_description: 'Grant type not allowed for this client' }, 400);
    }
    
    // grant_typeに応じた処理
    switch (tokenReq.grant_type) {
      case GrantType.AUTHORIZATION_CODE:
        return await handleAuthorizationCodeGrant(c, tokenReq, client);
        
      case GrantType.REFRESH_TOKEN:
        return await handleRefreshTokenGrant(c, tokenReq, client);
        
      case GrantType.CLIENT_CREDENTIALS:
        return await handleClientCredentialsGrant(c, tokenReq, client);
        
      default:
        return c.json({ error: 'unsupported_grant_type', error_description: 'Grant type not supported' }, 400);
    }
  } catch (err) {
    console.error('Token endpoint error:', err);
    return c.json({ error: 'server_error', error_description: 'Internal server error' }, 500);
  }
};

// 認可コードグラント処理
const handleAuthorizationCodeGrant = async (c: Context, tokenReq: TokenRequest, client: any): Promise<any> => {
  // 必須パラメータの確認
  if (!tokenReq.code) {
    return c.json({ error: 'invalid_request', error_description: 'code is required' }, 400);
  }
  
  if (!tokenReq.redirect_uri) {
    return c.json({ error: 'invalid_request', error_description: 'redirect_uri is required' }, 400);
  }
  
  // 認可コードの検証と交換
  const authCode = await exchangeAuthorizationCode(
    c,
    tokenReq.code,
    tokenReq.client_id,
    tokenReq.redirect_uri,
    tokenReq.code_verifier
  );
  
  if (!authCode) {
    return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
  }
  
  // アクセストークンの生成
  const accessToken = await generateAccessToken(c, authCode.user_id, client.client_id, authCode.scope);
  
  // スコープにopenidが含まれている場合、IDトークンを生成
  const scopes = authCode.scope.split(' ');
  const response: any = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600
  };
  
  if (scopes.includes('openid')) {
    response.id_token = await generateIdToken(c, authCode.user_id, client.client_id, authCode.nonce);
  }
  
  // offline_accessスコープが含まれている場合、リフレッシュトークンを発行
  if (scopes.includes('offline_access')) {
    response.refresh_token = await generateRefreshToken(c, authCode.user_id, client.client_id, authCode.scope);
  }
  
  response.scope = authCode.scope;
  
  return c.json(response);
};

// リフレッシュトークングラント処理
const handleRefreshTokenGrant = async (c: Context, tokenReq: TokenRequest, client: any): Promise<any> => {
  // 必須パラメータの確認
  if (!tokenReq.refresh_token) {
    return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' }, 400);
  }
  
  try {
    // リフレッシュトークンの検証
    const payload = await verify(tokenReq.refresh_token, c.env.JWT_SECRET);
    
    // トークンタイプと有効期限の確認
    if (payload.type !== 'refresh' || payload.client_id !== client.client_id) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token' }, 400);
    }
    
    // スコープの確認
    let scope = payload.scope;
    if (tokenReq.scope) {
      // 要求されたスコープが元のスコープのサブセットであることを確認
      const originalScopes = payload.scope.split(' ');
      const requestedScopes = tokenReq.scope.split(' ');
      
      // すべての要求されたスコープが元のスコープに含まれていることを確認
      const validScope = requestedScopes.every(s => originalScopes.includes(s));
      
      if (!validScope) {
        return c.json({ error: 'invalid_scope', error_description: 'Requested scope exceeds original scope' }, 400);
      }
      
      scope = tokenReq.scope;
    }
    
    // 新しいアクセストークンの生成
    const accessToken = await generateAccessToken(c, payload.sub, client.client_id, scope);
    
    // レスポンスの作成
    const response: any = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope
    };
    
    // スコープにopenidが含まれている場合、新しいIDトークンを生成
    if (scope.split(' ').includes('openid')) {
      response.id_token = await generateIdToken(c, payload.sub, client.client_id);
    }
    
    // 新しいリフレッシュトークン（オプション）
    response.refresh_token = await generateRefreshToken(c, payload.sub, client.client_id, scope);
    
    return c.json(response);
  } catch (err) {
    console.error('Refresh token verification error:', err);
    return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token' }, 400);
  }
};

// クライアント認証情報グラント処理
const handleClientCredentialsGrant = async (c: Context, tokenReq: TokenRequest, client: any): Promise<any> => {
  // スコープの確認
  let scope = 'system';
  if (tokenReq.scope) {
    const requestedScopes = tokenReq.scope.split(' ');
    const allowedScopes = client.scopes.filter((s: string) => s !== 'openid' && s !== 'offline_access');
    
    // クライアントに許可されたスコープのみをフィルタリング
    const validScopes = requestedScopes.filter(s => allowedScopes.includes(s));
    
    if (validScopes.length === 0) {
      return c.json({ error: 'invalid_scope', error_description: 'Invalid scope requested' }, 400);
    }
    
    scope = validScopes.join(' ');
  }
  
  // クライアント用のアクセストークンを生成
  const accessToken = await generateAccessToken(c, `client:${client.client_id}`, client.client_id, scope);
  
  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope
  });
};

// 発行者 (Issuer) の取得
export const getIssuer = (c: Context): string => {
  return c.env.ISSUER_BASE_URL || `https://${c.req.header('host')}`;
};

// トークン用の JWK セットを取得
export const getJwks = async (c: Context): Promise<any> => {
  // 実際の実装では、公開鍵のセットを返す
  // この例では、簡易的な実装としてダミーの JWK を返す
  return {
    keys: [
      {
        kid: "default",
        kty: "oct",
        alg: "HS256",
        use: "sig"
      }
    ]
  };
};