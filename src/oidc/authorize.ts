// src/oidc/authorize.ts
// OIDC 認可エンドポイント
import { generateAccessToken, generateIdToken } from './token';
import { Context } from 'hono';
import { 
  AuthorizationRequest, 
  ResponseType,
  OIDCScope
} from './types';
import { getClient, validateRedirectUri, validateScope } from './client';
import { generateAuthorizationCode } from './token';

// エラーリダイレクト
const redirectError = (redirectUri: string, error: string, description: string, state?: string): Response => {
  const params = new URLSearchParams();
  params.set('error', error);
  params.set('error_description', description);
  
  if (state) {
    params.set('state', state);
  }
  
  return Response.redirect(`${redirectUri}?${params.toString()}`, 302);
};

// 認可リクエストの検証
export const validateAuthorizationRequest = async (c: Context): Promise<{ valid: boolean; error?: any; client?: any; }> => {
  try {
    // リクエストパラメータを取得
    const query = c.req.query();
    const authRequest = query as unknown as AuthorizationRequest;
    
    // 必須パラメータの確認
    if (!authRequest.client_id) {
      return { valid: false, error: { error: 'invalid_request', error_description: 'client_id is required' } };
    }
    
    if (!authRequest.redirect_uri) {
      return { valid: false, error: { error: 'invalid_request', error_description: 'redirect_uri is required' } };
    }
    
    if (!authRequest.response_type) {
      return { valid: false, error: { error: 'invalid_request', error_description: 'response_type is required' } };
    }
    
    // クライアント情報の取得
    const client = await getClient(c, authRequest.client_id);
    
    if (!client) {
      return { valid: false, error: { error: 'invalid_client', error_description: 'Client not found' } };
    }
    
    // リダイレクトURIの検証
    if (!validateRedirectUri(client, authRequest.redirect_uri)) {
      return { valid: false, error: { error: 'invalid_redirect_uri', error_description: 'Invalid redirect URI' } };
    }
    
    // response_typeの検証
    if (!client.response_types.includes(authRequest.response_type)) {
      return { 
        valid: false, 
        error: { error: 'unsupported_response_type', error_description: 'Response type not supported for this client' },
        client
      };
    }
    
    // PKCEが必要な場合の検証
    if (authRequest.code_challenge_method === 'S256' && !authRequest.code_challenge) {
      return {
        valid: false,
        error: { error: 'invalid_request', error_description: 'code_challenge is required when code_challenge_method is provided' },
        client
      };
    }
    
    return { valid: true, client };
  } catch (err) {
    console.error('Validation error:', err);
    return { valid: false, error: { error: 'server_error', error_description: 'Internal server error' } };
  }
};

// 認可エンドポイントハンドラ
export const handleAuthorizationRequest = async (c: Context): Promise<Response> => {
  try {
    // リクエストパラメータを取得
    const query = c.req.query();
    const authRequest = query as unknown as AuthorizationRequest;
    
    // リクエストの検証
    const validation = await validateAuthorizationRequest(c);
    
    if (!validation.valid) {
      // エラーがあり、かつクライアントとリダイレクトURIが有効な場合はリダイレクト
      if (validation.client && validateRedirectUri(validation.client, authRequest.redirect_uri)) {
        return redirectError(
          authRequest.redirect_uri,
          validation.error.error,
          validation.error.error_description,
          authRequest.state
        );
      }
      
      // それ以外の場合は直接エラーを返す
      return c.json(validation.error, 400);
    }
    
    const client = validation.client;
    
    // スコープの検証
    const validScope = validateScope(client, authRequest.scope || 'openid');
    
    // ユーザーセッションの確認
    // @ts-ignore - TypeScriptエラーを回避するためのアノテーション
    const user = c.req.user;
    
    if (!user) {
      // ユーザーがログインしていない場合は、ログインページにリダイレクト
      // ログイン後に元のリクエストに戻れるように、認可リクエストの情報を保存
      
      // 認可リクエスト情報をセッションに保存
      const authSessionKey = `auth_session:${crypto.randomUUID()}`;
      await c.env.AUTH_STORE.put(authSessionKey, JSON.stringify({
        ...authRequest,
        scope: validScope
      }), { expirationTtl: 3600 }); // 1時間の有効期限
      
      // ログインページにリダイレクト
      const loginUrl = new URL('/login', c.req.url);
      loginUrl.searchParams.set('auth_session', authSessionKey);
      
      return Response.redirect(loginUrl.toString(), 302);
    }
    
    // response_typeに応じた処理
    switch (authRequest.response_type) {
      case ResponseType.CODE:
        return await handleAuthorizationCodeFlow(c, user, client, authRequest, validScope);
        
      case ResponseType.ID_TOKEN:
      case `${ResponseType.ID_TOKEN} ${ResponseType.TOKEN}`:
      case ResponseType.TOKEN:
        return await handleImplicitFlow(c, user, client, authRequest, validScope);
        
      default:
        return redirectError(
          authRequest.redirect_uri,
          'unsupported_response_type',
          'Response type not supported',
          authRequest.state
        );
    }
  } catch (err) {
    console.error('Authorization endpoint error:', err);
    return c.json({ error: 'server_error', error_description: 'Internal server error' }, 500);
  }
};

// 認可コードフローの処理
const handleAuthorizationCodeFlow = async (
  c: Context,
  user: any,
  client: any,
  authRequest: AuthorizationRequest,
  validScope: string
): Promise<Response> => {
  try {
    // 認可コードの生成
    const code = await generateAuthorizationCode(c, {
      client_id: client.client_id,
      redirect_uri: authRequest.redirect_uri,
      scope: validScope,
      user_id: user.id,
      code_challenge: authRequest.code_challenge,
      code_challenge_method: authRequest.code_challenge_method,
      nonce: authRequest.nonce,
      state: authRequest.state
    });
    
    // リダイレクトURLの作成
    const params = new URLSearchParams();
    params.set('code', code);
    
    if (authRequest.state) {
      params.set('state', authRequest.state);
    }
    
    return Response.redirect(`${authRequest.redirect_uri}?${params.toString()}`, 302);
  } catch (err) {
    console.error('Authorization code flow error:', err);
    return redirectError(
      authRequest.redirect_uri,
      'server_error',
      'Failed to generate authorization code',
      authRequest.state
    );
  }
};

// 暗黙的フロー（Implicit Flow）の処理
const handleImplicitFlow = async (
  c: Context,
  user: any,
  client: any,
  authRequest: AuthorizationRequest,
  validScope: string
): Promise<Response> => {
  try {
    // レスポンスパラメータの準備
    const params = new URLSearchParams();
    
    // response_typeに応じたトークンの生成
    if (authRequest.response_type.includes(ResponseType.TOKEN)) {
      const accessToken = await generateAccessToken(c, user.id, client.client_id, validScope);
      params.set('access_token', accessToken);
      params.set('token_type', 'Bearer');
      params.set('expires_in', '3600');
    }
    
    if (authRequest.response_type.includes(ResponseType.ID_TOKEN)) {
      const idToken = await generateIdToken(c, user.id, client.client_id, authRequest.nonce);
      params.set('id_token', idToken);
    }
    
    params.set('scope', validScope);
    
    if (authRequest.state) {
      params.set('state', authRequest.state);
    }
    
    // フラグメント形式でリダイレクト
    return Response.redirect(`${authRequest.redirect_uri}#${params.toString()}`, 302);
  } catch (err) {
    console.error('Implicit flow error:', err);
    return redirectError(
      authRequest.redirect_uri,
      'server_error',
      'Failed to generate tokens',
      authRequest.state
    );
  }
};

// 認可コードフロー完了後の処理（ログインリダイレクト後に使用）
export const resumeAuthorizationFlow = async (c: Context, authSessionKey: string): Promise<Response | null> => {
  try {
    // 保存された認可リクエスト情報を取得
    const sessionData = await c.env.AUTH_STORE.get(authSessionKey);
    
    if (!sessionData) {
      return null;
    }
    
    const authRequest = JSON.parse(sessionData) as AuthorizationRequest;
    
    // セッションを削除
    await c.env.AUTH_STORE.delete(authSessionKey);
    
    // クライアント情報の取得
    const client = await getClient(c, authRequest.client_id);
    
    if (!client) {
      return c.json({ error: 'invalid_client', error_description: 'Client not found' }, 400);
    }
    
    // ユーザー情報を取得
    // @ts-ignore - TypeScriptエラーを回避するためのアノテーション
    const user = c.req.user;
    
    if (!user) {
      return c.json({ error: 'access_denied', error_description: 'User authentication required' }, 401);
    }
    
    // スコープは既に検証済み
    const validScope = authRequest.scope;
    
    // response_typeに応じた処理
    switch (authRequest.response_type) {
      case ResponseType.CODE:
        return await handleAuthorizationCodeFlow(c, user, client, authRequest, validScope);
        
      case ResponseType.ID_TOKEN:
      case `${ResponseType.ID_TOKEN} ${ResponseType.TOKEN}`:
      case ResponseType.TOKEN:
        return await handleImplicitFlow(c, user, client, authRequest, validScope);
        
      default:
        return redirectError(
          authRequest.redirect_uri,
          'unsupported_response_type',
          'Response type not supported',
          authRequest.state
        );
    }
  } catch (err) {
    console.error('Resume authorization flow error:', err);
    return c.json({ error: 'server_error', error_description: 'Failed to resume authorization flow' }, 500);
  }
};

// 構成情報の公開
export const getOpenIDConfiguration = (c: Context): any => {
  const issuer = c.env.ISSUER_BASE_URL || `https://${c.req.header('host')}`;
  
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    registration_endpoint: `${issuer}/register`,
    scopes_supported: [
      OIDCScope.OPENID,
      OIDCScope.PROFILE,
      OIDCScope.EMAIL,
      OIDCScope.ADDRESS,
      OIDCScope.PHONE,
      OIDCScope.OFFLINE_ACCESS
    ],
    response_types_supported: [
      'code',
      'token',
      'id_token',
      'id_token token',
      'code id_token',
      'code token',
      'code id_token token'
    ],
    grant_types_supported: [
      'authorization_code',
      'implicit',
      'refresh_token',
      'client_credentials'
    ],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256', 'RS256'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none'
    ],
    claims_supported: [
      'sub',
      'iss',
      'auth_time',
      'acr',
      'name',
      'given_name',
      'family_name',
      'nickname',
      'preferred_username',
      'profile',
      'picture',
      'website',
      'email',
      'email_verified',
      'gender',
      'birthdate',
      'zoneinfo',
      'locale',
      'phone_number',
      'phone_number_verified',
      'address',
      'updated_at'
    ],
    code_challenge_methods_supported: ['plain', 'S256']
  };
};