import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { authMiddleware } from './middleware/auth';
import { debugMiddleware } from './middleware/debug';
import { 
  loginHandler, 
  logoutHandler, 
  registerHandler,
  completeMFAHandler,
  loginWithRecoveryCodeHandler 
} from './auth/login';
import { refreshTokenHandler } from './auth/jwt';
import { 
  initMFAHandler, 
  verifyAndEnableMFAHandler, 
  disableMFAHandler, 
  regenerateRecoveryCodesHandler 
} from './auth/mfa';

// OIDC関連のインポート
import { 
  handleAuthorizationRequest,
  resumeAuthorizationFlow,
  getOpenIDConfiguration
} from './oidc/authorize';
import { handleTokenRequest, getJwks } from './oidc/token';
import { handleUserInfoRequest } from './oidc/userinfo';
import { 
  registerClient,
  updateClient,
  deleteClient,
  getClient,
  validateRedirectUri 
} from './oidc/client';

// 環境変数の型定義
interface Env {
  AUTH_STORE: KVNamespace;
  JWT_SECRET: string;
  ISSUER_BASE_URL?: string;
  [key: string]: any;
}

// アプリケーションの作成
const app = new Hono<{ Bindings: Env }>();

// ミドルウェアの設定
app.use('*', logger());
app.use('*', debugMiddleware);
app.use('*', secureHeaders());
app.use('*', cors({
  origin: '*', // 本番環境では制限する
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  exposeHeaders: ['Content-Length'],
  maxAge: 86400,
}));

// ヘルスチェック用のエンドポイント
app.get('/', (c) => {
  return c.json({ status: 'ok', message: 'OIDC Auth Service is running' });
});

// OIDC Discovery エンドポイント
app.get('/.well-known/openid-configuration', (c) => {
  return c.json(getOpenIDConfiguration(c));
});

// JWKS エンドポイント
app.get('/.well-known/jwks.json', async (c) => {
  return c.json(await getJwks(c));
});

// 認可エンドポイント
app.get('/authorize', async (c) => {
  return await handleAuthorizationRequest(c);
});

// 認可フロー再開処理（ログイン後）
app.get('/auth/resume', authMiddleware, async (c) => {
  const authSessionKey = c.req.query('auth_session');
  
  if (!authSessionKey) {
    return c.json({ error: 'invalid_request', error_description: 'Missing auth_session parameter' }, 400);
  }
  
  const response = await resumeAuthorizationFlow(c, authSessionKey);
  
  if (!response) {
    return c.json({ error: 'invalid_request', error_description: 'Invalid or expired auth session' }, 400);
  }
  
  return response;
});

// トークンエンドポイント
app.post('/token', async (c) => {
  return await handleTokenRequest(c);
});

// ユーザー情報エンドポイント
app.get('/userinfo', async (c) => {
  return await handleUserInfoRequest(c);
});

// 認証関連のレガシーエンドポイント
app.post('/register', registerHandler);
app.post('/login', loginHandler);
app.post('/logout', logoutHandler);
app.post('/refresh', refreshTokenHandler);

// MFA関連のレガシーエンドポイント
app.post('/auth/mfa/complete', completeMFAHandler);
app.post('/auth/login/recovery', loginWithRecoveryCodeHandler);

// 保護されたルート（認証が必要）
const protectedRoutes = new Hono<{ Bindings: Env }>();
protectedRoutes.use('*', authMiddleware);

// 保護されたエンドポイントの例
protectedRoutes.get('/user', async (c) => {
  try {
    // @ts-ignore
    const user = c.req.user;
    
    return c.json({ 
      user: user || { message: 'User not authenticated' },
      authenticated: !!user
    });
  } catch (err) {
    console.error('Error in protected route:', err);
    return c.json({ error: 'Failed to retrieve user data' }, 500);
  }
});

// MFA管理用の保護されたルート
protectedRoutes.post('/mfa/init', initMFAHandler);
protectedRoutes.post('/mfa/verify', verifyAndEnableMFAHandler);
protectedRoutes.post('/mfa/disable', disableMFAHandler);
protectedRoutes.post('/mfa/recovery/regenerate', regenerateRecoveryCodesHandler);

// クライアント管理用の保護されたルート
const clientRoutes = new Hono<{ Bindings: Env }>();
clientRoutes.use('*', authMiddleware);

// クライアント登録
clientRoutes.post('/', async (c) => {
  try {
    const clientData = await c.req.json();
    const client = await registerClient(c, clientData);
    
    return c.json({ 
      message: 'Client registered successfully',
      client_id: client.client_id,
      client_secret: client.client_secret,
      client
    }, 201);
  } catch (err) {
    console.error('Client registration error:', err);
    return c.json({ error: 'Failed to register client' }, 500);
  }
});

// クライアント取得
clientRoutes.get('/:clientId', async (c) => {
  try {
    const clientId = c.req.param('clientId');
    const client = await getClient(c, clientId);
    
    if (!client) {
      return c.json({ error: 'Client not found' }, 404);
    }
    
    // クライアントシークレットを隠す
    const { client_secret, ...clientWithoutSecret } = client;
    
    return c.json(clientWithoutSecret);
  } catch (err) {
    console.error('Client retrieval error:', err);
    return c.json({ error: 'Failed to retrieve client' }, 500);
  }
});

// クライアント更新
clientRoutes.put('/:clientId', async (c) => {
  try {
    const clientId = c.req.param('clientId');
    const updates = await c.req.json();
    
    const updatedClient = await updateClient(c, clientId, updates);
    
    if (!updatedClient) {
      return c.json({ error: 'Client not found' }, 404);
    }
    
    // クライアントシークレットを隠す
    const { client_secret, ...clientWithoutSecret } = updatedClient;
    
    return c.json({
      message: 'Client updated successfully',
      client: clientWithoutSecret
    });
  } catch (err) {
    console.error('Client update error:', err);
    return c.json({ error: 'Failed to update client' }, 500);
  }
});

// クライアント削除
clientRoutes.delete('/:clientId', async (c) => {
  try {
    const clientId = c.req.param('clientId');
    const deleted = await deleteClient(c, clientId);
    
    if (!deleted) {
      return c.json({ error: 'Client not found' }, 404);
    }
    
    return c.json({ message: 'Client deleted successfully' });
  } catch (err) {
    console.error('Client deletion error:', err);
    return c.json({ error: 'Failed to delete client' }, 500);
  }
});

// クライアント管理ルートをマウント
app.route('/register/clients', clientRoutes);

// 保護されたルートをマウント
app.route('/api', protectedRoutes);

// エラーハンドリング
app.onError((err, c) => {
  console.error(`Error:`, err);
  // 開発環境ではエラーの詳細を返す
  const isDev = c.env.DEBUG === 'true';
  return c.json({ 
    error: 'Internal Server Error', 
    message: isDev ? String(err) : undefined,
    stack: isDev ? err.stack : undefined
  }, 500);
});

// 404ハンドリング
app.notFound((c) => {
  return c.json({ error: 'Not Found' }, 404);
});

export default app;