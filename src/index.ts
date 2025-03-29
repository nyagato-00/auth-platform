import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { authMiddleware } from './middleware/auth';
import { debugMiddleware } from './middleware/debug'; // デバッグミドルウェアをインポート
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

// 環境変数の型定義
interface Env {
  AUTH_STORE: KVNamespace;
  JWT_SECRET: string;
  [key: string]: any; // インデックスシグネチャを追加
}

// アプリケーションの作成
const app = new Hono<{ Bindings: Env }>();

// ミドルウェアの設定
app.use('*', logger());
app.use('*', debugMiddleware); // デバッグミドルウェアを追加
app.use('*', secureHeaders());
app.use('*', cors({
  origin: [
    'https://auth-platform.nyagato-eva.workers.dev', 
    'https://auth-test-client.pages.dev',
  ],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  exposeHeaders: ['Content-Length'],
  maxAge: 86400,
}));

// 認証関連のルート
app.post('/register', registerHandler);
app.post('/login', loginHandler);
app.post('/logout', logoutHandler);
app.post('/refresh', refreshTokenHandler);

// MFA関連のルート
app.post('/auth/mfa/complete', completeMFAHandler);
app.post('/auth/login/recovery', loginWithRecoveryCodeHandler);

// 保護されたルート（認証が必要）
const protectedRoutes = new Hono<{ Bindings: Env }>();
protectedRoutes.use('*', authMiddleware);

// 保護されたエンドポイントの例
protectedRoutes.get('/user', async (c) => {
  try {
    // @ts-ignore - TypeScriptエラーを回避するためのアノテーション
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

// 保護されたルートをマウント
app.route('/api', protectedRoutes);

// ヘルスチェック用のエンドポイント
app.get('/', (c) => {
  return c.json({ status: 'ok', message: 'Auth Service is running' });
});

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