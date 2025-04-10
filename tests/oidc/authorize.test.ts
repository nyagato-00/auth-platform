// tests/oidc/authorize.test.ts
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { Context } from 'hono';
import { 
  validateAuthorizationRequest,
  handleAuthorizationRequest,
  resumeAuthorizationFlow,
  getOpenIDConfiguration
} from '../../src/oidc/authorize';
import { OIDCScope, ResponseType } from '../../src/oidc/types';

// モックのインポート
vi.mock('../../src/oidc/client', () => ({
  getClient: vi.fn().mockImplementation((c, clientId) => {
    if (clientId === 'valid-client-id') {
      return Promise.resolve({
        client_id: 'valid-client-id',
        client_secret: 'client-secret',
        redirect_uris: ['https://example.com/callback', 'https://app.example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code', 'token', 'id_token', 'id_token token'],
        scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: 'client_secret_basic',
        created_at: new Date().toISOString()
      });
    } else if (clientId === 'code-only-client') {
      return Promise.resolve({
        client_id: 'code-only-client',
        client_secret: 'client-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile'],
        token_endpoint_auth_method: 'client_secret_basic',
        created_at: new Date().toISOString()
      });
    } else {
      return Promise.resolve(null);
    }
  }),
  validateRedirectUri: vi.fn().mockImplementation((client, redirectUri) => {
    if (!client || !client.redirect_uris) return false;
    return client.redirect_uris.includes(redirectUri);
  }),
  validateScope: vi.fn().mockImplementation((client, requestedScope) => {
    if (!requestedScope) return 'openid';
    const requestedScopes = requestedScope.split(' ');
    const allowedScopes = client.scopes;
    const validScopes = requestedScopes.filter(s => allowedScopes.includes(s));
    
    if (validScopes.length === 0) return 'openid';
    if (!validScopes.includes('openid')) validScopes.unshift('openid');
    
    return validScopes.join(' ');
  })
}));

vi.mock('../../src/oidc/token', () => ({
  generateAuthorizationCode: vi.fn().mockImplementation(() => {
    return Promise.resolve('test-authorization-code');
  }),
  generateAccessToken: vi.fn().mockImplementation(() => {
    return Promise.resolve('test-access-token');
  }),
  generateIdToken: vi.fn().mockImplementation(() => {
    return Promise.resolve('test-id-token');
  })
}));

// モックのContext
// tests/oidc/authorize.test.ts のcreateMockContext関数を修正
const createMockContext = (query = {}) => {
  const mockEnv = {
    AUTH_STORE: {
      put: vi.fn(),
      get: vi.fn(),
      delete: vi.fn()
    },
    ISSUER_BASE_URL: 'https://auth.example.com',
    JWT_SECRET: 'test-secret'
  };
  
  // Honoのコンテキストを模倣するオブジェクトを作成
  return {
    env: mockEnv,
    json: vi.fn().mockImplementation((data, status) => ({ body: data, status })),
    req: {
      query: vi.fn().mockReturnValue(query),
      url: 'https://auth.example.com/authorize',
      header: vi.fn().mockReturnValue('auth.example.com'),
      user: null,
      raw: {
        url: 'https://auth.example.com/authorize'
      }
    },
    // Contextインターフェースの他の必要なプロパティを追加
    finalized: false,
    // #privateプロパティをモック
    get: vi.fn(),
    set: vi.fn(),
    // その他必要なプロパティとメソッド
    var: {},
    _var: {},
    error: null,
    // テスト用に最小限のメソッドを実装
    executionCtx: {},
    res: {
      headers: new Headers()
    },
    // モックのContextとして扱うための型アサーション
  } as unknown as Context;
};

// レスポンスをモック
global.Response = {
  redirect: vi.fn().mockImplementation((url, status) => ({ url, status }))
} as any;

describe('OIDC Authorization Endpoint', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  
  describe('validateAuthorizationRequest', () => {
    it('should require client_id', async () => {
      const mockContext = createMockContext({
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_request',
        error_description: 'client_id is required'
      });
    });
    
    it('should require redirect_uri', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        response_type: 'code',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_request',
        error_description: 'redirect_uri is required'
      });
    });
    
    it('should require response_type', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_request',
        error_description: 'response_type is required'
      });
    });
    
    it('should validate client exists', async () => {
      const mockContext = createMockContext({
        client_id: 'non-existent-client',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_client',
        error_description: 'Client not found'
      });
    });
    
    it('should validate redirect_uri', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://malicious.com/callback',
        response_type: 'code',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_redirect_uri',
        error_description: 'Invalid redirect URI'
      });
    });
    
    it('should validate response_type', async () => {
      const mockContext = createMockContext({
        client_id: 'code-only-client',
        redirect_uri: 'https://example.com/callback',
        response_type: 'token',
        scope: 'openid'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'unsupported_response_type',
        error_description: 'Response type not supported for this client'
      });
      expect(result.client).toBeDefined();
    });
    
    it('should validate PKCE parameters', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid',
        code_challenge_method: 'S256'
        // code_challenge が欠けている
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(false);
      expect(result.error).toEqual({
        error: 'invalid_request',
        error_description: 'code_challenge is required when code_challenge_method is provided'
      });
    });
    
    it('should return valid result for valid request', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid profile',
        state: 'test-state'
      });
      
      const result = await validateAuthorizationRequest(mockContext);
      
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.client).toBeDefined();
      expect(result.client.client_id).toBe('valid-client-id');
    });
  });
  
  describe('handleAuthorizationRequest', () => {
    it('should redirect to login when user is not authenticated', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid profile',
        state: 'test-state'
      });
      
      mockContext.env.AUTH_STORE.put.mockResolvedValue(undefined);
      
      const response = await handleAuthorizationRequest(mockContext);
      
      expect(Response.redirect).toHaveBeenCalled();
      expect(mockContext.env.AUTH_STORE.put).toHaveBeenCalled();
      
      // リダイレクトURLがログインページを指しているか確認
      const redirectUrl = (Response.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toMatch(/^https:\/\/auth\.example\.com\/login\?auth_session=/);
    });
    
    it('should handle authorization code flow for authenticated user', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid profile',
        state: 'test-state'
      });
      
      // ユーザーを認証済みに設定
      mockContext.req.user = {
        id: 'test-user-id',
        username: 'testuser'
      };
      
      const response = await handleAuthorizationRequest(mockContext);
      
      expect(Response.redirect).toHaveBeenCalled();
      
      // リダイレクトURLに認可コードとステートが含まれているか確認
      const redirectUrl = (Response.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toMatch(/^https:\/\/example\.com\/callback\?code=test-authorization-code&state=test-state$/);
    });
    
    it('should handle implicit flow for authenticated user', async () => {
      const mockContext = createMockContext({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'id_token token',
        scope: 'openid profile',
        state: 'test-state',
        nonce: 'test-nonce'
      });
      
      // ユーザーを認証済みに設定
      mockContext.req.user = {
        id: 'test-user-id',
        username: 'testuser'
      };
      
      const response = await handleAuthorizationRequest(mockContext);
      
      expect(Response.redirect).toHaveBeenCalled();
      
      // リダイレクトURLにトークンとステートが含まれているか確認（フラグメント形式）
      const redirectUrl = (Response.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toMatch(/^https:\/\/example\.com\/callback#/);
      expect(redirectUrl).toContain('access_token=test-access-token');
      expect(redirectUrl).toContain('id_token=test-id-token');
      expect(redirectUrl).toContain('state=test-state');
    });
    
    it('should handle validation errors with redirect', async () => {
      const mockContext = createMockContext({
        client_id: 'code-only-client',
        redirect_uri: 'https://example.com/callback',
        response_type: 'token', // 対応していないレスポンスタイプ
        scope: 'openid profile',
        state: 'test-state'
      });
      
      const response = await handleAuthorizationRequest(mockContext);
      
      expect(Response.redirect).toHaveBeenCalled();
      
      // エラーパラメータを含むリダイレクトURLであることを確認
      const redirectUrl = (Response.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toMatch(/^https:\/\/example\.com\/callback\?error=unsupported_response_type/);
      expect(redirectUrl).toContain('state=test-state');
    });
    
    it('should return direct error when client validation fails', async () => {
      const mockContext = createMockContext({
        client_id: 'non-existent-client',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid'
      });
      
      const response = await handleAuthorizationRequest(mockContext);
      
      expect(Response.redirect).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'invalid_client',
          error_description: 'Client not found'
        }),
        400
      );
    });
  });
  
  describe('resumeAuthorizationFlow', () => {
    it('should return null when auth session does not exist', async () => {
      const mockContext = createMockContext();
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      const result = await resumeAuthorizationFlow(mockContext, 'non-existent-session');
      
      expect(result).toBeNull();
      // 修正: authSessionKeyをそのまま使用しているため、接頭辞をつけない
      expect(mockContext.env.AUTH_STORE.get).toHaveBeenCalledWith('non-existent-session');
    });
    
    it('should resume authorization code flow', async () => {
      const mockContext = createMockContext();
      
      // 認証済みユーザーを設定
      mockContext.req.user = {
        id: 'test-user-id',
        username: 'testuser'
      };
      
      // 保存された認可リクエスト情報をモック
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid profile',
        state: 'test-state'
      }));
      
      const response = await resumeAuthorizationFlow(mockContext, 'test-session');
      
      // 修正: authSessionKeyをそのまま使用しているため、接頭辞をつけない
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('test-session');
      expect(Response.redirect).toHaveBeenCalled();
      
      // リダイレクトURLに認可コードとステートが含まれているか確認
      const redirectUrl = (Response.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toMatch(/^https:\/\/example\.com\/callback\?code=test-authorization-code&state=test-state$/);
    });
    
    it('should return error when user is not authenticated', async () => {
      const mockContext = createMockContext();
      
      // ユーザーは認証されていない（デフォルト）
      
      // 保存された認可リクエスト情報をモック
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify({
        client_id: 'valid-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        scope: 'openid profile',
        state: 'test-state'
      }));
      
      const response = await resumeAuthorizationFlow(mockContext, 'test-session');
      
      // 修正: authSessionKeyをそのまま使用しているため、接頭辞をつけない
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('test-session');
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'access_denied',
          error_description: 'User authentication required'
        }),
        401
      );
    });
  });
  
  describe('getOpenIDConfiguration', () => {
    it('should return complete OIDC configuration', () => {
      const mockContext = createMockContext();
      
      const config = getOpenIDConfiguration(mockContext);
      
      expect(config.issuer).toBe('https://auth.example.com');
      expect(config.authorization_endpoint).toBe('https://auth.example.com/authorize');
      expect(config.token_endpoint).toBe('https://auth.example.com/token');
      expect(config.userinfo_endpoint).toBe('https://auth.example.com/userinfo');
      expect(config.jwks_uri).toBe('https://auth.example.com/.well-known/jwks.json');
      
      // 必須のスコープとレスポンスタイプを確認
      expect(config.scopes_supported).toContain(OIDCScope.OPENID);
      expect(config.scopes_supported).toContain(OIDCScope.PROFILE);
      expect(config.scopes_supported).toContain(OIDCScope.EMAIL);
      
      expect(config.response_types_supported).toContain(ResponseType.CODE);
      expect(config.response_types_supported).toContain(ResponseType.TOKEN);
      expect(config.response_types_supported).toContain(ResponseType.ID_TOKEN);
      
      // その他の必須フィールドを確認
      expect(config.subject_types_supported).toBeDefined();
      expect(config.id_token_signing_alg_values_supported).toBeDefined();
      expect(config.claims_supported).toBeDefined();
      expect(config.token_endpoint_auth_methods_supported).toBeDefined();
    });
  });
});