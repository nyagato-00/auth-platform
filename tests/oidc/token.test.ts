// tests/oidc/token.test.ts
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { 
  generateAccessToken, 
  generateIdToken, 
  generateRefreshToken,
  generateAuthorizationCode,
  exchangeAuthorizationCode,
  getIssuer
} from '../../src/oidc/token';
import { sign, verify } from 'hono/jwt';

// モックの Context
const createMockContext = () => {
  const mockEnv = {
    AUTH_STORE: {
      put: vi.fn(),
      get: vi.fn(),
      delete: vi.fn()
    },
    JWT_SECRET: 'test-secret-key',
    ISSUER_BASE_URL: 'https://auth.example.com'
  };
  
  return {
    env: mockEnv,
    json: vi.fn(),
    req: {
      header: vi.fn().mockReturnValue('auth.example.com')
    }
  };
};

// JWTモック
vi.mock('hono/jwt', () => ({
  sign: vi.fn().mockImplementation((payload, secret) => {
    return Promise.resolve(`mocked-jwt-token-${payload.sub}`);
  }),
  verify: vi.fn().mockImplementation((token, secret) => {
    if (token.startsWith('valid-token')) {
      return Promise.resolve({
        sub: 'test-user-id',
        client_id: 'test-client-id',
        scope: 'openid profile',
        type: token.includes('refresh') ? 'refresh' : undefined
      });
    } else {
      return Promise.reject(new Error('Invalid token'));
    }
  })
}));

describe('OIDC Token Functions', () => {
  let mockContext: any;
  
  beforeEach(() => {
    mockContext = createMockContext();
    vi.clearAllMocks();
  });
  
  describe('generateAccessToken', () => {
    it('should generate an access token', async () => {
      const accessToken = await generateAccessToken(
        mockContext,
        'test-user-id',
        'test-client-id',
        'openid profile'
      );
      
      expect(accessToken).toBe('mocked-jwt-token-test-user-id');
      expect(sign).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: 'https://auth.example.com',
          sub: 'test-user-id',
          client_id: 'test-client-id',
          scope: 'openid profile'
        }),
        'test-secret-key'
      );
    });
  });
  
  describe('generateIdToken', () => {
    it('should generate an ID token', async () => {
      // モックユーザープロファイル
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify({
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        mfaEnabled: true
      }));
      
      const idToken = await generateIdToken(
        mockContext,
        'test-user-id',
        'test-client-id',
        'test-nonce'
      );
      
      expect(idToken).toBe('mocked-jwt-token-test-user-id');
      expect(sign).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: 'https://auth.example.com',
          sub: 'test-user-id',
          aud: 'test-client-id',
          nonce: 'test-nonce',
          name: 'testuser',
          email: 'test@example.com',
          amr: ['mfa'],
          acr: '2'
        }),
        'test-secret-key'
      );
    });
    
    it('should handle user without MFA', async () => {
      // モックユーザープロファイル（MFA無効）
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify({
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        mfaEnabled: false
      }));
      
      const idToken = await generateIdToken(
        mockContext,
        'test-user-id',
        'test-client-id'
      );
      
      expect(idToken).toBe('mocked-jwt-token-test-user-id');
      expect(sign).toHaveBeenCalledWith(
        expect.objectContaining({
          amr: ['pwd'],
          acr: '1'
        }),
        'test-secret-key'
      );
    });
    
    it('should throw error when user not found', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      await expect(generateIdToken(
        mockContext,
        'non-existent-user',
        'test-client-id'
      )).rejects.toThrow('User not found');
    });
  });
  
  describe('generateRefreshToken', () => {
    it('should generate a refresh token and store it', async () => {
      const refreshToken = await generateRefreshToken(
        mockContext,
        'test-user-id',
        'test-client-id',
        'openid profile offline_access'
      );
      
      expect(refreshToken).toBe('mocked-jwt-token-test-user-id');
      expect(sign).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: 'https://auth.example.com',
          sub: 'test-user-id',
          client_id: 'test-client-id',
          scope: 'openid profile offline_access',
          type: 'refresh'
        }),
        'test-secret-key'
      );
      
      // KVストアに保存されたことを確認
      expect(mockContext.env.AUTH_STORE.put).toHaveBeenCalledTimes(1);
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][0]).toMatch(/^refresh_token:/);
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][1]).toContain('test-user-id');
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][1]).toContain('test-client-id');
    });
  });
  
  describe('generateAuthorizationCode', () => {
    it('should generate and store an authorization code', async () => {
      const authData = {
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid profile',
        user_id: 'test-user-id',
        nonce: 'test-nonce',
        state: 'test-state'
      };
      
      const code = await generateAuthorizationCode(mockContext, authData);
      
      expect(code).toBeDefined();
      expect(code.length).toBeGreaterThan(0);
      
      // KVストアに保存されたことを確認
      expect(mockContext.env.AUTH_STORE.put).toHaveBeenCalledTimes(1);
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][0]).toMatch(/^auth_code:/);
      
      const storedData = JSON.parse(mockContext.env.AUTH_STORE.put.mock.calls[0][1]);
      expect(storedData.client_id).toBe('test-client-id');
      expect(storedData.redirect_uri).toBe('https://example.com/callback');
      expect(storedData.user_id).toBe('test-user-id');
      expect(storedData.nonce).toBe('test-nonce');
      expect(storedData.state).toBe('test-state');
      expect(storedData.code).toBe(code);
      expect(storedData.expires_at).toBeDefined();
    });
  });
  
  describe('exchangeAuthorizationCode', () => {
    it('should return null when code does not exist', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      const result = await exchangeAuthorizationCode(
        mockContext,
        'invalid-code',
        'test-client-id',
        'https://example.com/callback'
      );
      
      expect(result).toBeNull();
      expect(mockContext.env.AUTH_STORE.get).toHaveBeenCalledWith('auth_code:invalid-code');
      expect(mockContext.env.AUTH_STORE.delete).not.toHaveBeenCalled();
    });
    
    it('should return null when code has expired', async () => {
      const expiredCode = {
        code: 'expired-code',
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid',
        user_id: 'test-user-id',
        expires_at: Math.floor(Date.now() / 1000) - 60 // 1分前に期限切れ
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(expiredCode));
      
      const result = await exchangeAuthorizationCode(
        mockContext,
        'expired-code',
        'test-client-id',
        'https://example.com/callback'
      );
      
      expect(result).toBeNull();
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('auth_code:expired-code');
    });
    
    it('should return null when client ID does not match', async () => {
      const authCode = {
        code: 'valid-code',
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid',
        user_id: 'test-user-id',
        expires_at: Math.floor(Date.now() / 1000) + 600 // 10分後に期限切れ
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(authCode));
      
      const result = await exchangeAuthorizationCode(
        mockContext,
        'valid-code',
        'wrong-client-id',
        'https://example.com/callback'
      );
      
      expect(result).toBeNull();
      expect(mockContext.env.AUTH_STORE.delete).not.toHaveBeenCalled();
    });
    
    it('should return null when redirect URI does not match', async () => {
      const authCode = {
        code: 'valid-code',
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid',
        user_id: 'test-user-id',
        expires_at: Math.floor(Date.now() / 1000) + 600 // 10分後に期限切れ
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(authCode));
      
      const result = await exchangeAuthorizationCode(
        mockContext,
        'valid-code',
        'test-client-id',
        'https://wrong-site.com/callback'
      );
      
      expect(result).toBeNull();
      expect(mockContext.env.AUTH_STORE.delete).not.toHaveBeenCalled();
    });
    
    it('should validate PKCE when code challenge is set', async () => {
      const authCode = {
        code: 'valid-code',
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid',
        user_id: 'test-user-id',
        expires_at: Math.floor(Date.now() / 1000) + 600, // 10分後に期限切れ
        code_challenge: 'test-challenge',
        code_challenge_method: 'plain'
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(authCode));
      
      // 無効なコードベリファイアー
      const resultWithInvalidVerifier = await exchangeAuthorizationCode(
        mockContext,
        'valid-code',
        'test-client-id',
        'https://example.com/callback',
        'wrong-verifier'
      );
      
      expect(resultWithInvalidVerifier).toBeNull();
      
      // 有効なコードベリファイアー
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(authCode));
      
      const resultWithValidVerifier = await exchangeAuthorizationCode(
        mockContext,
        'valid-code',
        'test-client-id',
        'https://example.com/callback',
        'test-challenge'
      );
      
      expect(resultWithValidVerifier).toEqual(authCode);
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('auth_code:valid-code');
    });
    
    it('should exchange a valid authorization code', async () => {
      const authCode = {
        code: 'valid-code',
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        scope: 'openid profile',
        user_id: 'test-user-id',
        expires_at: Math.floor(Date.now() / 1000) + 600, // 10分後に期限切れ
        nonce: 'test-nonce',
        state: 'test-state'
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(authCode));
      
      const result = await exchangeAuthorizationCode(
        mockContext,
        'valid-code',
        'test-client-id',
        'https://example.com/callback'
      );
      
      expect(result).toEqual(authCode);
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('auth_code:valid-code');
    });
  });
  
  describe('getIssuer', () => {
    it('should return ISSUER_BASE_URL when set', () => {
      const issuer = getIssuer(mockContext);
      expect(issuer).toBe('https://auth.example.com');
    });
    
    it('should construct issuer from host when ISSUER_BASE_URL not set', () => {
      // ISSUER_BASE_URL を削除
      delete mockContext.env.ISSUER_BASE_URL;
      
      const issuer = getIssuer(mockContext);
      expect(issuer).toBe('https://auth.example.com');
    });
  });
});