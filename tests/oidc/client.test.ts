// tests/oidc/client.test.ts
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { 
  generateClientId, 
  generateClientSecret, 
  registerClient, 
  getClient,
  updateClient,
  deleteClient,
  validateRedirectUri,
  validateScope
} from '../../src/oidc/client';
import { OIDCClient, TokenEndpointAuthMethod } from '../../src/oidc/types';

// モックの Context
const createMockContext = () => {
  const mockEnv = {
    AUTH_STORE: {
      put: vi.fn(),
      get: vi.fn(),
      delete: vi.fn()
    }
  };
  
  return {
    env: mockEnv,
    json: vi.fn()
  };
};

describe('OIDC Client Management', () => {
  let mockContext: any;
  
  beforeEach(() => {
    mockContext = createMockContext();
    vi.clearAllMocks();
  });
  
  describe('generateClientId', () => {
    it('should generate a client ID with 32 characters', () => {
      const clientId = generateClientId();
      expect(clientId).toHaveLength(32);
    });
    
    it('should generate unique client IDs', () => {
      const clientId1 = generateClientId();
      const clientId2 = generateClientId();
      expect(clientId1).not.toEqual(clientId2);
    });
  });
  
  describe('generateClientSecret', () => {
    it('should generate a client secret with 64 characters', () => {
      const clientSecret = generateClientSecret();
      expect(clientSecret).toHaveLength(64);
    });
    
    it('should generate unique client secrets', () => {
      const clientSecret1 = generateClientSecret();
      const clientSecret2 = generateClientSecret();
      expect(clientSecret1).not.toEqual(clientSecret2);
    });
  });
  
  describe('registerClient', () => {
    it('should register a client with default values', async () => {
      const clientData: Partial<OIDCClient> = {
        client_name: 'Test Client'
      };
      
      mockContext.env.AUTH_STORE.put.mockResolvedValue(undefined);
      
      const client = await registerClient(mockContext, clientData);
      
      expect(client.client_id).toBeDefined();
      expect(client.client_secret).toBeDefined();
      expect(client.client_name).toEqual('Test Client');
      expect(client.redirect_uris).toEqual([]);
      expect(client.grant_types).toContain('authorization_code');
      expect(client.response_types).toContain('code');
      expect(client.scopes).toContain('openid');
      expect(client.token_endpoint_auth_method).toEqual(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
      expect(client.created_at).toBeDefined();
      
      // Verify KV store was called
      expect(mockContext.env.AUTH_STORE.put).toHaveBeenCalledTimes(1);
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][0]).toMatch(/^client:/);
      expect(mockContext.env.AUTH_STORE.put.mock.calls[0][1]).toContain(client.client_id);
    });
    
    it('should register a client with custom values', async () => {
      const clientData: Partial<OIDCClient> = {
        client_name: 'Custom Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code', 'token'],
        scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_POST
      };
      
      mockContext.env.AUTH_STORE.put.mockResolvedValue(undefined);
      
      const client = await registerClient(mockContext, clientData);
      
      expect(client.client_id).toBeDefined();
      expect(client.client_secret).toBeDefined();
      expect(client.client_name).toEqual('Custom Client');
      expect(client.redirect_uris).toEqual(['https://example.com/callback']);
      expect(client.grant_types).toEqual(['authorization_code', 'refresh_token']);
      expect(client.response_types).toEqual(['code', 'token']);
      expect(client.scopes).toEqual(['openid', 'profile', 'email']);
      expect(client.token_endpoint_auth_method).toEqual(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
      expect(client.created_at).toBeDefined();
    });
  });
  
  describe('getClient', () => {
    it('should return null when client does not exist', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      const client = await getClient(mockContext, 'non-existent-client');
      
      expect(client).toBeNull();
      expect(mockContext.env.AUTH_STORE.get).toHaveBeenCalledWith('client:non-existent-client');
    });
    
    it('should return client when it exists', async () => {
      const mockClient: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        client_name: 'Test Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(mockClient));
      
      const client = await getClient(mockContext, 'test-client-id');
      
      expect(client).toEqual(mockClient);
      expect(mockContext.env.AUTH_STORE.get).toHaveBeenCalledWith('client:test-client-id');
    });
  });
  
  describe('updateClient', () => {
    it('should return null when client does not exist', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      const result = await updateClient(mockContext, 'non-existent-client', {
        client_name: 'Updated Client'
      });
      
      expect(result).toBeNull();
      expect(mockContext.env.AUTH_STORE.get).toHaveBeenCalledWith('client:non-existent-client');
      expect(mockContext.env.AUTH_STORE.put).not.toHaveBeenCalled();
    });
    
    it('should update client and return updated client', async () => {
      const mockClient: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        client_name: 'Test Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify(mockClient));
      mockContext.env.AUTH_STORE.put.mockResolvedValue(undefined);
      
      const updates = {
        client_name: 'Updated Client',
        redirect_uris: ['https://example.com/callback', 'https://app.example.com/oauth']
      };
      
      const updatedClient = await updateClient(mockContext, 'test-client-id', updates);
      
      expect(updatedClient).not.toBeNull();
      expect(updatedClient?.client_id).toEqual('test-client-id');
      expect(updatedClient?.client_name).toEqual('Updated Client');
      expect(updatedClient?.redirect_uris).toEqual(['https://example.com/callback', 'https://app.example.com/oauth']);
      expect(updatedClient?.updated_at).toBeDefined();
      expect(mockContext.env.AUTH_STORE.put).toHaveBeenCalledTimes(1);
    });
  });
  
  describe('deleteClient', () => {
    it('should return false when client does not exist', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(null);
      
      const result = await deleteClient(mockContext, 'non-existent-client');
      
      expect(result).toBe(false);
      expect(mockContext.env.AUTH_STORE.delete).not.toHaveBeenCalled();
    });
    
    it('should delete client and return true when successful', async () => {
      mockContext.env.AUTH_STORE.get.mockResolvedValue(JSON.stringify({ client_id: 'test-client-id' }));
      mockContext.env.AUTH_STORE.delete.mockResolvedValue(undefined);
      
      const result = await deleteClient(mockContext, 'test-client-id');
      
      expect(result).toBe(true);
      expect(mockContext.env.AUTH_STORE.delete).toHaveBeenCalledWith('client:test-client-id');
    });
  });
  
  describe('validateRedirectUri', () => {
    it('should return true when redirect URI is in client redirect URIs', () => {
      const client: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uris: ['https://example.com/callback', 'https://app.example.com/oauth'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      const result = validateRedirectUri(client, 'https://example.com/callback');
      
      expect(result).toBe(true);
    });
    
    it('should return false when redirect URI is not in client redirect URIs', () => {
      const client: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      const result = validateRedirectUri(client, 'https://malicious.com/callback');
      
      expect(result).toBe(false);
    });
  });
  
  describe('validateScope', () => {
    it('should filter out scopes not allowed for client', () => {
      const client: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      const result = validateScope(client, 'openid profile email address phone');
      
      expect(result).toEqual('openid profile email');
    });
    
    it('should add openid scope if not included', () => {
      const client: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      const result = validateScope(client, 'profile email');
      
      expect(result).toEqual('openid profile email');
    });
    
    it('should return default openid scope when no valid scopes', () => {
      const client: OIDCClient = {
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scopes: ['openid', 'profile'],
        token_endpoint_auth_method: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        created_at: new Date().toISOString()
      };
      
      const result = validateScope(client, 'email phone');
      
      expect(result).toEqual('openid');
    });
  });
});