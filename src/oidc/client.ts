// src/oidc/client.ts
// OIDC クライアント管理

import { Context } from 'hono';
import { OIDCClient, GrantType, ResponseType, TokenEndpointAuthMethod } from './types';

// クライアント ID の生成
export const generateClientId = (): string => {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

// クライアントシークレットの生成
export const generateClientSecret = (): string => {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

// クライアント登録
export const registerClient = async (c: Context, clientData: Partial<OIDCClient>): Promise<OIDCClient> => {
  // クライアント ID とシークレットの生成
  const client_id = generateClientId();
  const client_secret = generateClientSecret();
  
  // デフォルト値を設定
  const client: OIDCClient = {
    client_id,
    client_secret,
    redirect_uris: clientData.redirect_uris || [],
    grant_types: clientData.grant_types || [GrantType.AUTHORIZATION_CODE],
    response_types: clientData.response_types || [ResponseType.CODE],
    scopes: clientData.scopes || ['openid', 'profile', 'email'],
    token_endpoint_auth_method: clientData.token_endpoint_auth_method || TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
    client_name: clientData.client_name,
    client_uri: clientData.client_uri,
    logo_uri: clientData.logo_uri,
    created_at: new Date().toISOString(),
  };
  
  // Cloudflare KV に保存
  const clientKey = `client:${client_id}`;
  await c.env.AUTH_STORE.put(clientKey, JSON.stringify(client));
  
  return client;
};

// クライアント取得
export const getClient = async (c: Context, clientId: string): Promise<OIDCClient | null> => {
  const clientKey = `client:${clientId}`;
  const clientJson = await c.env.AUTH_STORE.get(clientKey);
  
  if (!clientJson) {
    return null;
  }
  
  return JSON.parse(clientJson) as OIDCClient;
};

// クライアント更新
export const updateClient = async (c: Context, clientId: string, updates: Partial<OIDCClient>): Promise<OIDCClient | null> => {
  const client = await getClient(c, clientId);
  
  if (!client) {
    return null;
  }
  
  // 更新可能なフィールドのみを更新
  const updatedClient: OIDCClient = {
    ...client,
    redirect_uris: updates.redirect_uris || client.redirect_uris,
    grant_types: updates.grant_types || client.grant_types,
    response_types: updates.response_types || client.response_types,
    scopes: updates.scopes || client.scopes,
    token_endpoint_auth_method: updates.token_endpoint_auth_method || client.token_endpoint_auth_method,
    client_name: updates.client_name || client.client_name,
    client_uri: updates.client_uri || client.client_uri,
    logo_uri: updates.logo_uri || client.logo_uri,
    updated_at: new Date().toISOString(),
  };
  
  // Cloudflare KV に保存
  const clientKey = `client:${clientId}`;
  await c.env.AUTH_STORE.put(clientKey, JSON.stringify(updatedClient));
  
  return updatedClient;
};

// クライアント削除
export const deleteClient = async (c: Context, clientId: string): Promise<boolean> => {
  const clientKey = `client:${clientId}`;
  
  // クライアントが存在するか確認
  const clientExists = await c.env.AUTH_STORE.get(clientKey);
  
  if (!clientExists) {
    return false;
  }
  
  // Cloudflare KV から削除
  await c.env.AUTH_STORE.delete(clientKey);
  
  return true;
};

// クライアント認証
export const authenticateClient = async (c: Context, clientId: string, clientSecret: string): Promise<boolean> => {
  const client = await getClient(c, clientId);
  
  if (!client) {
    return false;
  }
  
  return client.client_secret === clientSecret;
};

// クライアントリダイレクトURI検証
export const validateRedirectUri = (client: OIDCClient, redirectUri: string): boolean => {
  return client.redirect_uris.includes(redirectUri);
};

// クライアントスコープ検証
export const validateScope = (client: OIDCClient, requestedScope: string): string => {
  const requestedScopes = requestedScope.split(' ');
  const allowedScopes = client.scopes;
  
  // 許可されたスコープのみをフィルタリング
  const validScopes = requestedScopes.filter(scope => allowedScopes.includes(scope));
  
  // 有効なスコープがない場合は、デフォルトのスコープを使用
  if (validScopes.length === 0) {
    return 'openid';
  }
  
  // openid スコープが含まれていない場合は追加
  if (!validScopes.includes('openid')) {
    validScopes.unshift('openid');
  }
  
  return validScopes.join(' ');
};
