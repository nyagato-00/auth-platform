// src/oidc/types.ts
// OpenID Connect (OIDC) 関連の型定義

export interface OIDCClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scopes: string[];
  token_endpoint_auth_method: string;
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  created_at: string;
  updated_at?: string;
}

// 認証リクエストパラメータ
export interface AuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  prompt?: string;
  max_age?: number;
  id_token_hint?: string;
  login_hint?: string;
  acr_values?: string;
  display?: string;
  ui_locales?: string;
}

// トークンリクエストパラメータ
export interface TokenRequest {
  grant_type: string;
  code?: string;
  redirect_uri?: string;
  client_id: string;
  client_secret?: string;
  refresh_token?: string;
  code_verifier?: string;
  scope?: string;
}

// IDトークンのクレーム
export interface IDTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string[];
  azp?: string;
  [key: string]: any;
}

// アクセストークンのクレーム
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  client_id: string;
  scope: string;
  [key: string]: any;
}

// 認可コード情報
export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  user_id: string;
  expires_at: number;
  code_challenge?: string;
  code_challenge_method?: string;
  nonce?: string;
  state?: string;
}

// サポートするスコープ
export enum OIDCScope {
  OPENID = "openid",
  PROFILE = "profile",
  EMAIL = "email",
  ADDRESS = "address",
  PHONE = "phone",
  OFFLINE_ACCESS = "offline_access"
}

// サポートする認可フロー
export enum GrantType {
  AUTHORIZATION_CODE = "authorization_code",
  REFRESH_TOKEN = "refresh_token",
  CLIENT_CREDENTIALS = "client_credentials",
  PASSWORD = "password"
}

// レスポンスタイプ
export enum ResponseType {
  CODE = "code",
  TOKEN = "token",
  ID_TOKEN = "id_token"
}

// クライアント認証方式
export enum TokenEndpointAuthMethod {
  CLIENT_SECRET_BASIC = "client_secret_basic",
  CLIENT_SECRET_POST = "client_secret_post",
  CLIENT_SECRET_JWT = "client_secret_jwt",
  PRIVATE_KEY_JWT = "private_key_jwt",
  NONE = "none"
}
