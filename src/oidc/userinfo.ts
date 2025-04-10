// src/oidc/userinfo.ts
// OIDC ユーザー情報エンドポイント

import { Context } from 'hono';
import { verify } from 'hono/jwt';
import { getUserProfile } from '../auth/user';

// スコープからクレームへのマッピング
const SCOPE_TO_CLAIMS_MAPPING: Record<string, string[]> = {
  'profile': [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at'
  ],
  'email': ['email', 'email_verified'],
  'address': ['address'],
  'phone': ['phone_number', 'phone_number_verified']
};

// ユーザー情報エンドポイントハンドラ
export const handleUserInfoRequest = async (c: Context): Promise<Response> => {
  try {
    // Authorizationヘッダーの確認
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'invalid_token', error_description: 'Bearer token is required' }, 401);
    }
    
    const token = authHeader.replace('Bearer ', '');
    
    // アクセストークンの検証
    let payload;
    try {
      payload = await verify(token, c.env.JWT_SECRET);
    } catch (err) {
      return c.json({ error: 'invalid_token', error_description: 'Invalid access token' }, 401);
    }
    
    // スコープの確認
    if (!payload.scope) {
      return c.json({ error: 'insufficient_scope', error_description: 'Token has no scopes' }, 403);
    }
    
    const scopes = payload.scope.split(' ');
    
    // openidスコープがない場合はエラー
    if (!scopes.includes('openid')) {
      return c.json({ error: 'invalid_token', error_description: 'Token must have openid scope' }, 403);
    }
    
    // ユーザー情報の取得
    const userProfile = await getUserProfile(c, payload.sub);
    
    if (!userProfile) {
      return c.json({ error: 'invalid_token', error_description: 'User not found' }, 404);
    }
    
    // ユーザー情報をOIDCクレームにマッピング
    const userInfo: Record<string, any> = {
      sub: payload.sub,
    };
    
    // 各スコープに応じたクレームを追加
    for (const scope of scopes) {
      const claims = SCOPE_TO_CLAIMS_MAPPING[scope] || [];
      for (const claim of claims) {
        // ユーザープロファイルからクレーム値を取得
        addClaimToUserInfo(userInfo, claim, userProfile);
      }
    }
    
    // クレームのマッピング
    return c.json(userInfo);
  } catch (err) {
    console.error('UserInfo endpoint error:', err);
    return c.json({ error: 'server_error', error_description: 'Internal server error' }, 500);
  }
};

// ユーザープロファイルからクレーム値を取得してUserInfoに追加
const addClaimToUserInfo = (userInfo: Record<string, any>, claim: string, userProfile: any): void => {
  switch (claim) {
    case 'name':
      userInfo.name = userProfile.username;
      break;
    case 'email':
      userInfo.email = userProfile.email;
      break;
    case 'email_verified':
      userInfo.email_verified = !!userProfile.emailVerified;
      break;
    case 'preferred_username':
      userInfo.preferred_username = userProfile.username;
      break;
    case 'updated_at':
      userInfo.updated_at = userProfile.updatedAt ? 
        Math.floor(new Date(userProfile.updatedAt).getTime() / 1000) : 
        Math.floor(new Date(userProfile.createdAt).getTime() / 1000);
      break;
    // その他のクレーム...
    default:
      // ユーザープロファイルに直接存在するクレーム
      if (userProfile[claim] !== undefined) {
        userInfo[claim] = userProfile[claim];
      }
  }
};