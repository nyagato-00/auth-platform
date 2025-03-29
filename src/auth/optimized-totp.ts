// src/auth/optimized-totp.ts
// Cloudflare Workers向けに最適化されたTOTP実装
// 参考: https://gist.github.com/ashishjullia/49e049688ac84b298fefbf0acd52246d

/**
 * Base32のデコード関数
 * @param base32 Base32エンコードされた文字列
 * @returns デコードされたUint8Array
 */
export function base32Decode(base32: string): Uint8Array {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  
  // 入力を正規化（大文字に変換し、無効な文字を削除）
  const normalized = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  
  // パディングの処理
  let padded = normalized;
  while (padded.length % 8 !== 0) {
    padded += '=';
  }
  
  const bytes = new Uint8Array(Math.floor(padded.length * 5 / 8));
  
  let currentByte = 0;
  let validBits = 0;
  let byteIndex = 0;
  
  for (let i = 0; i < normalized.length; i++) {
    const charValue = CHARS.indexOf(normalized[i]);
    if (charValue === -1) continue;
    
    // 5ビットの値を追加
    currentByte = (currentByte << 5) | charValue;
    validBits += 5;
    
    // 8ビット以上あれば、1バイト出力
    if (validBits >= 8) {
      validBits -= 8;
      bytes[byteIndex++] = (currentByte >> validBits) & 0xFF;
    }
  }
  
  return bytes;
}

/**
 * Base32エンコード関数
 * @param bytes エンコードするバイト配列
 * @returns Base32エンコードされた文字列
 */
export function base32Encode(bytes: Uint8Array): string {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  
  let result = '';
  let currentByte = 0;
  let validBits = 0;
  
  for (let i = 0; i < bytes.length; i++) {
    // 8ビットを追加
    currentByte = (currentByte << 8) | bytes[i];
    validBits += 8;
    
    // 5ビット以上あれば、1文字出力
    while (validBits >= 5) {
      validBits -= 5;
      const charIndex = (currentByte >> validBits) & 0x1F;
      result += CHARS[charIndex];
    }
  }
  
  // 残りのビットがあれば処理
  if (validBits > 0) {
    const charIndex = (currentByte << (5 - validBits)) & 0x1F;
    result += CHARS[charIndex];
  }
  
  return result;
}

/**
 * ランダムなTOTPシークレットを生成
 * @returns Base32エンコードされたTOTPシークレット
 */
export function generateTOTPSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * TOTP認証用のURIを生成
 * @param username ユーザー名
 * @param secret TOTPシークレット
 * @param issuer サービス名
 * @returns TOTP URI
 */
export function generateTOTPUri(username: string, secret: string, issuer: string = 'Auth Platform'): string {
  const params = new URLSearchParams({
    secret: secret,
    issuer: issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30'
  });
  
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedUsername = encodeURIComponent(username);
  
  return `otpauth://totp/${encodedIssuer}:${encodedUsername}?${params.toString()}`;
}

/**
 * TOTPコードを生成
 * @param secret TOTPシークレット
 * @param counter カスタムカウンター（通常はタイムスタンプから計算）
 * @returns TOTPコード
 */
export async function generateTOTPCode(
  secret: string,
  counter?: number
): Promise<string> {
  // 現在のカウンター値を計算（30秒ごとに増加）
  if (counter === undefined) {
    counter = Math.floor(Date.now() / 1000 / 30);
  }
  
  // カウンターをバイト配列に変換（8バイト、ビッグエンディアン）
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xFF;
    counter = counter >> 8;
  }
  
  // シークレットをデコード
  const keyBytes = base32Decode(secret);
  
  // HMACキーを作成
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign']
  );
  
  // HMAC-SHA1でハッシュを計算
  const hmacResult = await crypto.subtle.sign('HMAC', key, counterBytes);
  const hmacBytes = new Uint8Array(hmacResult);
  
  // 動的切り捨て
  const offset = hmacBytes[19] & 0x0F;
  const truncatedHash = 
    ((hmacBytes[offset] & 0x7F) << 24) |
    ((hmacBytes[offset + 1] & 0xFF) << 16) |
    ((hmacBytes[offset + 2] & 0xFF) << 8) |
    (hmacBytes[offset + 3] & 0xFF);
  
  // 6桁のコードを生成
  const code = (truncatedHash % 1000000).toString().padStart(6, '0');
  
  return code;
}

/**
 * TOTPコードを検証
 * @param token 検証するTOTPコード
 * @param secret TOTPシークレット
 * @param windowSize 検証する時間窓の数（前後）
 * @returns 検証結果
 */
export async function verifyTOTPCode(
  token: string,
  secret: string,
  windowSize: number = 2
): Promise<boolean> {
  // 入力検証
  if (!token || !/^\d{6}$/.test(token)) {
    return false;
  }
  
  // 現在のカウンター値
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  
  // 前後の時間窓でコードを検証
  for (let window = -windowSize; window <= windowSize; window++) {
    const counter = currentCounter + window;
    const expectedToken = await generateTOTPCode(secret, counter);
    
    if (expectedToken === token) {
      return true;
    }
  }
  
  return false;
}

/**
 * デバッグ用の関数：指定されたシークレットと現在時刻で複数の時間窓のコードを表示
 */
export async function debugTOTPCodes(secret: string): Promise<void> {
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  console.log(`現在のカウンター値: ${currentCounter}`);
  console.log(`時刻: ${new Date().toISOString()}`);
  
  for (let window = -2; window <= 2; window++) {
    const counter = currentCounter + window;
    const code = await generateTOTPCode(secret, counter);
    console.log(`ウィンドウ ${window}: カウンター=${counter}, コード=${code}`);
  }
}
