// src/auth/webcrypto-totp.ts
// Web Crypto APIを使用したTOTP実装（Node.jsのcryptoモジュールに依存しない）

/**
 * Base32のデコード関数
 * @param base32 Base32エンコードされた文字列
 * @returns デコードされたUint8Array
 */
export function base32Decode(base32: string): Uint8Array {
  const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanedInput = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  
  const output = new Uint8Array(Math.floor(cleanedInput.length * 5 / 8));
  let bits = 0;
  let bitsCount = 0;
  let outputIndex = 0;
  
  for (let i = 0; i < cleanedInput.length; i++) {
    const charValue = BASE32_CHARS.indexOf(cleanedInput[i]);
    if (charValue === -1) continue;
    
    bits = (bits << 5) | charValue;
    bitsCount += 5;
    
    if (bitsCount >= 8) {
      bitsCount -= 8;
      output[outputIndex++] = (bits >> bitsCount) & 0xff;
    }
  }
  
  return output;
}

/**
 * Base32エンコード関数
 * @param data エンコードする元データ（Uint8Array）
 * @returns Base32エンコードされた文字列
 */
export function base32Encode(data: Uint8Array): string {
  const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let bitsCount = 0;
  
  for (let i = 0; i < data.length; i++) {
    bits = (bits << 8) | data[i];
    bitsCount += 8;
    
    while (bitsCount >= 5) {
      bitsCount -= 5;
      result += BASE32_CHARS[(bits >> bitsCount) & 31];
    }
  }
  
  if (bitsCount > 0) {
    result += BASE32_CHARS[(bits << (5 - bitsCount)) & 31];
  }
  
  return result;
}

/**
 * TOTPシークレットの生成
 * @returns ランダムに生成されたTOTPシークレット
 */
export function generateTOTPSecret(): string {
  const randomBytes = new Uint8Array(20); // 160ビット
  crypto.getRandomValues(randomBytes);
  return base32Encode(randomBytes);
}

/**
 * TOTPコードの生成
 * @param secret TOTPシークレット（Base32）
 * @param timestamp タイムスタンプ（ミリ秒）
 * @param digits コードの桁数
 * @param period 期間（秒）
 * @returns TOTPコード
 */
export async function generateTOTPCode(
  secret: string,
  timestamp: number = Date.now(),
  digits: number = 6,
  period: number = 30
): Promise<string> {
  // カウンターの計算（30秒ごとに増加）
  const counter = Math.floor(timestamp / 1000 / period);
  
  // カウンターをバイト列に変換（8バイト）
  const counterBytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    counterBytes[7 - i] = (counter >>> (i * 8)) & 0xff;
  }
  
  // Base32デコードしたシークレットでHMACキーを作成
  const keyBytes = base32Decode(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign']
  );
  
  // HMAC-SHA1の計算
  const signatureBuffer = await crypto.subtle.sign('HMAC', key, counterBytes);
  const signatureBytes = new Uint8Array(signatureBuffer);
  
  // 動的切り捨て
  const offset = signatureBytes[signatureBytes.length - 1] & 0x0f;
  const binary = 
    ((signatureBytes[offset] & 0x7f) << 24) |
    ((signatureBytes[offset + 1] & 0xff) << 16) |
    ((signatureBytes[offset + 2] & 0xff) << 8) |
    (signatureBytes[offset + 3] & 0xff);
  
  // 指定桁数の数値に変換
  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * TOTPコードの検証
 * @param token 検証するTOTPコード
 * @param secret TOTPシークレット（Base32）
 * @param timestamp タイムスタンプ（ミリ秒）
 * @param digits コードの桁数
 * @param period 期間（秒）
 * @param window 検証する時間窓の数（前後）
 * @returns 検証結果（true/false）
 */
export async function verifyTOTPCode(
  token: string,
  secret: string,
  timestamp: number = Date.now(),
  digits: number = 6,
  period: number = 30,
  window: number = 1
): Promise<boolean> {
  if (!token || token.length !== digits || !/^\d+$/.test(token)) {
    return false;
  }
  
  console.log('TOTP検証開始:', { token, timestamp: new Date(timestamp).toISOString() });
  
  // 現在の時間窓と前後の時間窓でコードを検証
  for (let i = -window; i <= window; i++) {
    const checkTime = timestamp + (i * period * 1000);
    const expectedToken = await generateTOTPCode(secret, checkTime, digits, period);
    
    console.log(`ウィンドウ ${i}: 期待値=${expectedToken}, 入力値=${token}, 一致=${expectedToken === token}`);
    
    if (expectedToken === token) {
      return true;
    }
  }
  
  return false;
}

/**
 * TOTP認証用のURIを生成（QRコード用）
 * @param accountName アカウント名（通常はユーザー名またはメールアドレス）
 * @param secret TOTPシークレット
 * @param issuer サービス提供者名
 * @param digits コードの桁数
 * @param period 期間（秒）
 * @returns TOTP URI
 */
export function generateTOTPUri(
  accountName: string,
  secret: string,
  issuer: string = 'Auth Platform',
  digits: number = 6,
  period: number = 30
): string {
  const params = new URLSearchParams({
    secret: secret,
    issuer: issuer,
    algorithm: 'SHA1',
    digits: digits.toString(),
    period: period.toString()
  });
  
  // URLエンコードされたアカウント名とissuer
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccountName = encodeURIComponent(accountName);
  
  return `otpauth://totp/${encodedIssuer}:${encodedAccountName}?${params.toString()}`;
}