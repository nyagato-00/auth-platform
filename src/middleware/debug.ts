import { Context, Next } from 'hono';

// デバッグ用ミドルウェア - すべてのリクエストとレスポンスをログに出力
// src/middleware/debug.ts を修正
export const debugMiddleware = async (c: Context, next: Next) => {
  const requestId = crypto.randomUUID().slice(0, 8);
  const method = c.req.method;
  const path = c.req.path;
  const headers = Object.fromEntries(c.req.raw.headers);
  
  console.log(`[${requestId}] REQUEST: ${method} ${path}`);
  console.log(`[${requestId}] HEADERS:`, JSON.stringify(headers, null, 2));
  
  try {
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      const contentType = c.req.header('Content-Type') || '';
      if (contentType.includes('application/json')) {
        // リクエストクローンを作成して、ボディが存在するか確認
        const clonedReq = c.req.raw.clone();
        const text = await clonedReq.text();
        
        if (text.trim()) {  // 空でない場合のみJSON解析を試みる
          const body = JSON.parse(text);
          console.log(`[${requestId}] BODY:`, JSON.stringify(body, null, 2));
          
          // リクエストボディを再設定
          c.req.raw = new Request(c.req.raw.url, {
            method: c.req.raw.method,
            headers: c.req.raw.headers,
            body: text,
          });
        } else {
          console.log(`[${requestId}] BODY: Empty`);
        }
      }
    }
    
    // リクエスト処理の開始時間を記録
    const startTime = Date.now();
    
    // 次のミドルウェアやハンドラーに処理を委譲
    await next();
    
    // リクエスト処理の完了時間を計算
    const duration = Date.now() - startTime;
    
    console.log(`[${requestId}] RESPONSE: ${c.res.status} (${duration}ms)`);
  } catch (error) {
    console.error(`[${requestId}] ERROR:`, error);
    throw error;
  }
};
