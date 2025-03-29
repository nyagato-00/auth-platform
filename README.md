# 認証基盤プロジェクト

TypeScript、Cloudflare Workers、Honoを使用した認証基盤の開発ドキュメントです。このプロジェクトでは、JWT（JSON Web Token）ベースの認証システムを実装しています。

## 1. プロジェクト概要

### 目的
外部Webアプリケーション向けに認証・認可サービスを提供する認証基盤の構築

### 使用技術
- **TypeScript**: 型安全性と保守性の向上
- **Cloudflare Workers**: エッジコンピューティング環境
- **Hono**: 軽量Webフレームワーク
- **JWT**: JSON Web Tokenによる認証
- **Cloudflare KV**: ユーザー情報の保存

### 主な機能
- ユーザー登録・ログイン・ログアウト
- JWTトークン発行と検証
- トークンのリフレッシュ
- 認証ミドルウェアによる保護されたAPIアクセス

## 2. プロジェクト構造

```
auth-platform/
├── src/
│   ├── index.ts        # アプリケーションのエントリーポイント
│   ├── auth/           # 認証関連のモジュール
│   │   ├── jwt.ts      # JWTの処理
│   │   ├── login.ts    # ログイン処理
│   │   └── user.ts     # ユーザー管理
│   ├── middleware/     # ミドルウェア
│   │   ├── auth.ts     # 認証ミドルウェア
│   │   └── debug.ts    # デバッグミドルウェア
├── test-client.html    # テスト用クライアント
├── tsconfig.json       # TypeScript設定
└── wrangler.toml       # Cloudflare Workersの設定
```

## 3. 開発環境のセットアップ

### 前提条件
- Node.js と npm（最新のLTS版を推奨）
- Git（バージョン管理用）
- Cloudflareアカウント

### 環境構築手順

```bash
# Cloudflare Wranglerのインストール
npm install -g wrangler

# Cloudflareアカウントへのログイン
wrangler login

# プロジェクトの作成
mkdir auth-platform
cd auth-platform

# プロジェクトの初期化
npm init -y

# 必要なパッケージのインストール
npm install hono@3.10.4
npm install --save-dev typescript@5.3.3 ts-node@10.9.2 @types/node@20.10.5 @cloudflare/workers-types@4.20231218.0 wrangler@3.22.0

# TSConfigの作成
# (tsconfig.jsonファイルを作成して設定)
```

### wrangler.tomlの設定

```toml
name = "auth-platform"
main = "src/index.ts"
compatibility_date = "2023-01-01"

[build]
command = "npm run build"

[vars]
JWT_SECRET = "your-secret-key-here" # 本番環境では安全な方法で管理すること
DEBUG = "true"                      # 開発環境のみtrueに設定

# KVの設定（ユーザー情報保存用）
[[kv_namespaces]]
binding = "AUTH_STORE"
id = "YOUR_KV_ID" # Cloudflareコンソールで作成したKVのIDを設定

# 開発環境用のKV設定
[dev]
port = 8787
```


## 5. APIエンドポイント

| エンドポイント | メソッド | 説明 | 認証要否 |
|--------------|---------|------|---------|
| `/` | GET | ヘルスチェック（サービス稼働確認） | 不要 |
| `/register` | POST | 新規ユーザー登録 | 不要 |
| `/login` | POST | ユーザーログイン | 不要 |
| `/logout` | POST | ユーザーログアウト | 不要 |
| `/refresh` | POST | アクセストークンの更新 | 不要 |
| `/api/user` | GET | ログインユーザー情報の取得 | 必要 |

### リクエスト・レスポンス例

#### ユーザー登録
**リクエスト**
```
POST /register
Content-Type: application/json

{
  "username": "testuser",
  "password": "testpass",
  "email": "test@example.com"
}
```

**レスポンス**
```json
{
  "message": "ユーザー登録が完了しました",
  "user": {
    "id": "e7492c12-756a-4e85-919c-70083366db64",
    "username": "testuser",
    "email": "test@example.com",
    "roles": ["user"],
    "createdAt": "2025-03-28T12:59:32.159Z"
  }
}
```

#### ログイン
**リクエスト**
```
POST /login
Content-Type: application/json

{
  "username": "testuser",
  "password": "testpass"
}
```

**レスポンス**
```json
{
  "message": "ログインに成功しました",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "e7492c12-756a-4e85-919c-70083366db64",
    "username": "testuser",
    "roles": ["user"]
  }
}
```

#### 保護されたAPIアクセス
**リクエスト**
```
GET /api/user
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**レスポンス**
```json
{
  "user": {
    "id": "e7492c12-756a-4e85-919c-70083366db64",
    "username": "testuser",
    "roles": ["user"]
  },
  "authenticated": true
}
```

## 6. 開発・デプロイ手順

### 開発サーバー起動
```bash
npm run dev
```

### ビルド
```bash
npm run build
```

### デプロイ
```bash
# KVネームスペースの作成（初回のみ）
wrangler kv:namespace create "AUTH_STORE"

# wrangler.tomlにKV IDを設定した後、デプロイ
npm run deploy
```

## 7. セキュリティに関する注意点

1. **本番環境では**:
   - `JWT_SECRET`は安全に管理してください（Cloudflare Secretsの使用を推奨）
   - `DEBUG`は`false`に設定してください
   - CORSの`origin`は適切に制限してください
   - より強力なパスワードハッシュアルゴリズム（bcryptなど）の使用を検討してください

2. **改善すべき点**:
   - パスワードのソルト追加（現在は単純なSHA-256を使用）
   - レート制限の実装（ブルートフォース対策）
   - トークンのブラックリスト機能（ログアウト時など）
   - アクセスログの詳細記録と監視
   - 二段階認証の実装

## 8. 拡張機能の実装案

本基盤を拡張する際に検討すべき機能：

1. **ユーザープロファイル管理**
   - プロファイル情報の更新
   - パスワード変更

2. **権限管理の強化**
   - ロールベースのアクセス制御
   - より詳細な権限設定

3. **セキュリティの強化**
   - レート制限の実装
   - ブルートフォース攻撃対策
   - アクセスログの記録と監視

4. **多要素認証**
   - メール/SMS/アプリによる二段階認証

5. **OAuth連携**
   - Google、GitHub、Facebookなどとの連携

## 9. トラブルシューティング

**問題**: ビルド時にTypeScriptエラーが発生する
**解決**: 
- `skipLibCheck: true`を`tsconfig.json`に追加
- 型定義の競合を解消するため、インデックスシグネチャ`[key: string]: any`を追加

**問題**: 認証ミドルウェアでのユーザー情報の受け渡しに失敗
**解決**:
- `c.set('user', ...)`の代わりに`c.req.user = ...`を使用
- 型チェックをバイパスするため`@ts-ignore`アノテーションを使用

**問題**: Node.js固有の`process.env`が使用できない
**解決**:
- Cloudflare Workersでは`c.env`を使用して環境変数にアクセス

## 10. リソース

- [Cloudflare Workers ドキュメント](https://developers.cloudflare.com/workers/)
- [Hono ドキュメント](https://hono.dev/)
- [TypeScript ドキュメント](https://www.typescriptlang.org/docs/)
- [JWT.io](https://jwt.io/) - JWTトークンのデバッグと検証ツール

## 11. テスト方法

### cURLによるテスト

以下のcURLコマンドを使用して、APIをテストできます。

```bash
# ユーザー登録
curl -X POST http://localhost:8787/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass","email":"test@example.com"}'

# ログイン
curl -X POST http://localhost:8787/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'

# 保護されたAPIアクセス
curl -X GET http://localhost:8787/api/user \
  -H "Authorization: Bearer <access_token>"

# トークン更新
curl -X POST http://localhost:8787/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh_token>"}'
```

### テスト用HTMLクライアント

プロジェクトルートに`test-client.html`ファイルを作成し、ブラウザで開くことでテストすることもできます。このクライアントでは以下の機能をテストできます：

- ユーザー登録
- ログイン・ログアウト
- 保護されたAPIへのアクセス
- トークンの更新

## 12. 性能に関する考慮事項

Cloudflare Workersは以下の特性があります：

1. **コールドスタート**: ほぼゼロに近い
2. **実行時間の制限**: 無料プランでは1リクエストあたり最大10ms、有料プランでは50ms
3. **メモリ制限**: 128MB
4. **KVストアの制限**:
   - 読み取り: 1秒あたり最大1,000リクエスト
   - 書き込み: 1秒あたり最大1,000リクエスト
   - 保存: 無料プランでは1GBまで

これらの制限を考慮して、以下の最適化を検討してください：

- 読み取り頻度の高いデータはKVのキャッシュを活用する
- 複雑な操作は非同期で行い、必要に応じてWebhookを使用する
- ユーザー数が多い場合は、スケーラブルなデータベース（例：Cloudflare D1）への移行を検討する

## 13. データストレージ

現在の実装ではCloudflare KVを使用していますが、以下のデータ構造でユーザー情報を保存しています：

1. **ユーザー名によるアクセス**: `user:{username}`
2. **IDによるアクセス**: `id:{userId}`
3. **メールアドレスによるアクセス**: `email:{email}`
4. **ログイン履歴**: `login:{userId}:{timestamp}`

KVストアの特性として、以下の点に注意してください：

- 値のサイズ制限: 25MB
- キーの文字数制限: 512文字
- 一貫性: 最終的には一貫性があるが、即時反映は保証されない

ユーザー数やデータ量が増加した場合は、Cloudflare D1（SQLiteベースのデータベース）への移行も検討してください。

## 14. モニタリングとログ

開発中は、`debugMiddleware`を使用して詳細なログを出力しています。本番環境では以下の方法でモニタリングを行うことが推奨されます：

1. **Cloudflare Workers ダッシュボード**:
   - リクエスト数、CPUタイム、エラー率などの基本的なメトリクスを確認

2. **カスタムログの実装**:
   - エラーや重要なイベントを外部のログサービスに送信する実装を追加

3. **アラートの設定**:
   - 異常な動作（例：急激なエラー増加、高いCPU使用率）を検知した場合に通知

これらの機能を実装することで、システムの健全性を継続的に監視し、問題を早期に発見・対応することが可能になります。

## 15. 今後の展望

このプロジェクトを基盤として、以下のような機能拡張が考えられます：

1. **APIゲートウェイの実装**:
   - 様々なマイクロサービスへのアクセス制御

2. **サービス間認証**:
   - マイクロサービスアーキテクチャにおけるサービス間の認証

3. **分析ダッシュボード**:
   - ユーザーのアクティビティ、ログイン履歴、異常な動作のモニタリング

4. **カスタムポリシーエンジン**:
   - より柔軟で詳細なアクセス制御ポリシーの実装

5. **DevOpsの自動化**:
   - CI/CDパイプラインの構築
   - 自動テストの実装
   - インフラストラクチャのコード化