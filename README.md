# Passkeys Demo

Go（WebAuthn）と Next.js で動く、パスワードまたはパスキーでログインできるデモサイトです。

## できること

- ユーザー名 + パスワードで新規登録・ログイン
- ログイン後にパスキーを追加・一覧・削除
- 次回以降はパスキー単体でもログイン（ユーザー名あり / なしの両方）

## 必要環境

- Go 1.23+
- Node.js 20+
- パスキー対応ブラウザ（Safari / Chrome / Edge など）と、Touch ID、Face ID、Windows Hello、iCloud キーチェーン、またはセキュリティキー

ローカルの `http://localhost:3000` 専用です。独自ドメインで動かす場合は HTTPS と WebAuthn の RP ID 変更が必要です。

## 起動

ターミナルを 2 つ使います。

```bash
# バックエンド（http://localhost:8080）
cd backend
go run ./cmd/server
```

```bash
# フロントエンド（http://localhost:3000）
cd frontend
npm install
npm run dev
```

ブラウザで [http://localhost:3000](http://localhost:3000) を開きます。フロントの `/api/*` は Next.js の rewrite で Go API に転送されます。

## 試し方

1. 「新規登録」でユーザー名（英数字と `_`、3〜32 文字）とパスワード（8 文字以上）を作る
2. ダッシュボードでパスキーの表示名を入れて「パスキーを追加」
3. OS のダイアログに従い、Touch ID / Windows Hello / セキュリティキーなどで登録する
4. ログアウトし、「パスキーでログイン」を押す
   - ユーザー名を空にすると、デバイス保存のパスキーから選ぶ（discoverable login）
   - ユーザー名を入れると、そのアカウントのパスキーに限定する

データは `backend/data/passkeys.db` の SQLite に保存されます。

## 環境変数（バックエンド）

| 変数 | デフォルト | 説明 |
|---|---|---|
| `HTTP_ADDR` | `:8080` | 待受アドレス |
| `DB_PATH` | `data/passkeys.db` | SQLite のパス |
| `RP_ID` | `localhost` | WebAuthn Relying Party ID |
| `RP_DISPLAY_NAME` | `Passkeys Demo` | 認証ダイアログに出る名前 |
| `RP_ORIGINS` | `http://localhost:3000` | 許可する Origin（カンマ区切り） |

## 環境変数（フロントエンド）

| 変数 | デフォルト | 説明 |
|---|---|---|
| `NEXT_PUBLIC_PASSKEY_UI_MODE` | `button`(未設定時) | `conditional` にすると、ログイン画面のパスキーログインを Conditional UI（ユーザー名欄への自動サジェスト）に切り替える。ブラウザが未対応の場合は自動的に `button`（明示的なボタン）へフォールバックする。 |

`frontend/.env.local` に `NEXT_PUBLIC_PASSKEY_UI_MODE=conditional` を書いて `npm run dev` を再起動すると切り替えられます。
