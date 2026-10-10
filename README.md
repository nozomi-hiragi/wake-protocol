# WAKE Protocol

**WebAuthn Authenticated Key Exchange — `WAKE/1`**

WebAuthnでユーザーを認証すると同時に一時ECDH鍵交換を認証し、得られたセッション鍵でアプリケーション層の通信を暗号化・認証するプロトコルの仕様です。

> [!WARNING]
> **未実装・未監査の設計ドラフト（v0.4）です。**
> 参照実装とテストベクターによる整合性検証、および第三者による暗号プロトコルレビューが済むまで、本番環境で採用しないでください。

## 仕様書

- [WAKE Protocol 仕様書](spec/wake-protocol.md)（設計ドラフト v0.4、2026-10-10）
- 版ごとの変更点は [CHANGELOG.md](CHANGELOG.md) を参照してください。

## 特徴

- **パスキーでログインした瞬間に鍵交換も認証される**: WebAuthn Challengeを鍵交換のTranscriptから導出するため、公開鍵のすり替えが成立しません。
- **ログインごとに新しい一時ECDH鍵**: ECDH秘密鍵とセッション鍵はネットワークに出しません。
- **TLSの上にもう一層**: 通信方向ごとに別の鍵（AES-256-GCM）を使い、要求と応答の対応付けや改ざん検出をアプリ層で行います。TLS（HTTPS）は必須で、WAKEはTLSの置き換えではありません。
- **重要操作のWebAuthn承認**: セッション鍵を盗まれても、指定された認否者のUV付きWebAuthn署名なしには操作を承認できません。`operationId`は承認文面のSHA-256なので、手元の`shasum`でも照合できます。
- **WebAuthnによる鍵更新**: セッションを維持したまま、新しいECDHで鍵世代を進めます。
- **Web標準だけで動く**: Web Crypto API、IndexedDB、Web Locks、BroadcastChannelで実装できる設計です。

## モジュール

| モジュール | 役割 | 主なAPI |
|---|---|---|
| **WAKE-KX** | Key Exchange。WebAuthnによる認証付きECDH鍵交換 | `POST /auth/start`, `POST /auth/complete` |
| **WAKE-SM** | Session Management。暗号化セッションの管理（暗号化・鍵世代・失効） | `wake/session`, `wake/logout` |
| **WAKE-ET** | Encrypted Transport。汎用暗号化APIトランスポート（任意） | `POST /wake/transport` |
| **WAKE-TA** | Transaction Authorization。操作要求とWebAuthnによる認否 | `wake/ta/*` |
| **WAKE-KR** | Key Rotation。WebAuthnによるセッション鍵の更新 | `wake/kr/start`, `wake/kr/complete` |

各モジュールは独立しており、組み合わせて使えます（例: TAの承認とKRを1回のWebAuthnで行う）。

## ログインの流れ（WAKE-KX）

```text
Client                                             Server
  | POST /auth/start                                 |
  |------------------------------------------------->| 一時ECDH鍵ペアとNonceを生成
  |<-------------------------------------------------| 公開情報 + WebAuthnオプション
  | 一時ECDH鍵ペアを生成                             |
  | Transcript → Challenge → パスキーで署名          |
  | 共有秘密 → 鍵導出 → clientFinished               |
  | POST /auth/complete                              |
  |------------------------------------------------->| Challengeを自分で再計算してWebAuthn検証
  |                                                  | 鍵導出 → clientFinished検証 → セッション確定
  |<-------------------------------------------------| serverFinished
  | serverFinished検証 → 暗号化通信を開始            |
```

2往復で完了します。ログイン画面の表示時に`/auth/start`を呼んでおけば、ユーザーが体感する往復は1回です。

## 暗号方式

| 用途 | 方式 |
|---|---|
| 鍵合意 | ECDH / NIST P-256（一時鍵） |
| ハッシュ | SHA-256 |
| 鍵導出 | HKDF-SHA-256 |
| 鍵確認 | HMAC-SHA-256 |
| メッセージ暗号 | AES-256-GCM（96bitランダムIV） |
| 認証 | WebAuthn（`userVerification: "required"`、ES256必須） |

## 保証しないこと

WAKEは次のものを防ぎません。詳しくは仕様書の「責任範囲と保証」を参照してください。

- XSS、およびXSSが存在する状況での安全性
- 侵害された端末上での安全性
- 通常APIのリプレイ（冪等性はAPI実装者の責任）
- HTTPメタデータ（`sessionId`、URL、サイズ、時刻）の秘匿
- 初回のユーザー登録・パスキー登録時の本人確認、全パスキーを失った場合の復旧

## ロードマップ

- [x] 設計ドラフト v0.4
- [ ] 参照実装（TypeScript / Web Crypto API）
- [ ] テストベクター（JSON）
- [ ] 第三者による暗号プロトコルレビュー
- [ ] 実装ノート（Cloudflare Workers / D1 / Durable Objects）

今後の検討事項（ストリーミング、厳密なリプレイ拒否、複数人承認の標準化など）は仕様書の「今後の検討事項」にまとめています。

## フィードバック

仕様への質問、矛盾や攻撃の指摘は [Issues](../../issues) で受け付けています。特に、暗号プロトコルとしての問題点の指摘を歓迎します。

## ライセンス

[Apache License 2.0](LICENSE)（仕様書、参照実装、テストベクターすべて）
