# WAKE Protocol 仕様書

**WebAuthn Authenticated Key Exchange — WAKE/1**

| 項目 | 値 |
|---|---|
| プロトコル | WAKE（WebAuthn Authenticated Key Exchange） |
| ワイヤ上のバージョン | `WAKE/1` |
| 文書版 | 設計ドラフト **v0.6** |
| 最終更新 | 2026-10-16 |
| 前版 | v0.5（2026-10-16） |
| 対象 | Webブラウザのクライアント、アプリケーションサーバー、複数サーバー構成 |
| 基本暗号 | WebAuthn / 一時ECDH P-256 / HKDF-SHA-256 / HMAC-SHA-256 / AES-256-GCM |
| 状態 | **未監査の提案仕様**。仮実装（`impl/ts/`）とテストベクター（`spec/test-vectors/`）で検証中。第三者による暗号プロトコルレビューを経るまで本番採用しない |

> 規範的な記述には **MUST / MUST NOT / SHOULD / SHOULD NOT / MAY**（RFC 2119 / RFC 8174）を用いる。「参考」と明記した節・例・付録は規範ではない。

---

## 0. v0.5からの主な変更

| 区分 | 変更 |
|---|---|
| WAKE-ET | `EtRequest`のパスとクエリを、RFC 3986のURI-referenceである`url`の1フィールドにまとめた（§11.2、§11.3）。絶対URI（`wake://…`、`https://…`）も相対参照も運べる。ワイヤ形式はv0.5と互換性がない |
| WAKE-ET | 受信側の解釈をWAKEの範囲外とした（§11.5）。登録済みルートとの完全一致、`route_not_found`、`/wake/`への転送禁止とプロキシの禁止を削除し、URLによる振り分けや転送は受信した実装が決める |
| WAKE-ET | 残す検査を、Fetch Standardの`Request`・`Response`に組み立てられる範囲に絞った（§11.2〜§11.4）。methodはtoken（`CONNECT`・`TRACE`・`TRACK`を除く）、`GET`・`HEAD`の要求と`204`・`205`・`304`の応答は本文を持たない。ヘッダーの重複の拒否、`host`の規則、`location`の制限を削除 |
| ETのエラー | `invalid_path`を`invalid_url`に改名し、`route_not_found`を削除（§11.6） |

### 0.1 v0.4からv0.5への主な変更

仮実装とテストベクターによる検証を受けた変更。

| 区分 | 変更 |
|---|---|
| WAKE-TA | 文面プロファイルを簡素化。制御文字（一般カテゴリCc）を**LFを含めて**禁止し、それ以外の特殊な文字は拒否せず承認画面で可視化する（§10.4、§10.11）。`content`は1行になり、§10.3の例を更新 |
| WAKE-ET | ETは通常のHTTP要求・応答を運ぶ補助に留める。`/wake/`への転送禁止とルート照合はディスパッチ側の責任とし（§11.5）、パス・クエリは正規化も独自の制限もせず形式だけを検査する（§11.2、§11.3）。ヘッダーの許可・拒否リストを廃止し、名前・値・順序・重複をHTTPの規則どおりに運ぶ（§11.4）。`location`は同じオリジン内の絶対パスに限る |
| ETのエラー | クエリの違反は`invalid_path`、`EtRequest` / `EtResponse`の形式不正は`invalid_request`と明記（§11.6） |
| 明確化 | Challengeの儀式とTranscriptのmodeの対応（§5.5）、時刻は2⁵³−1以下（§4.6）、ヘッダー全体の長さの数え方と`location`の範囲（§11.4）、平文長の上限の扱い（§8.7） |
| テストベクター | 異常系の`expectedError`コード一覧とJSONでの表し方を定義（§16）。`spec/test-vectors/`に収録 |
| WAKE-KX | `/auth/start`の応答に`serverTime`を追加（§7.2）。クライアントは`expiresAt`を端末の時刻に換算して、`/auth/complete`の再送の期限に使う（§7.7）。端末の時計がずれていても、再送の期限を正しく判断できるようにするため |

### 0.2 v0.3からv0.4への主な変更

| 区分 | 変更 |
|---|---|
| 暗号化通信 | Sequenceを廃止し、メッセージごとの96bitランダムIVと128bitの`requestId`に変更 |
| AAD | 受信したヘッダーのバイト列そのものをAADとする。URLパスではなく`context`文字列を結び付ける |
| 鮮度 | 認証済みヘッダーに`issuedAt`を追加（リプレイ防止ではなく、再送可能な時間の制限） |
| 鍵交換 | `/auth/confirm`を廃止し2往復化。Finishedを HMAC-SHA-256 に変更 |
| WebAuthn | KX・KR・TA・TA+KRのChallengeを1つの方式に統一。credential所有者とセッションユーザーの照合、credential状態の確認を必須化 |
| WAKE-KR | WebAuthnと新しいECDHによる鍵更新を追加。`keyEpoch`で鍵世代を管理 |
| WAKE-TA | `operationId = SHA-256(hashInput)`（外部ツールで再現可能）。`approverUserId`を必須化。状態は`PENDING → APPROVED / REJECTED / CANCELLED / EXPIRED`。操作の実行は範囲外 |
| エンコード | 長さ付きエンコード（LP）に統一。正準Base64urlのみ受理 |
| API | HTTPエンドポイント、context、エラーコードを定義 |

---

## 1. 概要

WAKEは、**WebAuthnでユーザーを認証すると同時に一時ECDH鍵交換を認証し、得られたセッション鍵でアプリケーション通信を暗号化・認証する**プロトコルである。加えて、重要操作に対するWebAuthnでの認否（WAKE-TA）と、WebAuthnによるセッション鍵の更新（WAKE-KR）を提供する。

| モジュール | 役割 | 主なAPI |
|---|---|---|
| **WAKE-KX** | Key Exchange。WebAuthnによる認証付きECDH鍵交換 | `POST /auth/start`, `POST /auth/complete` |
| **WAKE-SM** | Session Management。暗号化セッションの管理（暗号化・鍵世代・失効） | `wake/session`, `wake/logout` |
| **WAKE-ET** | Encrypted Transport。汎用暗号化APIトランスポート（利用は任意） | `POST /wake/transport` |
| **WAKE-TA** | Transaction Authorization。操作要求とWebAuthnによる認否の管理 | `wake/ta/*` |
| **WAKE-KR** | Key Rotation。WebAuthnによるセッション鍵更新 | `wake/kr/start`, `wake/kr/complete` |

各モジュールは独立しており、組み合わせて使える（例: TA承認とKRを1回のWebAuthnで実施する）。

**TLS（HTTPS）は必須（MUST）**。WAKEはTLSの置き換えではなく、アプリケーション層での追加の暗号化と、鍵所有に基づく認証を提供する。

### 1.1 設計原則

1. WebAuthnの認証秘密鍵をECDHに使わない。WebAuthn署名は鍵交換情報や承認対象への同意・認証に使う。
2. ログインと鍵更新のたびに、クライアントとサーバーは新しい一時ECDH鍵ペアを生成する。
3. ECDH秘密鍵とセッション鍵をネットワークへ送信しない。
4. WebAuthn Challengeは鍵交換情報や承認対象から導出する。サーバーは自分の保存値から再計算して検証し、クライアントが主張する値を正解として採用しない。
5. WebAuthn検証と鍵確認に成功してからセッションを有効にする。
6. ログインごとに固有の`sessionId`を発行する。同じパスキーによる別端末でのログインは別セッションとする。
7. 通信方向ごとに別の鍵を使い、メッセージごとにランダムIVを使う。
8. 暗号化・改ざん検出・要求と応答の対応付けはWAKEが担う。通常APIのリプレイ防止と業務処理はAPI実装者が担う。
9. WAKE-TAは、操作要求と認否の管理だけを担う。操作の実行は扱わない。
10. WAKE-ETの利用は任意とし、独自APIでWAKEの暗号化機能を直接使うことを妨げない。

---

## 2. 用語

| 用語 | 意味 |
|---|---|
| セッション | 1回のログインで確立される暗号化通信の単位。`sessionId`で識別する |
| 鍵世代（epoch） | セッション内の鍵の世代番号`keyEpoch`。ログイン時は0、KRのたびに1増える |
| 交換（exchange） | KXまたはKRの1回分の鍵交換。`exchangeId`で識別し、サーバーが状態を保存する |
| 儀式（ceremony） | 1回のWebAuthn認証。KX、KR、TA、TA+KRのいずれか |
| Operation | WAKE-TAの操作要求。`operationId`で識別する |
| content | 実装者が定義する、操作内容を表す不変のUTF-8文字列 |
| hashInput | `content`にWAKEが生成したNonce行を連結した文字列。`operationId`のハッシュ対象 |
| 認否者 | Operationの認否を確定できるユーザー。`approverUserId`で指定する |
| 承認試行（approval attempt） | 承認のための使い捨てChallenge材料。`approvalId`で識別する |
| 認否 | Operationに対して確定する`APPROVED` / `REJECTED` / `CANCELLED` / `EXPIRED`のいずれか |
| context | 暗号化メッセージの用途を示すASCII文字列。AADに含まれる |
| requestId | 暗号化した要求ごとに生成する128bit乱数。応答との対応付けに使う |
| userId | 実装者が管理するユーザーの不透明な識別子（UTF-8、1〜256バイト） |

---

## 3. 責任範囲と保証

### 3.1 責任分担

| 機能 | WAKEの責任 | 実装者の責任 |
|---|---|---|
| 認証 | WebAuthnによる認証・検証 | ユーザー管理、初回登録 |
| 鍵交換 | 認証付きECDH鍵交換、交換状態の単回使用 | 鍵の具体的な保存基盤 |
| セッション | 暗号化・鍵世代・失効 | 期限などの運用ポリシー |
| 通常API | 暗号化・改ざん検出・暗号Nonceの安全性・requestIdの付与・要求と応答の対応付け | 業務処理、リプレイ対策、冪等性 |
| WAKE-ET | 汎用暗号化トランスポート（HTTP形式の要求・応答の符号化と暗号化） | 受信した要求の解釈（URLのスキームやパスの意味、振り分け、転送）と処理 |
| 操作要求 | 不変の文字列、Nonce生成、`operationId`、状態管理 | 要求内容（content）の定義、認否者の指定権限の検証 |
| 操作承認 | 認否者の認証、WebAuthnによる認否の確定、認否の一意性 | 承認結果の利用方法 |
| 操作実行 | 対象外 | 実行、冪等性、結果管理、実行時のリプレイ対策、複数人承認の集計 |
| パスキー管理 | credential状態の確認、所有者照合、セッション失効の機能 | 登録・追加・停止・削除のフロー |
| クライアント改ざん | 保証範囲外 | 配信コードの真正性確認 |

### 3.2 WAKEが提供する性質

| ID | 性質 |
|---|---|
| P1 | **鍵交換の認証**: WebAuthn署名は、両方のECDH公開鍵・サーバーNonce・`sessionId`・`keyEpoch`に結び付く。サーバーは自分の保存値で検証するため、公開鍵のすり替えは成立しない |
| P2 | **セッション通信の保護**: 機密性、完全性、通信方向の分離、要求と応答の対応付け、セッションや鍵世代の取り違えの防止 |
| P3 | **鮮度**: `issuedAt`によって、捕捉された暗号文を再送できる時間を制限する。リプレイの防止は保証しない |
| P4 | **鍵更新**: 新しい鍵世代は、そのセッションのユーザーの有効なcredentialによるWebAuthn認証なしには確立できない |
| P5 | **操作承認**: 攻撃者が有効なセッション鍵を持っていても、`approverUserId`として指定されたユーザーの有効なcredentialによるUV付きWebAuthn署名なしには、Operationを`APPROVED`にできない。1つのOperationに確定する認否は1つだけである。`hashInput`は作成後に変更できず、`operationId`はその SHA-256 である |

### 3.3 保証の前提条件

上記の性質は、次の条件が満たされている場合に限り成立する。

1. TLSで通信が保護され、クライアントが正しいオリジンに接続している。
2. クライアントで実行されるHTML・JavaScriptが改ざんされていない（§3.4）。
3. **認証の信頼関係を変更する操作の保護（実装者の要件）**: credentialの追加・停止・再開・削除など認証の信頼関係を変更する操作は、(a) 変更対象を一意に識別する情報（追加するcredentialのIDと公開鍵の SHA-256 など）を含む要求に対し、(b) 状態が有効な既存credentialによるUV付きWebAuthn署名で承認された場合に限り、確定しなければならない（MUST）。「セッションが直近に再認証済みである」という状態だけでは、この要件を満たさない。WAKE-TAはこの承認に利用できる（付録B）。この条件が満たされない場合、セッション鍵を盗んだ攻撃者が自分の鍵をcredentialとして登録でき、P4・P5は成立しない。
4. credentialの状態（§6.5）が正しく管理されている。
5. サーバーの鍵管理要件（§8.10）が満たされている。

初回のユーザー登録・パスキー登録時の本人確認と、全パスキーを喪失した場合の復旧は、WAKEの仕様範囲外とする。

### 3.4 保証しないこと

- XSSの防止、およびXSSが存在する状況での安全性。XSSは鍵を使ってAPIを操作でき、ユーザーのWebAuthn操作に便乗して、自分が生成した抽出可能な鍵でKXやKRを行うこともできる。
- 侵害された端末上での安全性。
- WebAuthn実行時にユーザーが実際に見た内容の真正性。
- 悪意あるJavaScriptによる表示内容の改ざんの防止。
- 通常APIのリプレイ防止、承認結果を利用した処理の一意性。
- HTTPメタデータ（`sessionId`、URL、サイズ、時刻）の秘匿。
- クライアントの実行コードが改ざんされていないことのリモート証明。

---

## 4. 共通エンコーディング

### 4.1 整数

| 表記 | 形式 |
|---|---|
| `u8(x)` | 符号なし1バイト |
| `u16(x)` | 符号なし2バイト、ビッグエンディアン |
| `u32(x)` | 符号なし4バイト、ビッグエンディアン |
| `u64(x)` | 符号なし8バイト、ビッグエンディアン |

### 4.2 長さ付きエンコード（LP）

```text
LP(f1, f2, …, fn) = u32(len(f1)) ‖ f1 ‖ u32(len(f2)) ‖ f2 ‖ … ‖ u32(len(fn)) ‖ fn
```

- 各フィールドはバイト列である。整数は`uN`でバイト列にしてから渡す（整数にも4バイトの長さが付く）。
- 空のフィールド（`ε`と表記）は、長さ0として符号化する。
- 入れ子の構造は、`LP(…)`の結果を1つのフィールドとして渡す。
- 1フィールドの長さは2³²−1バイト以下でなければならない。実装はこれより短い上限を各所で設ける。
- デコードは厳密に行わなければならない（MUST）。構造ごとにフィールド数を固定し、固定長のフィールドは長さを検査し、末尾に余分なバイトがあれば拒否する。

例:

```text
LP(ascii("ab"), ε) = 00000002 6162 00000000   （16進）
```

### 4.3 文字列

- `ascii(s)`: ASCII文字列のバイト列。プロトコル上のラベルとcontextはASCIIである。
- `utf8(s)`: UTF-8のバイト列。正しい形式でなければならない（孤立サロゲートや不正なバイト列を含まない）。
- WAKEはUnicode正規化・改行変換・空白の除去などを**行わない**。検査して拒否するだけである。
- UTF-8のデコードは、不正なバイト列を置換文字（U+FFFD）に置き換えずに**エラーとする**厳密モードで行わなければならない（MUST）。例: JavaScriptの`new TextDecoder("utf-8", { fatal: true })`、Javaの`CodingErrorAction.REPORT`。

### 4.4 Base64url

- RFC 4648 §5の文字集合を使い、パディング（`=`）を付けない。
- **正準形のみ受理する（MUST）**。デコードした結果を再エンコードし、元の文字列と一致しなければ拒否する（末尾の未使用ビットが0でないもの、`=`を含むもの、文字集合外の文字を含むものは拒否される）。

### 4.5 16進表現

`operationId`は外部ツールでの照合のため、**小文字の16進数64文字**で表す。APIは小文字のみを受理しなければならない（MUST）。人が見比べる画面では大文字・小文字を区別せずに比較してよい。プロトコル内部（`ta`の入力など）では、32バイトの生のバイト列として扱う。

### 4.6 識別子と固定長の値

| 値 | 形式 | 生成 |
|---|---|---|
| `sessionId` | 32B | CSPRNG。秘密ではない |
| `exchangeId` | 16B | CSPRNG |
| `requestId` | 16B | CSPRNG。暗号化した要求ごとに新規 |
| `approvalId` | 16B | CSPRNG |
| `serverNonce` | 32B | CSPRNG。交換ごとに新規 |
| `approvalNonce` | 32B | CSPRNG。承認試行ごとに新規 |
| TA Nonce | 16B（小文字16進32文字で表記） | CSPRNG。Operationごとに新規 |
| IV | 12B | CSPRNG。暗号化ごとに新規 |
| `keyEpoch` | `u32` | ログイン時0、KRごとに+1 |
| 時刻 | `u64` | Unix時刻（ミリ秒）。JSONでも扱えるよう、0〜2⁵³−1に限る（MUST）。範囲外は形式不正として拒否する |
| ECDH公開鍵 | 65B | SEC1非圧縮形式（先頭`0x04`） |
| ハッシュ値・MAC | 32B | 切り詰めない |
| 通信方向 `dir` | `u8` | `0x01` = c2s（クライアント→サーバー）、`0x02` = s2c |
| `operationId` | 32B | §10.3 |

### 4.7 ラベル

| ラベル（ASCII） | 用途 |
|---|---|
| `WAKE/1 kx-transcript` | KX/KRのTranscript |
| `WAKE/1 webauthn-challenge` | すべてのWebAuthn Challenge |
| `WAKE/1 ta-approve` | TA承認の結び付け |
| `WAKE/1 msg` | 暗号化メッセージのヘッダー（AAD） |
| `WAKE/1 et-req` / `WAKE/1 et-res` | WAKE-ETの平文 |
| `WAKE/1 key c2s` / `WAKE/1 key s2c` | HKDFのinfo（通信鍵） |
| `WAKE/1 finished c2s` / `WAKE/1 finished s2c` | HKDFのinfo（Finished鍵） |
| `WAKE/1 client finished` / `WAKE/1 server finished` | FinishedのMAC入力 |
| `WAKE/1 key-wrap` / `WAKE/1 exchange-key` | サーバー内部の鍵保護（推奨。§8.10） |

`operationId`のハッシュ入力にはラベルを付けない（外部ツールでの再現を優先するため。§10.3）。

### 4.8 JSON

- `/auth/*`と、暗号化されたWAKE内部APIの平文はJSONとする。JSONは I-JSON（RFC 7493）に従わなければならない（MUST）。キーの重複、孤立サロゲート、2⁵³以上の整数を含むものは拒否する。
- バイナリ値はBase64url（§4.4）の文字列とする。ただし`operationId`は16進（§4.5）とする。
- 時刻はミリ秒の整数とする。
- 受信側は未知のフィールドを無視する（MUST）。

---

## 5. 暗号方式

### 5.1 アルゴリズム

| 用途 | 方式 |
|---|---|
| 鍵合意 | ECDH / NIST P-256 |
| ハッシュ | SHA-256 |
| 鍵導出 | HKDF-SHA-256（RFC 5869） |
| 鍵確認 | HMAC-SHA-256 |
| メッセージ暗号 | AES-256-GCM、IVは96bit乱数、認証タグは128bit固定 |

### 5.2 ECDH

- 一時鍵ペアは交換ごとに新しく生成する（MUST）。
- 受信した公開鍵は、**長さが65バイトで先頭が`0x04`であることを、インポートの前に**検査しなければならない（MUST）。圧縮点（33バイト）やハイブリッド形式は拒否する。
- 公開鍵が曲線上の有効な点であることを検証しなければならない（MUST）。Web Crypto APIは`importKey`で検証するが、他の暗号ライブラリでは明示的な検証が必要な場合がある。
- 共有秘密`ss`は共有点のx座標とし、**先頭のゼロを含む固定長32バイト**（SEC1 FE2OSP）とする（MUST）。多倍長整数を経由する実装では、先頭のゼロが落ちないよう注意すること。

### 5.3 Transcript

```text
th = SHA-256(LP(
  ascii("WAKE/1 kx-transcript"),
  u8(mode),            // 0x01 = login (KX), 0x02 = rekey (KR)
  exchangeId,          // 16B
  sessionId,           // 32B
  u32(epoch),          // KX: 0 / KR: 更新後の世代
  prevTh,              // KX: ε / KR: 更新前の世代のth（32B）
  serverNonce,         // 32B
  serverPublicKey,     // 65B
  clientPublicKey      // 65B
))
```

### 5.4 TA承認の結び付け

```text
ta = SHA-256(LP(
  ascii("WAKE/1 ta-approve"),
  approvalId,          // 16B
  operationId,         // 32B（生のバイト列）
  approvalNonce,       // 32B
  sessionId            // 32B（承認試行を発行したセッション）
))
```

### 5.5 WebAuthn Challenge

```text
challenge = SHA-256(LP(ascii("WAKE/1 webauthn-challenge"), thOrε, taOrε))
WebAuthn options.challenge = challenge（32B）
```

| 儀式 | 第2フィールド | 第3フィールド |
|---|---|---|
| KX（ログイン） | `th`（mode=0x01） | ε |
| KR | `th`（mode=0x02） | ε |
| TA | ε | `ta` |
| TA+KR | `th`（mode=0x02） | `ta` |

- 上の表にない組み合わせ（両方ε、mode=0x01と`ta`の組み合わせなど）は拒否しなければならない（MUST）。
- Challengeの入力にmodeは含まれない。儀式の種類は呼び出されたAPI（`/auth/complete`、`wake/kr/complete`、`wake/ta/approve`）で決まり、実装はその儀式に対応するmodeで`th`を計算しなければならない（MUST）。受信した値から儀式の種類を推測してはならない（MUST NOT）。
- サーバーはChallengeを自分の保存値と受信したクライアント公開鍵から再計算する（MUST）。クライアントから受け取ったChallenge値を使ってはならない（MUST NOT）。
- クライアントもChallengeを自分で計算する。サーバーはChallenge値を送らない。

### 5.6 鍵導出

```text
k_c2s = HKDF-SHA-256(IKM = ss, salt = th, info = ascii("WAKE/1 key c2s"),      L = 32)
k_s2c = HKDF-SHA-256(IKM = ss, salt = th, info = ascii("WAKE/1 key s2c"),      L = 32)
fk_c  = HKDF-SHA-256(IKM = ss, salt = th, info = ascii("WAKE/1 finished c2s"), L = 32)
fk_s  = HKDF-SHA-256(IKM = ss, salt = th, info = ascii("WAKE/1 finished s2c"), L = 32)
```

`k_c2s`と`k_s2c`はAES-256-GCM鍵、`fk_c`と`fk_s`はHMAC-SHA-256鍵とする。Finished鍵をメッセージ暗号に使ってはならない（MUST NOT）。

### 5.7 Finished

```text
clientFinished = HMAC-SHA-256(fk_c, LP(ascii("WAKE/1 client finished"), th))

serverFinished = HMAC-SHA-256(fk_s, LP(
  ascii("WAKE/1 server finished"),
  th,
  clientFinished,
  u64(serverTime),            // サーバー時刻（ミリ秒）
  u64(absoluteExpiresAt),     // セッションの絶対有効期限（ミリ秒）
  u32(idleTimeoutSec)         // 無操作期限（秒）
))
```

- Finishedの検証は定数時間で行わなければならない（MUST）。Web Crypto APIでは`crypto.subtle.verify("HMAC", …)`を使う。
- `serverFinished`に時刻と期限を含めることで、クライアントの時刻補正（§8.5）の基準値が認証される。

---

## 6. WebAuthn検証プロファイル

### 6.1 クライアントへ渡すオプション

サーバーは次の形式でWebAuthnのオプションを返す。`challenge`は含めず、クライアントが§5.5で計算して設定する。

```json
{
  "rpId": "example.com",
  "allowCredentials": [
    { "type": "public-key", "id": "<base64url>", "transports": ["internal", "hybrid"] }
  ],
  "userVerification": "required",
  "timeout": 270000
}
```

- `userVerification`は`"required"`でなければならない（MUST）。
- `timeout`は、交換または承認試行のTTLより30秒以上短くする（SHOULD）。
- クライアントが送るassertionは、WebAuthn Level 3の`AuthenticationResponseJSON`形式とする。

### 6.2 検証手順

サーバーは、すべての儀式で次をすべて検証しなければならない（MUST）。

1. `clientDataJSON.type`が`"webauthn.get"`である。
2. `clientDataJSON.challenge`が正準Base64url（§4.4）で、デコードしたバイト列がサーバーの再計算したChallengeと一致する。
3. `clientDataJSON.origin`が、儀式の種類に応じて許可されたoriginである（§6.3）。`crossOrigin`が`true`のものは拒否する。
4. `authenticatorData.rpIdHash`が`SHA-256(rpId)`と一致する。
5. UP（User Present）とUV（User Verified）のフラグが両方立っている。
6. credentialが存在し、状態が`active`である（§6.5）。
7. 署名が、そのcredentialの公開鍵で正しく検証できる。ES256（COSE −7）のサポートは必須（MUST）、RS256（−257）とEdDSA（−8）は任意（MAY）。ES256署名はDER形式なので、Web Crypto APIで検証する場合は64バイトの`r‖s`形式に変換する。
8. `userHandle`がある場合、credentialに登録された値と一致する。
9. ユーザーの照合:
   - KX: ユーザー名指定方式（§6.6）では、credentialの`userId`が指定されたユーザーと一致する。
   - KR・TA・TA+KR: **credentialの`userId`がセッションの`userId`と一致する**。
   - TA・TA+KR: さらに、**セッションの`userId`がOperationの`approverUserId`と一致する**。
10. 署名カウンターの規則（§6.4）を満たす。

### 6.3 Originの設定

| 儀式 | 許可するorigin |
|---|---|
| KX | 設定値`loginOrigins`のいずれか |
| KR | セッションを確立したorigin（`established_origin`）と一致すること |
| TA、TA+KR | 設定値`taOrigins`のいずれか、かつ`established_origin`と一致すること |

- 既定値は`taOrigins = loginOrigins`とし、**同一originでの承認を正式にサポートする**。
- より強い分離が必要な実装は、承認専用のorigin（例: `https://approve.example.com`）を用意し、`taOrigins`をそのoriginだけにしてよい（MAY）。RP IDを登録可能ドメイン（`example.com`）にすれば、同じパスキーを複数のサブドメインで使える。登録可能ドメインが異なる場合は、WebAuthn Level 3のRelated Origin Requestsを利用できる。
- WebAuthnのoriginにはURLのパスが含まれないため、パスによる承認画面の分離はXSSに対する境界にならない。

### 6.4 署名カウンター

| 保存値 | 受信値 | 動作 |
|---|---|---|
| 0 | 0 | 受理する（同期パスキーでは一般的） |
| n | m > n | 受理し、`m`に更新する |
| n > 0 | m ≤ n | 複製の疑い。BE（Backup Eligible）フラグが0のcredentialは拒否し、1のcredentialは受理したうえで記録・通知する（SHOULD） |

並行する儀式による競合を避けるため、更新は`max(保存値, 受信値)`で行う（SHOULD）。

### 6.5 Credentialの状態と照合

WAKEは、実装者が提供するcredentialストアから次の情報を取得する（参考: インターフェース例）。

```ts
interface WakeCredential {
  credentialId: Uint8Array;
  userId: string;            // 実装者のユーザーID（不透明）
  userHandle: Uint8Array;    // WebAuthnの user.id
  publicKey: Uint8Array;     // COSE_Key
  algorithm: number;         // COSE alg
  signCount: number;
  backupEligible: boolean;
  status: "active" | "pending" | "suspended" | "deleted";
}
```

- 状態が`active`でないcredential（承認待ち、停止中、削除済み）は、KX・KR・TA・TA+KRの**いずれの儀式でも受理してはならない**（MUST NOT）。
- credentialを停止・削除したときは、そのcredentialでログインまたはKRしたセッションを失効させるべきである（SHOULD）。WAKEはこのための失効機能（§8.9）を提供する。

### 6.6 ユーザー名指定方式と列挙対策

`/auth/start`は次の2つの方式をサポートする。

| 方式 | `allowCredentials` | 備考 |
|---|---|---|
| `discoverable`（推奨） | 空 | ユーザーはassertionの`userHandle`とcredentialから特定する。ユーザー名を送らないため、ユーザー列挙が起きない |
| `username` | 指定ユーザーの有効なcredential | ユーザー列挙対策が必要 |

`username`方式では、存在しないユーザーに対しても、実在ユーザーと区別できない応答を返すべきである（SHOULD）。例: `HMAC(サーバー秘密, username)`から決定的に生成した偽のcredential IDを、実在ユーザーと同じ件数分布で返す。応答時間もそろえる。

---

## 7. WAKE-KX：ログインと鍵交換（Key Exchange）

### 7.1 シーケンス

```text
Client                                             Server
  | POST /auth/start {mode, username?}               |
  |------------------------------------------------->| exchangeId, sessionId, serverNonce,
  |                                                  | 一時ECDH鍵ペアを生成し、交換状態を保存
  |<-------------------------------------------------| 公開情報 + WebAuthnオプション
  | 一時ECDH鍵ペアを生成                             |
  | th → challenge → navigator.credentials.get       |
  | ss → 鍵導出 → clientFinished → 秘密鍵を破棄       |
  | POST /auth/complete                              |
  |   {exchangeId, clientPublicKey, assertion,       |
  |    clientFinished}                               |
  |------------------------------------------------->| 保存値からth・challengeを再計算
  |                                                  | WebAuthn検証 → ss → 鍵導出
  |                                                  | clientFinished検証 → 原子的に確定
  |                                                  | （交換をCOMPLETED、セッションをACTIVE）
  |<-------------------------------------------------| serverFinished + セッション情報
  | serverFinished検証 → 鍵を保存 → ACTIVE           |
```

通信は2往復である。ログイン画面の表示時に`/auth/start`を先に呼んでおけば、ユーザーが体感する往復は1回になる。

### 7.2 `POST /auth/start`

**要求**

```json
{ "mode": "discoverable" }
```

```json
{ "mode": "username", "username": "nozomi" }
```

**応答**

```json
{
  "version": "WAKE/1",
  "exchangeId": "<base64url 16B>",
  "sessionId": "<base64url 32B>",
  "epoch": 0,
  "serverNonce": "<base64url 32B>",
  "serverPublicKey": "<base64url 65B>",
  "serverTime": 1791590400000,
  "expiresAt": 1791590700000,
  "webauthn": { "rpId": "example.com", "allowCredentials": [], "userVerification": "required", "timeout": 270000 }
}
```

`sessionId`は予約された識別子であり、これだけでは何の権限も持たない。

`serverTime`は応答を作った時点のサーバー時刻（ミリ秒）である。クライアントは`expiresAt`を端末の時刻とそのまま比べてはならない（MUST NOT）。`serverTime`は認証されていないため、再送の期限の判断（§7.7）にだけ使い、セッションの時刻補正（§8.5）には使わない。

### 7.3 `POST /auth/complete`

**要求**

```json
{
  "exchangeId": "<base64url 16B>",
  "clientPublicKey": "<base64url 65B>",
  "assertion": { "...": "AuthenticationResponseJSON" },
  "clientFinished": "<base64url 32B>"
}
```

**応答**

```json
{
  "sessionId": "<base64url 32B>",
  "epoch": 0,
  "serverTime": 1791590460000,
  "absoluteExpiresAt": 1792195260000,
  "idleTimeoutSec": 86400,
  "serverFinished": "<base64url 32B>"
}
```

### 7.4 交換状態

サーバーは交換ごとに次の状態を保存する（論理モデル。付録A）。

```text
PENDING ──検証成功＋原子的確定──▶ COMPLETED ──保持期間の経過──▶ 削除
   ├──期限切れ──────────────▶ EXPIRED（一時秘密鍵を直ちに破棄）
   └──鍵世代が進んだ（KRのみ）──▶ SUPERSEDED（一時秘密鍵を直ちに破棄）
```

- 交換のTTLは既定300秒とする。期限の比較には、インスタンス間で一貫した時刻（DBの時刻、またはNTPで同期されたサーバー時刻）を使う（MUST）。
- 終了状態（`COMPLETED`・`EXPIRED`・`SUPERSEDED`）に移るとき、一時ECDH秘密鍵を利用不能にしなければならない（MUST）。期限切れの交換は定期的に処理して秘密鍵を破棄する（SHOULD）。
- 検証に失敗しても交換状態は変更しない（MUST）。`exchangeId`は通信経路から観測できるため、失敗のたびに交換を無効にすると、観測者が正規のログインを妨害できる。試行回数はレート制限で抑える。

### 7.5 サーバー処理

```text
procedure AuthComplete(req):
  ex ← 交換状態を exchangeId で取得
  if ex が存在しない or ex.kind ≠ login: return auth_failed
  公開鍵の形式と曲線上の点を検証（§5.2）。不正なら bad_request
  th ← Transcript(0x01, ex.exchangeId, ex.sessionId, 0, ε, ex.serverNonce, ex.serverPublicKey, req.clientPublicKey)

  if ex.state = COMPLETED:                               // §7.6
     if th = ex.th and req.clientFinished = ex.clientFinished: return ex.response
     return auth_failed
  if ex.state ≠ PENDING or now ≥ ex.expiresAt: return auth_failed

  cred ← WebAuthn検証(req.assertion, Challenge(th, ε), 儀式 = KX, 指定ユーザー = ex.requestedUserId)   // §6.2
  if 失敗: return auth_failed                           // 交換状態は変更しない
  ss ← ECDH(ex.serverPrivateKey, req.clientPublicKey); 鍵導出（§5.6）; 秘密鍵と ss を破棄
  if not HMAC-Verify(fk_c, clientFinished入力, req.clientFinished): return auth_failed

  寿命の決定: absoluteExpiresAt ← now + authLifetime, hardCapAt ← now + hardCap
  response ← {sessionId, epoch: 0, serverTime: now, absoluteExpiresAt, idleTimeoutSec, serverFinished}

  原子的に:
    (a) 交換を COMPLETED にする（条件: state = PENDING かつ expiresAt > now）。
        th・clientFinished・response を保存し、一時秘密鍵を破棄する
    (b) (a) が成功した場合に限り、セッションを ACTIVE で作成する
        （userId, credentialId, established_origin = clientDataJSON.origin, epoch 0 の鍵, th, 寿命）
    (c) (a) が成功した場合に限り、署名カウンターを更新する
  if (a) が失敗: 交換状態を読み直して §7.6 の判定を行う
  return response
```

交換の単回使用は、(a)の条件付き更新とセッション作成を**同じ原子的操作**で行うことで保証する（MUST）。具体的な実現方法（RDBのトランザクション、D1の`batch()`、Durable Objectsなど）は実装者が選ぶ。

### 7.6 冪等性と再送

- 交換が`COMPLETED`で、受信した要求から計算した`th`と`clientFinished`が保存値と一致する場合、サーバーは保存済みの応答をそのまま返さなければならない（MUST）。このときWebAuthnを再検証しない。
- この判定は安全である。`clientFinished`を作れるのはクライアントの一時秘密鍵を持つ者だけであり、応答の内容（`serverFinished`、期限、時刻）は秘密ではない。
- ECDSA署名は毎回値が変わるため、assertionのバイト列の一致を判定条件にしてはならない（MUST NOT）。
- 保存済みの応答は、交換の期限から少なくとも10分間保持する（SHOULD）。

### 7.7 クライアント処理

1. `POST /auth/start`を呼ぶ。
2. 一時ECDH鍵ペアを生成する（秘密鍵は抽出不可）。
3. `th`と`challenge`を計算し、`options.challenge`に設定して`navigator.credentials.get()`を呼ぶ。
4. `ss`を導出し、`k_c2s`・`k_s2c`を抽出不可のAES-GCM鍵、`fk_c`・`fk_s`をHMAC鍵として導出する。`clientFinished`を計算し、一時秘密鍵と`ss`を破棄する。
5. `/auth/complete`の要求本文を保持し、最初の1回は必ず送る。ネットワークエラーの場合は、交換の期限まで**同じ本文**を再送する。期限は端末の時刻に換算して判断する。`/auth/start`の応答を受け取った時点の端末時刻を`t₀`とすると、期限は`t₀ + (expiresAt − serverTime)`である。
6. `serverFinished`を検証する。失敗した場合はすべての鍵を破棄し、最初からやり直す。
7. 鍵・`th`・時刻のオフセット（§8.5）を保存し、セッションを`ACTIVE`とする。

### 7.8 失敗時の扱い

| 事象 | サーバー | クライアント |
|---|---|---|
| 不明・期限切れの`exchangeId` | `auth_failed` | `/auth/start`からやり直す |
| 公開鍵の形式不正 | `bad_request` | 実装のバグとして扱う |
| WebAuthn検証失敗 | `auth_failed`（交換状態は変えない） | やり直す |
| `clientFinished`不一致 | `auth_failed`（交換状態は変えない） | やり直す |
| 応答が届かない | — | 同じ本文を再送する |
| `serverFinished`不一致 | — | 鍵を破棄してやり直す。サーバー側に残るセッションは無操作期限で失効する |

---

## 8. WAKE-SM：セッション管理（Session Management）

### 8.1 セッション状態と寿命

| 状態 | 説明 |
|---|---|
| `ACTIVE` | 暗号化通信が可能 |
| `REVOKED` | 明示的なログアウトや失効操作で無効化された |
| `EXPIRED` | 期限切れ |

| 期限 | 既定値 | 説明 |
|---|---|---|
| 絶対有効期限 `absoluteExpiresAt` | ログイン時刻 + 7日 | KRで`min(hardCapAt, KR時刻 + 7日)`まで延長できる |
| 上限 `hardCapAt` | ログイン時刻 + 30日 | KRでも延長できない |
| 無操作期限 `idleTimeoutSec` | 86400秒 | 最後の活動から経過したら失効する |

既定値は規格の固定値ではなく、サービスの脅威モデルに合わせて設定する。期限が切れたセッションは鍵を削除し、次の通信では新しいWebAuthnログインを要求する。

### 8.2 メッセージ形式

```text
MsgHeader = LP(
  ascii("WAKE/1 msg"),
  u8(dir),             // 0x01 = c2s, 0x02 = s2c
  sessionId,           // 32B
  u32(epoch),
  requestId,           // 16B
  u64(issuedAt),       // ミリ秒
  ascii(context),      // 1〜256B、各バイトは 0x20〜0x7E
  iv                   // 12B
)

Wire = u32(len(MsgHeader)) ‖ MsgHeader ‖ Ciphertext ‖ Tag(16B)
```

- `len(MsgHeader)`は`115 + len(context)`であり、116〜371バイトの範囲になる。
- HTTPでは`Content-Type: application/wake`とし、本文を`Wire`とする。JSONに埋め込む場合は`base64url(Wire)`とする。
- 受信側は、ラベルの一致、フィールド数8、固定長フィールドの長さ、contextの文字種と長さ、末尾に余分なバイトがないことを厳密に検査しなければならない（MUST）。

### 8.3 暗号化と復号

```text
Seal(dir, session, epoch, requestId, context, plaintext):
  key ← (dir = c2s) ? session.k_c2s[epoch] : session.k_s2c[epoch]
  iv  ← CSPRNG(12)                        // 呼び出し側からIVを受け取ってはならない
  issuedAt ← (クライアント) localNow + offset /（サーバー） serverNow
  H ← MsgHeader(dir, session.sessionId, epoch, requestId, issuedAt, context, iv)
  C ← AES-256-GCM-Encrypt(key, iv, plaintext, aad = H)    // 暗号文 ‖ 16Bタグ
  return u32(len(H)) ‖ H ‖ C
```

サーバーは要求を次の順で処理する（MUST）。

1. `Wire`の長さを検査し、`MsgHeader`を厳密に解析する。`dir`が`0x01`でなければ`bad_request`。
2. `sessionId`でセッションを取得する。存在しない、`ACTIVE`でない、または期限切れなら`reauth`。
3. 鍵世代の受理判定を行う（§8.6）。
4. **受信したヘッダーのバイト列をそのままAADとして**復号する。失敗したら`reauth`。
5. `|serverNow − issuedAt| > W`なら、暗号化エラー`stale_request`を返す（§8.5）。
6. `context`がそのエンドポイントで受け付けるものでなければ、暗号化エラー`invalid_context`を返す。
7. 処理を振り分ける。

AADを受信側で組み立て直してはならない（MUST NOT）。

### 8.4 requestIdと要求・応答の対応

- c2s: クライアントは暗号化のたびに新しい`requestId`を生成する（MUST）。再送する場合も、新しい`requestId`と新しいIVで暗号化し直す。
- s2c: サーバーの応答は、要求と同じ`sessionId`・`epoch`・`requestId`・`context`を持ち、`issuedAt`はサーバー時刻、IVは新しい乱数とする（MUST）。
- クライアントは、`dir = 0x02`で、`sessionId`・`epoch`・`requestId`・`context`が未完了の要求と一致する応答だけを受理し、最初の1件で確定する（MUST）。
- WAKEは通常APIの要求のリプレイを拒否しない。同じ要求が複数回届いた場合、サーバーはそのたびに新しいIVで応答を暗号化する。業務上の冪等性はAPI実装者が平文の中の冪等キーなどで実現する。

### 8.5 issuedAtと時刻補正

- クライアントは、KX/KRの完了時に`offset = serverTime − localNow`を計算して保存する。以後、各応答ヘッダーの`issuedAt`（認証済みのサーバー時刻）で更新してよい。
- c2sの`issuedAt`は`localNow + offset`とする。
- サーバーは、`|serverNow − issuedAt| ≤ W`（既定300秒）の要求だけを処理する（MUST）。範囲外の要求には、暗号化エラー`stale_request`を返す。この応答の`issuedAt`でクライアントはoffsetを補正し、新しい`requestId`で再送する。
- `issuedAt`は、捕捉された暗号文を再送できる時間を制限する補助的な仕組みであり、リプレイ防止ではない。

### 8.6 鍵世代の受理規則

| 受信した`epoch` | 条件 | サーバーの動作 |
|---|---|---|
| current | — | 受理する |
| current − 1 | `now ≤ prev_valid_until` | 受理する（応答も同じ旧世代の鍵で暗号化する） |
| current − 1 | 猶予期間の後 | `epoch_retired` |
| current − 1 より古い | — | `epoch_retired` |
| current より新しい | — | `reauth` |

応答は常に、**要求と同じ鍵世代**の`k_s2c`で暗号化する（MUST）。

### 8.7 IVの使用上限

- 1つの鍵による暗号化は**2³²回を超えてはならない**（MUST。NIST SP 800-38D）。
- 運用目標として、1つの鍵につき**2²⁴回**以下に保つべきである（SHOULD）。2²⁴回時点のIV衝突確率は約2⁻⁴⁹、2²⁸回で約2⁻⁴¹である。
- 鍵世代の最大寿命を設けなければならない（MUST）。既定では`authLifetime`（7日）であり、KRで新しい鍵世代に切り替わる。
- 実装は、上限をどのように保証するかを文書化しなければならない（MUST）。具体的な管理方法は実装者が選ぶ。参考:
  - **クライアント（c2s）**: c2sを暗号化するのは正規クライアントのタブだけなので、正確に数えられる。IndexedDBのカウンターをブロック単位（例: 4096回）で予約すれば、タブ間の協調なしに上限値を管理できる。2²⁴回で次のWebAuthnの機会にKRを行い、実装の定めるハード上限（2²⁸回を推奨）で暗号化を止めてKRまたは再ログインを求める。
  - **サーバー（s2c）**: s2cの応答は、リプレイされた要求にも生成されるため、攻撃者が鮮度窓の間に増やせる。インスタンスごと・セッションごとのレート制限（認証タグが正しい要求をリプレイも含めて数える）と鍵世代の寿命を組み合わせ、`最大インスタンス数 × レート × 鍵世代の寿命 ≤ ハード上限`となるよう設定する。例: 10インスタンス × 40 req/s × 7日 ≈ 2.42×10⁸ < 2²⁸。
- 暗号化する平文の長さには上限を設ける（MUST）。受信側は、復号の前に`Wire`の長さから平文の長さを求めて上限と比較し、超えていれば`too_large`とする（MUST）。上限はサービスが決める。参考: ETを使う場合、ETの本文の上限に`EtRequest`の枠組み（パス、クエリ、ヘッダー）を足した値。

### 8.8 context

- WAKE内部APIのcontextは§12.2で予約する。`wake/`または`wake-`で始まるcontextを、実装者が独自に定義してはならない（MUST NOT）。
- 独自APIのcontextは実装者が定義する。形式は`"METHOD ルートテンプレート"`（例: `"POST /api/transfer"`）を推奨する（SHOULD）。
- サーバーは、観測したURLではなく、ルートごとに設定したcontextとバイト単位で比較する（MUST）。これにより、リバースプロキシによるパスの書き換えの影響を受けない。

### 8.9 ログアウトと失効

**ログアウト（`wake/logout`）**

1. クライアントは`wake/logout`を暗号化して送る。
2. サーバーは復号に成功した後、セッションを`ACTIVE`から`REVOKED`へ原子的に変更する。
3. サーバーは、要求と同じ鍵世代の鍵で応答を暗号化してから、セッション鍵を削除する。そのセッションの`PENDING`な交換と承認試行も無効にする。
4. クライアントは応答の有無にかかわらずローカルの鍵を削除し、他のタブに通知する。
5. `sessionId`の指定だけでセッションを失効させる経路を、利用者向けに公開してはならない（MUST NOT）。

**サーバー側の失効機能（参考: ライブラリAPI）**

- `revokeSession(sessionId)`
- `revokeSessionsByUser(userId)`
- `revokeSessionsByCredential(credentialId)`: そのcredentialでログインまたはKRしたセッションを失効させる（§6.5）。

失効は、遅くとも`Δ`（既定30秒）以内に全インスタンスで反映されなければならない（MUST）。

### 8.10 サーバー側の鍵管理と複数インスタンス

**要件（MUST）**

1. 一時ECDH秘密鍵は、交換が終了状態に移った時点で利用不能にする。
2. セッション鍵と一時秘密鍵を、保存時に保護する。暗号化して保存する場合、暗号化に使う鍵（KEK）は、保存先とは別の保護境界で管理する。
3. 暗号化して保存する場合、AADでセッション・鍵世代（一時秘密鍵の場合は`exchangeId`）に結び付け、DB上で行を入れ替えても復号できないようにする。推奨形式:
   ```text
   セッション鍵:   aad = LP(ascii("WAKE/1 key-wrap"), sessionId, u32(epoch))
   一時秘密鍵:     aad = LP(ascii("WAKE/1 exchange-key"), exchangeId)
   ```
4. セッション失効後は、その鍵による認証を受け付けない。
5. 交換の確定、鍵世代の更新、ログアウト、TAの認否の確定を、複数インスタンス間で原子的に管理する。
6. 鍵をアプリケーションのログに出力しない。

**推奨（SHOULD）**

- インスタンスごとのメモリキャッシュには、`(sessionId, epoch)`をキーとして鍵と状態を置き、TTLを`Δ`以下にする。
- `last_activity_at`は、前回の更新から粒度`G = min(idleTimeoutSec / 8, 15分)`以上経過した場合だけ、条件付きで更新する。通常APIの処理ごとに共有DBへ書き込むことは必須ではない。
- 共有ストアが利用できない場合、`Δ`以内の新鮮なキャッシュがある通常の要求だけを処理し、それ以外は`retry`とする。KX・KR・TA・ログアウトは安全側に倒して失敗させる。

一時秘密鍵をDBに保存する場合、DB本体だけでなくWALやバックアップにも残り得る。前方秘匿性は、それを保護する鍵が破棄されるまでに限られることに注意する。具体的な保存方式（RDB、Cloudflare D1、Durable Objects、外部KMS、プロセスメモリなど）は実装者が選ぶ。

### 8.11 クライアント側の保存と複数タブ

- `CryptoKey`は`extractable: false`で生成・導出し、IndexedDBにStructured Cloneで保存する（SHOULD）。
- 保存する内容: `sessionId`、現在の鍵世代、世代ごとの`k_c2s`・`k_s2c`・`th`、時刻のoffset、`established_origin`、KR中の保留世代。
- IndexedDBを正とし、`BroadcastChannel`は通知だけに使う。タブの可視化・フォーカス時と、`epoch_retired`を受けたときにもIndexedDBを読み直す。
- KR全体の排他にはWeb Locksを使う。IndexedDBのトランザクションはWebAuthnの待ち時間をまたいで保持できないため、最後の切り替えにだけ使う。
- 保存できない環境では、ページの読み込みごとに再ログインを求める。
- 抽出不可の鍵でも、同一オリジンで動く悪意あるスクリプトによる鍵の使用は防げない（§3.4）。

---

## 9. WAKE-KR：WebAuthnによる鍵更新（Key Rotation）

### 9.1 シーケンス

```text
Client（epoch e で暗号化）                          Server
  | wake/kr/start {}                                 |
  |------------------------------------------------->| 交換を保存（kind=rekey, target_epoch=e+1,
  |                                                  | prev_th=th_e）
  |<-------------------------------------------------| exchangeId, epoch, serverNonce,
  |                                                  | serverPublicKey, WebAuthnオプション
  | Web Lock取得 → ECDH → th_{e+1} → challenge       |
  | → WebAuthn → 鍵導出 → clientFinished             |
  | 保留世代 e+1 として IndexedDB に保存             |
  | wake/kr/complete {...}                           |
  |------------------------------------------------->| 検証 → 原子的に確定（交換COMPLETED、
  |                                                  | セッションの current_epoch = e+1）
  |<-------------------------------------------------| epoch e の鍵で暗号化した応答
  | serverFinished検証 → current = e+1 → 通知        |
```

### 9.2 `wake/kr/start`

要求の平文は`{}`。応答:

```json
{
  "exchangeId": "<base64url 16B>",
  "epoch": 1,
  "serverNonce": "<base64url 32B>",
  "serverPublicKey": "<base64url 65B>",
  "expiresAt": 1791590700000,
  "webauthn": { "rpId": "example.com", "allowCredentials": [{ "type": "public-key", "id": "<base64url>" }], "userVerification": "required", "timeout": 270000 }
}
```

`epoch`は更新後の世代である。`prevTh`は通信に含めず、クライアントは保存している現世代の`th`を使う。

1つのセッションで同時に`PENDING`にできるKR交換は既定3件とする。超えた場合は最も古いものを`SUPERSEDED`にする。

### 9.3 `wake/kr/complete`

要求:

```json
{
  "exchangeId": "<base64url 16B>",
  "clientPublicKey": "<base64url 65B>",
  "assertion": { "...": "AuthenticationResponseJSON" },
  "clientFinished": "<base64url 32B>"
}
```

応答（要求と同じ鍵世代eの`k_s2c`で暗号化）:

```json
{
  "epoch": 1,
  "serverTime": 1791590460000,
  "absoluteExpiresAt": 1792195260000,
  "idleTimeoutSec": 86400,
  "serverFinished": "<base64url 32B>"
}
```

### 9.4 サーバー処理

1. 交換を取得する。`kind = rekey`で、交換の`session_id`が要求ヘッダーの`sessionId`と一致し、`bound_approval_id`が空でなければならない（TA+KR用の交換は§10.8でのみ確定できる）。
2. 交換が`COMPLETED`なら、§7.6と同じ規則で保存済みの応答を返す。応答は**新しい要求の`requestId`で暗号化し直す**。
3. `PENDING`で期限内であることを確認する。`target_epoch ≠ current_epoch + 1`なら交換を`SUPERSEDED`にして`conflict`を返す。
4. `th`（mode=0x02、`prevTh = cur_th`）とChallengeを計算し、WebAuthnを検証する（§6.2。credentialの所有者がセッションのユーザーであること、originが`established_origin`であることを含む）。
5. ECDH・鍵導出・`clientFinished`の検証を行う。
6. 原子的に、交換を`COMPLETED`にし（条件: `PENDING`かつ期限内）、セッションを更新する（条件: `current_epoch = e`かつ`ACTIVE`）。更新内容: `current_epoch = e+1`、新しい鍵、`cur_th = th_{e+1}`、旧世代の鍵を`prev`へ、`prev_valid_until = now + G_epoch`、`auth_time = now`、`absolute_expires_at = min(hard_cap_at, now + authLifetime)`、`last_auth_credential_id`。
7. 応答を返す。

検証に失敗した場合、交換状態は変更しない。

### 9.5 旧世代の扱い

- 旧世代（e）は猶予期間`G_epoch`（既定60秒、最大300秒）の間だけ受理する（§8.6）。他のタブの通信中の要求を処理するためである。
- 猶予期間が過ぎたら、旧世代の鍵を物理的に削除する（SHOULD。定期処理または次のKR時）。
- KRは`sessionId`を維持する。他のデバイスのセッションには影響しない。

### 9.6 クライアントの回復手順

| 状況 | 対処 |
|---|---|
| `wake/kr/complete`の応答が届かない | 同じ平文を、新しい`requestId`で世代eとして再送する。サーバーは保存済みの応答を返す |
| 再送が`epoch_retired`で拒否された | 保留世代e+1の鍵で`wake/session`を送る。成功すればe+1に切り替え、失敗すれば再ログイン |
| `conflict` | 別のタブが先に更新している。保留世代を破棄し、IndexedDBから最新の世代を読み込む |
| `serverFinished`不一致 | 保留世代を破棄し、セキュリティイベントとして記録して再ログインする |

### 9.7 同時実行と複数タブ

- クライアントはWeb Locks（例: `wake-kr:<sessionId>`）でKRを1タブに限る。
- サーバーは鍵世代の条件付き更新で、同時に確定するKRを1つに限る。
- 確定後、クライアントはIndexedDBのトランザクションで現在の世代を切り替え、`BroadcastChannel`で他のタブに通知する。

### 9.8 有効期限との関係

KRはUV付きの再認証なので、`auth_time`を更新し、絶対有効期限を`min(hardCapAt, now + authLifetime)`まで延長する。`hardCapAt`は延長しない。KRの頻度に上限を設けてもよい（MAY）。

---

## 10. WAKE-TA：操作要求と認否（Transaction Authorization）

### 10.1 概要と責任範囲

WAKE-TAは、**操作要求の管理と、その要求に対する認否の確定だけ**を担う。

```text
【アプリケーションサーバー】 要求を生成 → content を確定 → WAKE-TAに登録 → operationId を受け取る
【WAKE-TA】                 PENDING → WebAuthnによる承認 / 拒否 → APPROVED / REJECTED
【アプリケーションサーバー】 WAKE-TAから認否結果を取得 → 実装者が独自に処理
```

- WAKE-TAは業務処理のパラメーターを受け取らず、操作を実行しない。
- WAKEは「このOperationが、指定された認否者によって承認された（または拒否された）」という事実を保証する。その結果をどの業務処理に、何回使うかは保証しない（§14.2）。
- 1つのOperationの認否者は1人とする。複数人承認や承認割合の集計は、実装者が複数のOperationを使って管理する。

### 10.2 Operationの作成（サーバー側API）

Operationは、実装者のサーバーからだけ作成できる（MUST）。利用者向けの作成APIは設けない。

**入力（参考: `createOperation`）**

| 項目 | 必須 | 内容 |
|---|---|---|
| `content` | ✓ | 文面プロファイル（§10.4）を満たすUTF-8文字列 |
| `approverUserId` | ✓ | 認否者の`userId`（1〜256バイト） |
| `expiresAt` | ✓ | 承認期限。`now < expiresAt ≤ now + maxOperationLifetime`（既定30日） |

**処理**

1. 実装者は、呼び出す前に`approverUserId`の妥当性と、その認否者を指定する権限を検証する（実装者の責任）。
2. WAKEは`content`を文面プロファイルで検査し、違反があれば`invalid_content`で拒否する。
3. WAKEはTA Nonce（16B）を生成し、`hashInput`と`operationId`を計算する（§10.3）。
4. WAKEは`operationId`を一意キーとしてOperationを`PENDING`で保存する。万一既存の`operationId`と衝突した場合、Nonceを生成し直す。**既存のOperationを作成結果として返してはならない**（MUST NOT）。
5. 戻り値: `operationId`、`nonce`、`hashInput`、`expiresAt`。

`content`、Nonce、`hashInput`、`approverUserId`は作成後に変更できない（MUST）。DBの制約で更新を禁止することを推奨する。

### 10.3 hashInputとoperationId

```text
nonceHex    = 小文字16進(TA Nonce 16B)                  // 32文字
hashInput   = content ‖ "\n" ‖ "WAKE-TA-Nonce: " ‖ nonceHex
operationId = SHA-256(utf8(hashInput))                   // 32B
外部表現     = 小文字16進(operationId)                    // 64文字
```

- 区切りは改行（U+000A）1つ、ラベル`WAKE-TA-Nonce: `（コロンの後に空白1つ）である。
- `hashInput`の末尾48バイトは常にこの固定形式のNonce行である。`content`は改行を含まない（§10.4）ため、`hashInput`の改行は区切りの1つだけであり、`content`とNonceを一意に分離できる。
- ハッシュ入力には`hashInput`のUTF-8バイト列だけを使い、ラベルや非公開のパラメーターを加えない。一般的なSHA-256計算ツールで`operationId`を再現できるようにするためである。
- 128bitのNonceを含むため、同じ`content`でも別の`operationId`になり、`operationId`から`content`を辞書攻撃で推測することもできない。

**例（参考）**

`content`の中の`\n`は改行ではなく、バックスラッシュと`n`の2文字である（§10.4）。

```text
content:
送金要求\n送金先: 山田太郎\n金額: 10000 JPY

TA Nonce: 3f9a1c7e5b2d4f6081a3c5e7092b4d6f

hashInput（104バイト）:
送金要求\n送金先: 山田太郎\n金額: 10000 JPY
WAKE-TA-Nonce: 3f9a1c7e5b2d4f6081a3c5e7092b4d6f

operationId:
1140095b9147435cc75d76b00be2938ebd69885f938afdcc02337c925cedfd74
```

承認ページのURLは`https://example.com/approve/{operationId}`の形式を想定する（URLの形式は実装者が決める）。

### 10.4 文面プロファイル

`content`は次をすべて満たさなければならない（MUST）。WAKEはOperationの作成時に検査し、違反があれば拒否する。正規クライアントも表示前に同じ検査を行う。

| 規則 | 内容 |
|---|---|
| 符号化 | 正しい形式のUTF-8（孤立サロゲートや不正なバイト列を含まない） |
| 長さ | `utf8(content)`が1〜65,536バイト |
| 正規化 | **NFCであること**（NFCでなければ拒否する。WAKEは変換しない） |
| 制御文字 | 一般カテゴリCcの文字（U+0000–U+001F、U+007F–U+009F）を含まない。**LF（U+000A）、CR、タブも禁止**であり、`content`は常に1行である |
| 先頭・末尾 | U+0020、U+3000で始まったり終わったりしてはならない |

- Cc以外の文字（ゼロ幅文字、双方向制御文字、異体字セレクター、私用領域、絵文字など）は、プロファイルでは拒否しない。これらで文面の見た目を偽装されないよう、承認画面で可視化する（§10.11）。
- 複数行の文面を表したい場合は、改行の代わりにバックスラッシュと`n`の2文字（`\n`）を使う。これは単なる文字であり、ハッシュの入力もこの2文字のままである。承認画面は、これを改行として表示する表示形式を選べるようにしてよい（§10.11）。
- 実装者は、`content`に表示を紛らわしくする文字を入れないよう、自分のサーバーで文面を組み立てる段階で注意する（SHOULD）。

### 10.5 状態遷移

```text
            PENDING
               │
   ┌───────┬───┴────┬──────────┐
   ▼       ▼        ▼          ▼
APPROVED REJECTED CANCELLED EXPIRED
```

| 状態 | 確定のしかた |
|---|---|
| `APPROVED` | 認否者がWebAuthnで承認する（§10.7） |
| `REJECTED` | 認否者が拒否する（WAKEセッション認証のみ。§10.9） |
| `CANCELLED` | 実装者のサーバーが取り消す（§10.9） |
| `EXPIRED` | `PENDING`のまま`expiresAt`を過ぎる。参照時に判定するだけでもよい |

- 1つのOperationに確定する認否は1つだけである（MUST）。確定は`PENDING`を条件とする原子的な状態遷移で行う。
- 確定した認否は変更できない。
- 同じ承認の再送で新しい承認結果が生成されることはない。

### 10.6 利用者向けAPI

すべてWAKEで暗号化して呼び出す（§12）。`operationId`は小文字16進、その他のバイナリはBase64urlで表す。セッションのユーザーが`approverUserId`でないOperationは、すべてのAPIで`not_found`として扱う（MUST）。

**`wake/ta/list`**

```json
{ "status": "PENDING", "limit": 20, "cursor": "<opaque>" }
```

```json
{
  "operations": [
    { "operationId": "5f1a…b461", "content": "…", "nonce": "3f9a…4d6f", "status": "PENDING",
      "createdAt": 1791590400000, "expiresAt": 1791676800000 }
  ],
  "nextCursor": "<opaque>"
}
```

`status`と`cursor`は省略できる。`limit`は1〜20（既定20）。

**`wake/ta/get`**

```json
{ "operationId": "5f1a…b461" }
```

```json
{
  "operationId": "5f1a…b461",
  "content": "送金要求\n送金先: 山田太郎\n金額: 10000 JPY",
  "nonce": "3f9a1c7e5b2d4f6081a3c5e7092b4d6f",
  "status": "PENDING",
  "createdAt": 1791590400000,
  "expiresAt": 1791676800000,
  "decidedAt": null
}
```

`hashInput`は通信に含めない。クライアントは`content`と`nonce`から§10.3の規則で組み立てる。

**`wake/ta/challenge`**

```json
{ "operationId": "5f1a…b461", "rekey": false }
```

```json
{
  "approvalId": "<base64url 16B>",
  "approvalNonce": "<base64url 32B>",
  "expiresAt": 1791590700000,
  "webauthn": { "rpId": "example.com", "allowCredentials": [{ "type": "public-key", "id": "<base64url>" }], "userVerification": "required", "timeout": 270000 },
  "kr": null
}
```

- `rekey: true`の場合、`kr`に`{exchangeId, epoch, serverNonce, serverPublicKey}`を含める。このKR交換は承認試行に結び付けて保存する（`bound_approval_id`）。
- 承認試行のTTLは既定300秒。1つのOperationで同時に有効な承認試行は既定5件までとする。
- Operationが`PENDING`でない、または期限切れなら、`already_decided`または`expired`を返す。

**`wake/ta/approve`**

```json
{
  "approvalId": "<base64url 16B>",
  "operationId": "5f1a…b461",
  "assertion": { "...": "AuthenticationResponseJSON" },
  "kr": null
}
```

TA+KRの場合、`kr`は`{exchangeId, clientPublicKey, clientFinished}`とする。

```json
{
  "operationId": "5f1a…b461",
  "ta": { "result": "approved", "status": "APPROVED" },
  "kr": null
}
```

- `ta.result`: `approved` / `already_decided` / `expired`
- `kr`（TA+KRの場合）: `{ "result": "committed", "epoch", "serverTime", "absoluteExpiresAt", "idleTimeoutSec", "serverFinished" }`、または`{ "result": "conflict" }` / `{ "result": "expired" }`

**`wake/ta/reject`**

```json
{ "operationId": "5f1a…b461" }
```

```json
{ "result": "rejected", "status": "REJECTED" }
```

`result`: `rejected` / `already_decided` / `expired`

### 10.7 承認の処理

```text
procedure Approve(session, req):
  att ← 承認試行を approvalId で取得
  if att が存在しない or att.sessionId ≠ session.sessionId: return not_found
  if att.state = CONSUMED: return att.result                       // 冪等応答（新しい requestId で暗号化）
  if att.state ≠ PENDING or now ≥ att.expiresAt: return expired
  op ← att.operationId の Operation
  if req.operationId ≠ op.operationId: return invalid_request
  if session.userId ≠ op.approverUserId: return not_found

  thOrε ← ε
  if req.kr ≠ null:
     ex ← 交換を req.kr.exchangeId で取得
     要件: ex.kind = rekey, ex.boundApprovalId = att.approvalId, ex.sessionId = session.sessionId
     th ← Transcript(0x02, …, prevTh = session.cur_th, …, req.kr.clientPublicKey)
     thOrε ← th
  ta ← TA(att.approvalId, op.operationId, att.approvalNonce, session.sessionId)
  WebAuthn検証(req.assertion, Challenge(thOrε, ta), 儀式 = TA or TA+KR)    // §6.2
  if 失敗: return webauthn_failed                                  // 承認試行は変更しない
  if req.kr ≠ null: ECDH・鍵導出・clientFinished の検証。失敗なら webauthn_failed

  原子的に:
    (1) 承認試行を CONSUMED にする（条件: PENDING かつ期限内）。失敗したら読み直して冪等判定
    (2) Operation を APPROVED にする（条件: PENDING かつ expiresAt > now）
        → ta.result = approved / already_decided / expired
        → approved の場合、認否記録（§10.10）を保存
    (3) KR がある場合: §9.4 の手順6と同じ条件で交換とセッションを更新
        → kr.result = committed / conflict / expired。失敗した部分は (3) の中だけ取り消す
    (4) 結果を承認試行に保存する
  return 結果
```

- 承認試行は単回使用である。同じ承認試行で2回目の承認は確定しない。
- 承認試行を発行したセッションと、承認を送るセッションは一致しなければならない（MUST）。Operationの作成と承認は、別のセッションや別のデバイスで行ってよい。

### 10.8 TA+KR

- 1回のWebAuthn署名で、TA承認とKRの両方を認証する（§5.5）。
- TAとKRの結果は**独立して判定する**（MUST）。一方の失敗で、もう一方の成功を取り消さない。両方の判定と結果の保存は、1つの原子的操作の中で行う。
- KRの応答部分は、要求と同じ鍵世代の鍵で暗号化された`wake/ta/approve`の応答に含まれる。クライアントは`kr.result = committed`の場合に限り、`serverFinished`を検証して新しい世代に切り替える。

### 10.9 拒否・取消・期限切れ

- **拒否**: 認否者が`wake/ta/reject`で行う。WebAuthnは要求しない（悪用されても妨害にとどまる）。拒否は監査のため記録する。
- **取消**: 実装者のサーバーがサーバー側API（参考: `cancelOperation(operationId)`）で行う。v0.4では利用者向けの取消APIを定義しない。
- **期限切れ**: 承認・拒否・取消の確定条件には、必ず`expiresAt > now`を含める（MUST）。

### 10.10 認否記録と承認結果の取得

`APPROVED`の場合、WAKEは承認を後から再検証できるよう、次を保存しなければならない（MUST）。

| 項目 | 内容 |
|---|---|
| `decidedAt` | 確定時刻 |
| `decidedByUserId`, `decidedByCredentialId` | 認否者とcredential |
| `sessionId`, `approvalId`, `approvalNonce` | `ta`の入力 |
| `th` | TA+KRの場合のみ |
| `authenticatorData`, `clientDataJSON`, `signature` | assertionの生データ |

`REJECTED`と`CANCELLED`では、確定時刻と確定した主体を保存する。

実装者のサーバーは、サーバー側API（参考: `getOperation(operationId)`）で状態と認否記録を取得する。**クライアントが申告した認否結果を信用してはならない**（MUST NOT）。認否記録を外部で検証するためのデータ形式を付録Cに示す。

### 10.11 正規クライアントの承認画面

正規のWAKEクライアントは、承認画面で次を行わなければならない（MUST）。

1. URLから`operationId`を取得し、小文字16進64文字であることを確認する。
2. `wake/ta/get`で`content`と`nonce`を取得する。
3. `content`を文面プロファイル（§10.4）で検査し、`nonce`が小文字16進32文字であることを確認する。
4. `hashInput`を組み立て、`SHA-256(utf8(hashInput))`がURLの`operationId`と一致することを確認する。一致しなければ承認を中止し、警告する。
5. `hashInput`全体（Nonce行を含む）と`operationId`を表示する。等幅フォントを使うこと（SHOULD）。表示は次を満たさなければならない（MUST）。
   - Cc以外の不可視・特殊な文字（ゼロ幅文字、双方向制御文字、書式文字、異体字セレクター、私用領域、非文字など）を、位置とコードポイントが分かる目立つ形で可視化する。
   - 双方向制御文字が、可視化の印や周囲の表示を並べ替えないようにする（例: 各文字を独立した要素として左から右に並べる）。
   - `\n`（バックスラッシュと`n`）を文字どおりに表示する形式を必ず用意する。改行として表示する形式に切り替えられるようにしてよい（MAY）。
   - 表示の切り替えは見た目だけを変え、`content`・`hashInput`・`operationId`を変えてはならない。
6. ユーザーが承認ボタンを押したら、`wake/ta/challenge`を呼ぶ。
7. **手順1の`operationId`**と、受け取った`approvalId`・`approvalNonce`から`ta`とChallengeを計算し、WebAuthnを実行する。
8. `wake/ta/approve`を送る。

手順7で表示中の`operationId`をChallengeに使うため、サーバーの応答が別のOperationを指していても、署名はサーバー側の再計算と一致しない。ただし、悪意あるJavaScriptが実行されている場合、これらの検証自体が改ざんされ得る（§3.4）。

### 10.12 外部ツールによる独立検証

ユーザーは、表示された`hashInput`を外部のSHA-256計算ツールに入力し、結果がURLの`operationId`と一致することを確認できる。

- `hashInput`には区切りの改行1つと空白も含まれる。末尾に改行を付けてはならない。`content`の中の`\n`は2文字のまま入力する。
- 手元のツールを推奨する。例（`echo`は末尾に改行を付けたり`\n`を解釈したりするため使わない）:
  ```bash
  printf '%s' '送金要求\n送金先: 山田太郎\n金額: 10000 JPY
  WAKE-TA-Nonce: 3f9a1c7e5b2d4f6081a3c5e7092b4d6f' | shasum -a 256
  ```
- 外部のWebサイトに入力することを前提とするため、`content`に秘密情報を含めてはならない（§14.2）。
- 一致しない場合は承認してはならない。打ち直した場合は、全角・半角や似た記号（「ー」「─」「-」など）の違いで一致しないことがある。
- 文字列と`operationId`の一致だけでは、実際のWebAuthn Challengeがその`operationId`に対応していることまでは証明できない（§10.11）。

---

## 11. WAKE-ET：汎用暗号化API（Encrypted Transport）

### 11.1 経路

```http
POST /wake/transport
Content-Type: application/wake
```

contextは`wake-et`とする。WAKE-ETの利用は任意であり、実装者は独自APIでWAKEの暗号化・復号機能を直接使ってよい（§11.7）。

### 11.2 論理リクエスト・レスポンス

```text
EtRequest  = LP(ascii("WAKE/1 et-req"), ascii(method), ascii(url), headers, body)
EtResponse = LP(ascii("WAKE/1 et-res"), u16(status), headers, body)
headers    = LP(name1, value1, name2, value2, …)     // nameはASCII、valueはHTTP field octets。0組なら ε
```

ETの要求・応答は、Fetch Standardの`Request`・`Response`に組み立てられる範囲に限る。WAKEが検査するのは§11.3〜§11.4の形式だけで、内容の解釈には関与しない（§11.5）。

- `method`: RFC 9110のtoken。1〜32バイト。大文字・小文字は受け取ったまま運ぶ。Fetch Standardが禁止する`CONNECT`、`TRACE`、`TRACK`（大文字・小文字を区別しない）は拒否する（MUST）。
- `url`: §11.3のURI。
- `body`: 生のバイト列。既定の上限は1MiB。`method`が`GET`または`HEAD`（大文字・小文字を区別しない）の要求は、空でない本文を持てない（MUST）。
- `status`: 200〜599。`204`、`205`、`304`の応答は、空でない本文を持てない（MUST）。

### 11.3 URL

`url`はRFC 3986のURI-referenceとし、規則に合わないものは**拒否する**（MUST）。

- 6,144バイト以下で、URIに使える可視ASCII文字（unreserved、reserved、`%`）で構成される。フラグメント（`#`以降）は含めない。
- パーセントエンコードは`%`に16進2桁を続ける（16進は大文字・小文字のどちらでもよい）。
- スキームとオーソリティを持つ絶対URI（例: `wake://app/members`、`https://api.example.com/v1/items?id=1`）と、相対参照（例: `/members?id=1`）のどちらも運べる。
- ETは値を正規化しない。`.`/`..`セグメント、連続する`/`、エンコードされた区切り文字や非予約文字も、そのまま運ぶ。

### 11.4 ヘッダー

- 名前はRFC 9110のtoken（ASCII）とし、受け取った大文字・小文字を保つ。値はHTTP field octetsとして扱う。ASCIIではTAB、SP〜VCHARをそのまま符号化し、obs-textはU+0080〜U+00FFを対応する1バイトに写す（UTF-8へ変換しない）。C0制御文字（TABを除く）とDEL、U+00FFを超える値は拒否する。ヘッダー全体は8KiB以下とする。長さは各ヘッダーの名前と値のバイト数の合計で数える（LPの長さ欄は含めない）。
- 同じ名前のヘッダーが複数あってもよい。名前・値・順序を保って運ぶ。`Set-Cookie`のように結合できないフィールドは別々の行として保持する。
- HTTP field nameの独自allowlist/denylistは設けず、値の意味も検査しない。

### 11.5 受信側の解釈

- 復号した`EtRequest`・`EtResponse`をどう解釈するかは、受け取った実装が決める。URLのスキーム・ホスト・パスによる振り分け、未知のURLへの応答、別のサーバーへの転送、ヘッダーの意味づけ（`location`、`host`、重複したフィールドの扱いなど）は、WAKEの範囲外である。
- サーバーの実装は、復号した要求と、その要求を受理したセッションの認証情報`{userId, sessionId, epoch, credentialId, authTime, requestId}`を受信側に渡す。認証情報はETの中のヘッダーではなく、WAKEのセッションから得たものである（§14.2）。

### 11.6 ETのエラー

ETの形式の違反は、暗号化した`EtResponse`で返す。本文はJSON`{"error": {"code": "…"}}`とする。受信側が返す応答（存在しないURLへの404など）は、受信側が決める。

| status | code | 事象 |
|---|---|---|
| 400 | `invalid_url` / `invalid_header` / `invalid_method` | §11.2〜§11.4の規則違反 |
| 400 | `invalid_request` | `EtRequest`または`EtResponse`の形式不正（LPの不正、ラベルの不一致、ヘッダーの組が奇数、不正なstatus、本文を持てない要求・応答の本文など。§12.4） |
| 413 | `too_large` | サイズ超過 |

### 11.7 独自APIとの共存

- 独自APIは任意のURLで`application/wake`を受け付け、§8.3の手順で復号・暗号化する。
- 独自APIとWAKE-ETは同じセッション鍵を使い、`context`で区別する。
- 参考（ライブラリAPI）: クライアント`wake.fetch(url, init)`、`wake.seal(context, plaintext)`、`wake.open(wire, pending)`。サーバー`wakeOpen(request, {contexts})`、`wakeSeal(reply, responseContext)`。

---

## 12. API一覧とエラー

### 12.1 HTTPエンドポイント

| Method | Path | 形式 | 内容 |
|---|---|---|---|
| POST | `/auth/start` | JSON（平文） | KX開始 |
| POST | `/auth/complete` | JSON（平文） | KX完了 |
| POST | `/wake/up` | `application/wake` | WAKE内部API（Utility Procedure。contextで振り分ける） |
| POST | `/wake/transport` | `application/wake` | WAKE-ET（任意） |

### 12.2 context一覧

| context | 内容 | 平文 |
|---|---|---|
| `wake/session` | セッション情報の取得（疎通確認を兼ねる） | JSON |
| `wake/logout` | ログアウト | JSON |
| `wake/kr/start` / `wake/kr/complete` | WAKE-KR | JSON |
| `wake/ta/list` / `wake/ta/get` / `wake/ta/challenge` / `wake/ta/approve` / `wake/ta/reject` | WAKE-TA | JSON |
| `wake-et` | WAKE-ET | `EtRequest` / `EtResponse` |

`wake/session`の応答:

```json
{
  "sessionId": "<base64url>", "epoch": 1, "authTime": 1791590460000,
  "absoluteExpiresAt": 1792195260000, "hardCapAt": 1794182460000,
  "idleTimeoutSec": 86400, "serverTime": 1791590500000, "rekeyRecommended": false
}
```

### 12.3 外側（平文）のエラー

暗号化された応答を返せない場合、HTTPステータスとJSON`{"wakeError": "<code>"}`を返す。これは認証されていないため、クライアントはヒントとして扱う（偽装されても妨害にとどまる）。

| code | HTTP | 事象 | クライアントの動作 |
|---|---|---|---|
| `bad_request` | 400 | ワイヤ形式・ヘッダーの不正 | 再送しない（実装のバグ） |
| `too_large` | 413 | サイズ超過 | 再送しない |
| `reauth` | 401 | セッション不明・失効・期限切れ、復号失敗、未知の新しい世代 | IndexedDBを読み直し、それでも失敗すれば再ログイン |
| `epoch_retired` | 401 | 古い鍵世代 | 最新世代を読み込み、新しい`requestId`で再送 |
| `rate_limited` | 429 | レート制限 | `Retry-After`に従う |
| `retry` | 503 | 一時的な障害 | 待って再送 |

セッションが存在しない場合と復号に失敗した場合は、区別せず`reauth`とする。

### 12.4 暗号化されたエラー

復号に成功した要求のエラーは、暗号化した応答`{"error": {"code": "<code>"}}`で返す。

| code | 事象 |
|---|---|
| `invalid_request` | 平文の形式不正、必須項目の欠落 |
| `invalid_context` | エンドポイントで受け付けないcontext |
| `stale_request` | `issuedAt`が許容範囲外（応答ヘッダーの`issuedAt`で補正して再送する） |
| `not_found` | 対象が存在しない、またはアクセス権がない |
| `expired` | 交換・承認試行・Operationの期限切れ |
| `already_decided` | Operationの認否が確定済み |
| `webauthn_failed` | WebAuthnまたは鍵確認の検証失敗 |
| `conflict` | KRの競合 |
| `rate_limited` | レート制限 |
| `internal` | サーバー内部エラー |

### 12.5 `/auth/*`のエラー

| code | HTTP | 事象 |
|---|---|---|
| `bad_request` | 400 | 形式不正 |
| `auth_failed` | 401 | 交換の不明・期限切れ、WebAuthnや鍵確認の失敗（原因は区別しない） |
| `rate_limited` | 429 | レート制限 |
| `retry` | 503 | 一時的な障害 |

本文は`{"error": "<code>"}`とする。

---

## 13. パラメーターの既定値

| パラメーター | 既定値 | 備考 |
|---|---|---|
| 交換のTTL | 300秒 | |
| WebAuthnの`timeout` | 270,000ミリ秒 | TTL − 30秒以下 |
| 承認試行のTTL | 300秒 | |
| `issuedAt`の許容幅 `W` | ±300秒 | |
| 旧世代の猶予期間 `G_epoch` | 60秒 | 最大300秒 |
| `authLifetime`（絶対有効期限） | 7日 | KRで延長 |
| `hardCap` | 30日 | 延長不可 |
| `idleTimeoutSec` | 86,400秒 | |
| `last_activity_at`の更新粒度 `G` | `min(idleTimeoutSec/8, 15分)` | |
| 失効反映の上限 `Δ` | 30秒 | |
| `maxOperationLifetime` | 30日 | |
| セッションごとのPENDINGなKR交換 | 3件 | |
| Operationごとの有効な承認試行 | 5件 | |
| 1鍵あたりの暗号化回数 | 2³²回以下（MUST）、目標2²⁴回（SHOULD） | §8.7 |
| `content`の最大長 | 65,536バイト | |
| contextの最大長 | 256バイト | |
| ETの本文の最大長 | 1MiB | 設定可能 |
| ETのmethod・URL・ヘッダー | 32B / 6,144B / 8KiB | |
| `wake/ta/list`の`limit` | 1〜20 | |

---

## 14. セキュリティ上の考慮事項

### 14.1 脅威と対応

| 脅威 | 対応・限界 |
|---|---|
| TLS終端やログでの受動的な観測 | 通信内容はWAKEで暗号化される。暗号文は`W`の間だけ再送できる |
| 能動的なTLS中間者 | 鍵交換は保護されるが、JavaScriptを差し替えられれば破られる |
| ECDH公開鍵のすり替え | WebAuthn署名とサーバー保存値による検証で防ぐ（P1） |
| `sessionId`の漏洩 | 単独では何もできない |
| セッション鍵の漏洩 | 通常APIは悪用され得る。KRとTA承認にはWebAuthnが必要（P4、P5）。期限と失効で被害を限定する |
| 通常APIの暗号文の再送 | WAKEは拒否しない。`issuedAt`で時間を制限し、API実装者が冪等性で対処する |
| WebAuthn署名の別目的への流用 | Challengeは用途ごとに異なる構造で、サーバーが保存値から再計算する。sessionIdとoperationIdに結び付く |
| 他人のOperationの承認 | `approverUserId`とセッションのユーザー、credentialの所有者を照合する |
| 偽造したパスキーの登録 | 信頼関係の変更には既存credentialによる承認が必要（§3.3、実装者の要件） |
| 承認待ち・停止中のcredentialの使用 | すべての儀式で拒否する（§6.5） |
| 承認済みOperationの再利用・流用 | WAKEの範囲外（§14.2） |
| XSS | 防げない（§3.4）。承認専用のoriginで、承認の署名だけは守れる（§6.3） |
| 承認時の表示の偽装 | 正規クライアントの検証と外部ツールでの照合で検出の機会を与える。悪意あるJavaScriptが動いている場合は保証しない |
| DBの漏洩 | 鍵は別の保護境界の鍵で暗号化して保存する |
| DBとKEKの同時漏洩 | 保存中の鍵が漏れる。失効と監査で対処する |
| IVの衝突 | ランダムIVと使用回数の上限（§8.7） |

### 14.2 実装者への注意事項

**承認結果の利用**

- 承認結果を使って処理を実行する前に、自分のDBで`operationId`ごとに「使用済み」の印を原子的に付けること。WAKEは同じ承認結果を何度でも返す。セッション鍵を盗んだ攻撃者は、実行APIを繰り返し呼ぶことができる。
- `operationId`を、別の業務処理の許可として使わないこと。実行する処理の内容は承認済みの`content`から決めるか、保存した要求について`SHA-256(hashInput) = operationId`を検証すること。
- 認否結果は必ずサーバー側でWAKEから取得すること。

**content**

- 外部ツールに入力される前提なので、秘密情報や不要な個人情報を含めないこと。
- 操作の内容を、利用者が判断できる程度に十分に記述すること。

**パスキーの管理**

- §3.3の要件を満たすこと。追加の承認では、新しい端末に表示した指紋（新しいcredentialの公開鍵の SHA-256 の先頭など）を、既存端末の承認画面の`content`と照合させると、登録要求のすり替えを見抜ける（付録B）。
- 登録URLのトークンは、持っていれば誰でも使える秘密である。有効期限と単回使用を設けること。
- 初回登録に4桁のPINを使う場合、総当たりを防ぐため試行回数の上限とトークンの有効期限が必須である。
- credentialを停止・削除したら、`revokeSessionsByCredential`を呼ぶこと。

**XSSと配信コード**

- 同一originで承認する場合、XSSは表示と署名対象をすり替えられる。必要に応じて承認専用のoriginを使うこと。
- CSP、Trusted Types、依存関係の管理などの一般的なXSS対策を行うこと。
- 配信コードの真正性は、公開ソース、再現可能なビルド、配信ファイルのハッシュの公開などで確認できるようにすること。

**通常API**

- リプレイで問題が生じるAPIには、冪等キーなどの対策を実装すること。

**WAKE-ETで運ぶヘッダー**

- ETはHTTPのリクエスト・レスポンスの形式に従って符号化・復号する。内容の意味や用途、信頼性の判断には関与しない。ETの中のヘッダーはクライアントが自由に指定した値であり、リバースプロキシによる上書きや除去を受けない。どのヘッダーを信頼するかは実装者が決める。
- 例えば`x-forwarded-for`、`forwarded`、`x-real-ip`、`host`を接続元やホストの判定に使うと、IP制限やログを偽装され得る。これらは外側のHTTP要求から得ることを勧める。
- 利用者の判定には、`cookie`や`authorization`ではなく§11.5の認証情報を使うことを勧める。
- ETで運ぶURLの解釈もWAKEの範囲外である（§11.5）。

### 14.3 レート制限

次の操作にレート制限を設けなければならない（MUST）。

- `/auth/start`（IP単位、全体）、IP単位のPENDINGな交換の件数
- `/auth/complete`（交換単位、IP単位）
- `wake/kr/start`、`wake/ta/challenge`（セッション単位）
- セッション単位の暗号化通信（§8.7）
- Operationの作成（実装者のAPI）

---

## 15. 実装ノート：Cloudflare Workers / Web Crypto API（参考）

| 要素 | 可否 | 注意点 |
|---|---|---|
| ECDH P-256 | ✓ | `deriveBits(…, 256)`は固定長32バイトを返す |
| 公開鍵のインポート | ✓ | 圧縮点を受け付ける場合があるため、長さと先頭バイトを先に検査する |
| 一時秘密鍵の保存 | ✓ | ECDH秘密鍵は`raw`で書き出せない。`extractable: true`で生成し、`pkcs8`または`jwk`で書き出して暗号化する |
| HKDF、HMAC、AES-256-GCM | ✓ | サーバーは`deriveBits`で生の鍵を得て暗号化保存する。クライアントは`deriveKey`で抽出不可の鍵にする |
| 定数時間比較 | ✓ | `crypto.subtle.verify("HMAC", …)`を使う。Workersには`crypto.subtle.timingSafeEqual`もある（独自拡張。長さが違うと例外） |
| WebAuthnの検証 | ✓ | `@simplewebauthn/server`をバージョンを固定して使う。自前で検証する場合は、DER形式の署名を`r‖s`に変換する |
| D1 | ✓（工夫が必要） | 対話的なトランザクションがない。`batch()`は原子的だが、途中の結果で分岐できない（下記） |
| Durable Objects | ✓ | セッション単位のオブジェクトにすれば、`transactionSync`で状態遷移を素直に書ける。TA+KRの独立判定に向く |
| KV | ✗ | 結果整合性しかないため、失効状態や鍵世代の管理に使わない |
| isolateのメモリ | △ | isolate間で無効化できないため、TTLを`Δ`以下にする |
| `Date.now()` | ✓ | リクエスト内ではI/Oまで進まない。ミリ秒単位の`issuedAt`には十分 |
| KEK | ✓ | Workers Secretsに版番号付きの名前で保存する |

**D1での条件付き確定の例（KX）**: 後に実行する文が、先に実行した文の結果を条件にするように書く。

```sql
-- batch() でまとめて実行する（原子的）
UPDATE wake_exchanges
   SET state = 'COMPLETED', completion_token = ?1, server_private_key = NULL,
       th = ?2, client_finished = ?3, response = ?4, completed_at = ?6
 WHERE exchange_id = ?5 AND state = 'PENDING' AND expires_at > ?6;

INSERT INTO wake_sessions (session_id, user_id, login_credential_id, established_origin, ...)
SELECT session_id, ?7, ?8, ?9, ...
  FROM wake_exchanges
 WHERE exchange_id = ?5 AND completion_token = ?1;
```

1つ目の文の`changes`が0なら、交換状態を読み直して冪等判定を行う。KRでは、交換を更新する文にも「セッションの`current_epoch`が`target_epoch − 1`である」という`EXISTS`条件を付け、交換とセッションの更新が食い違わないようにする。D1の読み取りレプリカを使う場合、失効状態と鍵世代はプライマリから読むか、`Δ`以内の古さを許容することを明示する。

---

## 16. テストベクター

テストベクターは参照実装で生成し、JSONで配布する。バイト列は**16進**で記述する（読みやすさのため）。

```json
{
  "wake": "WAKE/1",
  "suite": "transcript",
  "vectors": [
    {
      "name": "kx-login-basic",
      "input": { "mode": 1, "exchangeId": "…", "sessionId": "…", "epoch": 0, "prevTh": "",
                 "serverNonce": "…", "serverPublicKey": "…", "clientPublicKey": "…" },
      "expected": { "encoded": "…", "th": "…" }
    }
  ]
}
```

異常系は`"expectedError": "<code>"`を持つ。

**JSONでの表し方**

- バイト列は小文字の16進文字列とする。空のバイト列（ε）は空文字列`""`とする。
- テキスト（`content`、`hashInput`、context、パスなど）はJSON文字列とする。
- 整数はJSONの数値とする。

**`expectedError`のコード**

テストベクター用のコードであり、§12の通信上のエラーコードとは別のものである（一部は同じ名前を使う）。実装は内部のエラーをこれらのコードに対応付けて照合する。

| code | 対象 |
|---|---|
| `bad_request` | LPや固定長フィールドの不正、ラベルの不一致、`MsgHeader`の不正、未定義のChallengeの組み合わせ、Transcriptのmodeとepochの不整合。ETの`EtRequest` / `EtResponse`構造不正には使わず、`invalid_request`とする（§11.6） |
| `invalid_request` | ETの`EtRequest` / `EtResponse`構造不正（LP、ラベル、フィールド数/status）。本文を持てない要求・応答の本文（§11.2）を含む（§11.6） |
| `reauth` | AES-GCMの認証失敗（タグやAADの改ざん） |
| `too_large` | 平文の長さの上限超過（§8.7） |
| `invalid_base64url` | 正準形でないBase64url |
| `invalid_utf8` | 不正なUTF-8 |
| `invalid_public_key` | ECDH公開鍵の形式不正、曲線上にない点 |
| `invalid_content` | 文面プロファイル（§10.4）の違反 |
| `invalid_method` / `invalid_url` / `invalid_header` / `invalid_request` | ETの規則違反（§11.6） |

**正常系（必須）**

| suite | 内容 |
|---|---|
| `lp` | 空フィールド、入れ子、整数 |
| `transcript` | login、rekey |
| `challenge` | KX、KR、TA、TA+KR |
| `ecdh` | 共有秘密（**先頭が0x00になる例を含む**） |
| `hkdf` | 4つの鍵 |
| `finished` | clientFinished、serverFinished |
| `msg` | `MsgHeader`の符号化、AES-GCMの暗号化（鍵とIVを固定）、c2sとs2c |
| `ta` | `hashInput`、`operationId`（日本語、絵文字、ZWJ、`\n`の2文字を含む例）、`ta` |
| `et` | `EtRequest`、`EtResponse` |
| `base64url` | 正準形 |

**異常系（必須）**

| suite | 内容 |
|---|---|
| `base64url` | `=`付き、末尾ビットが0でない、文字集合外 |
| `ecdh` | 圧縮点、ハイブリッド形式、曲線上にない点、長さ不正 |
| `utf8` | 不正なバイト列、サロゲートの符号化 |
| `ta-profile` | NFCでない、LF、CR、タブ、DEL、C1制御文字、先頭・末尾の空白、空文字列 |
| `msg` | 余分なバイト、固定長の不一致、ラベル不一致、`dir`の逆転、タグの改ざん、AADの1バイト改ざん、context外の文字 |
| `challenge` | 未定義の組み合わせ |
| `et` | 不正なURL（フラグメント、URIに使えない文字、長さ超過）、禁止されたmethod、本文を持てない要求・応答の本文、CRLFを含む値 |

---

## 17. 今後の検討事項

- ストリーミング、WebSocket、サーバープッシュ（メッセージ種別の追加）
- 共有ストアによる厳密なリプレイ拒否（拡張モジュール）
- KXとTAを1回のWebAuthnで行う組み合わせ（承認専用originでのログインと承認）
- 複数人承認の標準化
- X25519などのアルゴリズムの追加、メッセージごとの鍵導出
- DBSCなど、ブラウザ内蔵の鍵との統合
- 配信コードの真正性を検証する独立ツール（Client Integrity）

---

## 付録A. サーバーDBの論理モデル（参考）

### `wake_exchanges`

| カラム | 内容 |
|---|---|
| `exchange_id` (PK) | 16B |
| `kind` | `login` / `rekey` |
| `session_id` | loginでは予約ID、rekeyでは対象セッション |
| `target_epoch` | loginは0、rekeyは作成時の`current_epoch + 1` |
| `prev_th` | rekeyのみ |
| `server_nonce`, `server_public_key` | |
| `server_private_key` | 暗号化して保存。終了状態でNULL |
| `requested_user_id` | username方式のみ |
| `bound_approval_id` | TA+KR用の場合のみ |
| `state` | `PENDING` / `COMPLETED` / `EXPIRED` / `SUPERSEDED` |
| `th`, `client_finished`, `response`, `completion_token` | 確定時に保存（冪等応答用） |
| `created_at`, `expires_at`, `completed_at` | |

### `wake_sessions`

| カラム | 内容 |
|---|---|
| `session_id` (PK) | 32B |
| `user_id` | |
| `login_credential_id`, `last_auth_credential_id` | 失効機能で使う |
| `established_origin` | ログイン時のorigin |
| `status` | `ACTIVE` / `REVOKED` / `EXPIRED` |
| `current_epoch`, `cur_keys`（暗号化）, `cur_th` | |
| `prev_keys`（暗号化）, `prev_valid_until` | 旧世代 |
| `created_at`, `auth_time`, `absolute_expires_at`, `hard_cap_at`, `idle_timeout_sec`, `last_activity_at` | |

### `wake_operations`

| カラム | 内容 |
|---|---|
| `operation_id` (PK) | 32B |
| `content`, `nonce` | 不変 |
| `approver_user_id` | 不変 |
| `status` | `PENDING` / `APPROVED` / `REJECTED` / `CANCELLED` / `EXPIRED` |
| `created_at`, `expires_at`, `decided_at` | |
| `decided_by_user_id`, `decided_by_credential_id` | |
| `decision_record` | §10.10 |

### `wake_approval_attempts`

| カラム | 内容 |
|---|---|
| `approval_id` (PK) | 16B |
| `operation_id`, `session_id`, `approval_nonce` | |
| `kr_exchange_id` | TA+KRの場合のみ |
| `state` | `PENDING` / `CONSUMED` / `EXPIRED` |
| `result` | 冪等応答用 |
| `created_at`, `expires_at` | |

---

## 付録B. TAを用いたパスキー追加フローの例（参考）

既存のパスキーを使える端末Aから、新しい端末Bにパスキーを追加する例。具体的な手順は実装者が設計する。

```text
【端末A（ログイン済み）】 パスキー追加を要求 → 登録用URLを発行 → 端末Bへ渡す
【端末B】               登録URLにアクセス → デバイス名を入力 → navigator.credentials.create()
                        → 新しいcredentialを pending で保存 → 指紋を表示（例: 公開鍵SHA-256の先頭8バイト）
【サーバー】             新しいcredentialのIDと公開鍵ハッシュを含む content で Operation を作成
                        （approverUserId = 対象ユーザー）
【端末A】               承認画面で content と端末Bの指紋を照合 → 既存パスキーでWebAuthn承認
【サーバー】             APPROVED を確認 → 承認された content と保存中の credential が一致することを照合
                        → credential を active にする（使用済みの印を付ける）
```

`content`の例:

```text
パスキーの追加\nデバイス名: Pixel 9\nCredential ID: 8m3Qp…（Base64url）\n公開鍵SHA-256: 7c2e91d0a4b85f13…
```

承認待ちのcredentialは、承認が確定するまでどの儀式でも受理されない（§6.5）。そのため、承認待ちのcredentialが自分自身の追加を承認することはできない。

---

## 付録C. 認否記録の検証用データ形式（参考）

```json
{
  "format": "WAKE/1 ta-bundle",
  "rpId": "example.com",
  "operationId": "1140095b9147435cc75d76b00be2938ebd69885f938afdcc02337c925cedfd74",
  "content": "送金要求\\n送金先: 山田太郎\\n金額: 10000 JPY",
  "nonce": "3f9a1c7e5b2d4f6081a3c5e7092b4d6f",
  "approval": {
    "approvalId": "<base64url 16B>",
    "approvalNonce": "<base64url 32B>",
    "sessionId": "<base64url 32B>",
    "th": null,
    "credentialPublicKey": "<base64url COSE_Key>",
    "authenticatorData": "<base64url>",
    "clientDataJSON": "<base64url>",
    "signature": "<base64url>"
  }
}
```

検証手順:

1. `content`を文面プロファイルで検査する。
2. `hashInput`を組み立て、`operationId`を再計算して比較する。
3. `ta`とChallengeを再計算する（TA+KRの場合は`th`を使う）。
4. `clientDataJSON`の`type`・`challenge`・`origin`、`authenticatorData`の`rpIdHash`とUVフラグを確認する。
5. 署名を`credentialPublicKey`で検証する。

`credentialPublicKey`がそのユーザーのものであることは、この形式だけでは証明できない。登録済みcredentialの一覧など、別の信頼できる経路で確認する必要がある。

---

## 参考文献

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 2119 / RFC 8174 — 要求レベルを示すキーワード](https://www.rfc-editor.org/rfc/rfc8174)
- [RFC 4648 — Base16, Base32, Base64](https://www.rfc-editor.org/rfc/rfc4648)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 7493 — I-JSON](https://www.rfc-editor.org/rfc/rfc7493)
- [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
- [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [MDN Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Cloudflare D1](https://developers.cloudflare.com/d1/)
- [SimpleWebAuthn](https://simplewebauthn.dev/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

**要約:** WAKE/1は、WebAuthnがユーザーと鍵交換内容を認証し、一時ECDHとHKDFがログインごとのセッション鍵を導出する。以後はランダムIVのAES-256-GCMで、要求と応答を対応付けた暗号化通信を行う。WAKE-KRはWebAuthnと新しいECDHで鍵世代を更新し、WAKE-TAは不変の文字列から外部ツールで再現できる`operationId`を生成して、指定された認否者によるWebAuthnでの認否を一度だけ確定する。WAKE-ETは、アプリケーションがすぐ利用できる標準の暗号化トランスポートを提供する。
