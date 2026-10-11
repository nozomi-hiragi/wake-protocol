# 仮実装の設計方針

`impl/ts` のコードをどう分け、どう書くかの方針です。パッケージ分割のリファクタ（2026-10）で決めたことと、その理由を残しています。新しいコードの置き場所や名前に迷ったら、ここに戻ってください。

## 1. 構成

```text
@wake-protocol/bytes    依存なし       Bytes、Byte / Byte2 / Byte4 / Byte8、Brand、number ↔ bigint
@wake-protocol/codec    依存なし       長さ付き符号化（LP）、ASCII / Latin-1 / UTF-8
@wake-protocol/crypto   @scure/base    Web Crypto のラッパー（SHA-256、HMAC、HKDF、AES-256-GCM、P-256）
          ↑
@wake-protocol/core     bytes、codec、crypto、@scure/base    WAKE プロトコル
          ↑
@wake-protocol/vectors  core、bytes、codec、@scure/base      §16 テストベクターの生成と照合（開発用）
@wake-protocol/server   core、bytes、codec、crypto、@scure/base   KX と SM のサーバー（フレームワーク非依存）
@wake-protocol/client   core、bytes、codec、crypto、@scure/base   KX と SM のクライアント（ブラウザと Node）
          ↑
@wake-protocol/demo     server、client、汎用パッケージ、hono、@hono/node-server   デモアプリ、結合テスト、e2e（開発用）
```

- **汎用パッケージ**（bytes / codec / crypto）は WAKE を知りません。
- **core** は汎用パッケージを組み合わせて WAKE を実装します。中は `spec/`（ラベル・ブランド型・エラーなど仕様全体の定義）、`keys/`、`kx/`、`msg/`、`ta/`、`et/` に分けています。
- **vectors** は開発用の道具です。製品のコードから vectors に依存してはいけません。
- **server** と **client** は互いに依存しません。両者は §7・§8・§12 のワイヤ形式（JSON と `Wire`）だけでつながります。client と server を組み合わせるテストは、両方に依存できる demo に置きます。
- server は `Request` を受け取り `Response` を返す関数（`handle`）だけを持ち、Web フレームワークに依存しません。WebAuthn の検証（§6.2）は server の `webauthn/` に自前で書いています（理由は §5）。
- **demo** は開発用です。WAKE の範囲外のパスキー登録と、ブラウザで動かす画面を持ちます。製品のコードから demo に依存してはいけません。

## 2. 原則

### 2.1 汎用と WAKE 固有を分ける
汎用パッケージには、WAKE の用語、仕様の § 番号、`WakeError` とエラーコードを持ち込みません。判断の基準は「WAKE の仕様書を読まなくても意味が分かるか」です。

- 「u32 の長さ ‖ 中身」を並べる LP の符号化は、SSH の `string` 型と同じ汎用の形なので codec に置きます。先頭のフィールドをラベルにする決まりと、構造ごとのフィールド定義は WAKE 固有なので、core（`spec/domain.ts`、各モジュール）に置きます。
- `Brand` と長さを検査する `fixedLength` は汎用なので bytes に置きます。`SessionId` などのブランド型の一覧と `as*` 関数は、core の `spec/types.ts` に置きます。

### 2.2 依存は一方向にし、汎用パッケージどうしは依存しない
- パッケージ間の依存と外部の実行時依存は、`scripts/check-deps.ts` の `allowedEdges` に明示しています。`npm test` は、`package.json` の宣言と import の両方をこの表と照合します。表の外で許可するのは Node の組み込みモジュールだけです。ルートの開発用依存（`typescript`、`@types/node`）は、各パッケージの `test/` と `scripts/` からだけ import できます。`src/` からは import できず、`src/` の import は `allowedEdges` に加えてパッケージ自身の `dependencies` / `peerDependencies` / `optionalDependencies` に宣言されている必要があります。ルートの開発用依存は、パッケージ自身の `devDependencies` にだけ宣言できます。依存を足すには表を変える必要があるので、PR で理由を説明してください。
- パッケージの中でも、下の層は上の層を知りません。たとえば `msg/`（暗号化メッセージ）は、その上で運ぶ `et/` に依存しません。`DEFAULT_MAX_PLAINTEXT` は数値の定数にして、ET の最大長を覆っていることはテストで確かめています。

### 2.3 標準の型で書けるものは標準の型で書く
- codec と crypto は `Uint8Array` を受け取り、返します。`Bytes` に揃えること自体は目的にしません。依存しないで済むなら、そのほうがよいからです。
- `Bytes` との変換は、core の薄いアダプター（`spec/crypto.ts`、`spec/domain.ts`）に集めます。
- `Bytes` とブランド型は、WAKE の値のように、不変であることや型の区別が必要な場所で使います。

### 2.4 名前は、やっていることで付ける
特定の使い道に縛られない関数は、やっていることで名前を付けます（`numberToBigInt`。旧名は `timeToU64`）。使い道と強く結び付いて、そこでしか使わないものは、使い道の名前でかまいません（`encodeHeader`）。ファイル名も中身で付けます（`time.ts` → `bigint.ts`）。

| 種類 | 規則 | 例 |
|---|---|---|
| 変換 | `XToY`（noble / scure の流儀）。向きが名前から読める | `asciiToBytes` / `bytesToAscii`、`latin1ToBytes` / `bytesToLatin1` |
| 長さ付き符号化 | 長さの幅を名前に入れる（Go の cryptobyte、BoringSSL の流儀）。ストリームの区切りに読まれやすい「delimited」は使わない | `encodeU32LengthPrefixed` / `decodeU32LengthPrefixed` / `checkFieldLengths` |
| 固定幅の整数 | 幅をバイト数で表し、値は `.number` で読む（`Byte8` は `bigint`） | `Byte`、`Byte2`、`Byte4`、`Byte8` |
| core の接頭辞 | `as*` 外から来たバイト列を検査してブランドを付ける。`new*` 乱数で作る。`check*` 検査して違反なら投げる。`parse*` 受け取ったデータを検査して型の付いた値にする。`encode*` / `decode*` ワイヤ形式との変換 | `asSessionId`、`newIv`、`checkContext`、`parseWire`、`encodeEtRequest` |

### 2.5 1つの関数には1つの仕事をさせる
- `decodeU32LengthPrefixed` はバイト列をフィールドに分けるだけ、`checkFieldLengths` はフィールド数と固定長を検査するだけです。core の `decodeFields` がこの2つを組み合わせて、§4.2 の厳密な復号（フィールド数の固定、固定長の検査、余分なバイトの拒否）にしています。
- 逆に、呼び出し元が1つしかなく、分けても読みやすくならない補助関数は作りません。

### 2.6 仕様の構成要素は1か所に置く
- ラベルは `spec/labels.ts` の `LABELS` にだけ書きます。
- ラベル付きの LP は `labeled`、ラベルの照合は `expectLabel`、上限オプションの検査は `checkMaxLength` で、それぞれ1か所にまとめています。
- `seal` と testing の `sealWithIv` は、処理の本体（`sealWithHeaderAnyKey`）を共有します。公開の `seal` / `sealWithHeader` は鍵の役割と `dir` の組み合わせを型で確かめ、本体に渡します。

### 2.7 公開する範囲は狭くする
- core の `index.ts` が公開するのは、WAKE の API、ブランド型、`LABELS`、`WakeError`、`Bytes`、鍵のインポート（`aesKey` / `hmacKey`）とその鍵型だけです。汎用の関数は再エクスポートしません。使う側が各パッケージから直接 import します。
- 乱数を固定するものや、制約のない符号化（`sealWithIv`、`importEcdhPrivateKey`、`encodeChallengeInput`）は、`@wake-protocol/core/testing` にだけ置きます。

### 2.8 取り違えを型で防ぐ
WAKE には32バイトの値がたくさんあり、引数を取り違えてもテストをすり抜けがちです。型で防げるものは型で防ぎます。

- 固定長の値はブランド型にします。外から来たバイト列は、対応する検査関数（`as*` や、曲線上の点かまで確かめる `parseEcPublicKey`）を通らないとブランド型になりません（parse, don't validate）。
- 儀式ごとに関数を分けます（`kxChallenge` / `krChallenge` / `taChallenge` / `taKrChallenge`）。ログイン用と鍵更新用の `th` を取り違えると、コンパイルエラーになります（§5.5）。
- 鍵は役割ごとの型にします。`aesKey` は `C2sKey` / `S2cKey` だけを受け取り、`C2sCryptoKey` / `S2cCryptoKey` を返します。Finished 鍵をメッセージの暗号化に使うこと（§5.6 で禁止）は、型の段階で防げます。
- ブランドは実行時には消えます。実行時にも守る必要がある条件（AES-256 の鍵長、IV の長さ）は、汎用の crypto で検査します。
- `fixedLength<B extends string>(name, len)` はブランドの識別子を型引数に取り、`Brand<B>` を返す検査関数を作ります。`Byte4` のようなクラス型を型引数で偽れないようにするためです。
- 「通ってはいけない呼び出し」は、テストに `// @ts-expect-error` で書きます（`packages/core/test/key-roles.test.ts`）。`npm run typecheck` はテストも対象です。

### 2.9 受け取ったバイト列は厳密に分解する
WAKE の構造は LP（u32 の長さ ‖ 中身の繰り返し）で組み立てます。区切り文字を使わないので、どんなバイト列を並べても分け方が1通りに決まり、組み立て方も1通りしかありません。そのため、クライアントとサーバーが別々に組み立てた Transcript や Finished の入力が一致し、ET はエスケープなしで任意のバイトを運べます。

この性質を保つため、受け取ったデータは §4.2 のとおり厳密に分解します。

- 構造の決まったデータは、必ず `decodeFields(bytes, lengths)` に長さの配列を渡し、フィールド数・固定長・余分なバイトを検査します。1つのバイト列に複数の解釈があると、たとえば AAD として認証されたヘッダーと、解析した結果が食い違います。
- フィールド数を固定しないのは、ET の `headers` だけです。`lengths` を渡し忘れても型エラーにはならないので、レビューで確かめます。

## 3. エラーの扱い

| 状況 | 投げるもの | 例 |
|---|---|---|
| 汎用パッケージの検査に引っかかった | 標準の例外（`RangeError` / `TypeError` / `SyntaxError`）。`fail` は使わず、そのまま `throw` する | 非 ASCII のバイト → `RangeError` |
| 呼び出し側が固定幅の整数フィールドに範囲外の数値を渡した | `RangeError`（プログラムのバグとして扱う） | `epoch` に 2^32、`issuedAt` に −1、`idleTimeoutSec` に 2^32 |
| メッセージの暗号化・復号に合わない鍵を渡した | `TypeError`（AES-GCM のラッパーが事前に検査する） | `seal` に AES-128 の鍵や HMAC の鍵を渡す |
| Web Crypto 自身の失敗 | Web Crypto の `DOMException` がそのまま伝わる | Finished の関数に AES の鍵を渡す → `InvalidAccessError` |
| 受け取ったデータの形式不正 | `WakeError`（§12 のコード） | `parseWire` → `bad_request`、ET のデコード → `invalid_request` |
| 意味の検査 | `WakeError`（エンコード時も） | `checkContext` → `bad_request`、`checkContent` → `invalid_content`、ET → `invalid_method` / `invalid_path` / `invalid_header`、ET の status が範囲外 → `invalid_request` |
| 上限の設定・超過 | `WakeError` | 設定値の不正 → `invalid_option`、超過 → `too_large` |
| 認証の失敗 | `WakeError("reauth")` | `open` で復号に失敗した |

ET の status は数値ですが、§11 の意味の検査として扱うので、エンコード時も `WakeError` です。`RangeError` にするのは、u32 や u64 の幅に収まるかだけが問題になる整数フィールドです。

- 標準の例外から `WakeError` への変換は、core の境界で `remap(code, fn)`（非同期なら `remapAsync`）を使って行います。変換するのは `RangeError` / `TypeError` / `SyntaxError` の3種類だけで、`DOMException` などはそのまま伝わります。包むのは、外から来た値で失敗しうる汎用の呼び出しだけで、1つずつ包みます。たとえば、受け取ったバイト列を分ける `decodeFields` / `decodeU32LengthPrefixed` や `bytesToAscii`、ブランドを付ける `fixedLength`、受け取った公開鍵を検査する `checkP256PublicKey` です。関数全体を包むと、内部のバグで出た `TypeError` まで、受け取ったデータのエラーに見えてしまいます。
- 例外は握りつぶしません。`aesGcmDecrypt` が `null` を返すのは認証の失敗だけで、それ以外の例外は投げます。以前はどんな例外も `null` にしていたため、鍵の設定ミスが `reauth`（再ログインの要求）に化けていました。
- 範囲外の数値を `WakeError` にしないのは、それが通信で受け取った値ではなく、呼び出し側のバグだからです。以前あった `invalid_integer` も §12 にないローカルのコードだったので、`u32Field` ごと削除しました。
- テストベクターで、照合用のコード（`invalid_base64url` など）や数値の失敗のコードが必要な場合は、vectors の側で付け替えます。

## 4. `Bytes`
- 所有することで不変を保ちます。コンストラクタも `toUint8Array()` もコピーするので、外から中身を書き換えられません。
- コピーするので、秘密の値が複数の場所に残りえます。`Bytes` は秘密データの消去を保証する仕組みではありません。
- コンストラクタは受け取ったバイト列をコピーするだけです。整数の符号化と長さの検査は、各 `Byte*` クラスの中（`static #encode`）で行います。
- 比較は `.equals()`、連結は `Bytes.concat()` を使います。
- **テストで `Bytes` を `assert.deepEqual` で比べてはいけません。** 中身はプライベートフィールド（`#data`）にあり、`deepEqual` はそれを比較しないので、中身が違っても通ってしまいます。`.equals()` を使うか、`hex.encode(x.toUint8Array())` で文字列にして比べます。

## 5. 外部ライブラリ
信頼できて置き換えられるライブラリは採用して、自前のコードを減らします。自前で持つのは、条件に合うものがないときだけです。

採用の条件:
- ライセンスが寛容であること（MIT、Apache-2.0、BSD、ISC、CC0 など）。GPL などのコピーレフト、独自ライセンス、ライセンスの表記がないものは採用しません。判断に迷うものは相談します。
- 依存がない（または非常に少ない）こと
- 第三者の監査を受けている、または広く使われていること
- 仕様と厳密に一致すること。寛容に受け付けるライブラリは、仕様違反の原因になります
- ブラウザと Node の両方で動くこと
- 実行時の依存（各パッケージの `dependencies`）は、バージョンを完全に固定し（`^` を付けない）、lockfile の integrity で検証すること。更新するときは差分を確認します。開発用のツール（ルートの `devDependencies` の `typescript`、`@types/node`）は範囲指定のままにし、lockfile で固定します

名前を付け替えるだけのラッパーは作らず、使う側が直接 import します（codec にあった hex / base64url のラッパーは削除しました）。

| 対象 | 判断 |
|---|---|
| hex、base64url | `@scure/base` 2.4.0（MIT）を採用。依存がなく、cure53 の監査（2022年）と v2.2.0 の自己監査を受けている。`base64urlnopad` は正規形でない入力を拒否する |
| LP | 自前。`it-length-prefixed` などはストリーム向けで、長さの形式も既定は varint（u32 に差し替えはできる）。フィールド数や固定長を検査する厳密な復号の機能はなく、依存も増える。自前なら30行ほどで済む |
| ASCII、UTF-8、Latin-1 | 自前で `codec/text.ts` にまとめる。`@scure/base` にも ascii / utf8 はあるが、`decode` が「文字列 → バイト列」と向きが逆で紛らわしく、減る行数も少ない。Latin-1 はない |
| 暗号 | 標準の Web Crypto API を使う |
| WebAuthn の検証 | 自前（server の `webauthn/`）。`@simplewebauthn/server` は依存が多く、§6.4 の署名カウンターの規則（BE が1なら値が戻っても受理する）とも合わない。必要なのは ES256 の assertion の検証だけで、CBOR の解析も要らない（公開鍵は SPKI で保存する。SPEC-NOTES.md） |
| ECDSA の DER 署名 | 自前（crypto の `ecdsaDerToRaw` / `ecdsaRawToDer`）。Web Crypto は `r‖s` 形式しか受け付けない。厳密な DER の解析は50行ほどで、非最小の整数・余分なバイト・長形式の長さを拒否することをテストで確かめている |
| 厳密な JSON（I-JSON） | 自前（codec の `parseIJson`）。`JSON.parse` は重複したキーや孤立サロゲートを受け付けてしまう。§4.8 はこれらの拒否を求める |
| HTTP サーバー（demo のみ） | `hono` 4.13.13（MIT）と `@hono/node-server` 2.1.3（MIT）。どちらも実行時の依存がない。server 本体は `Request` / `Response` だけを使うので、フレームワークは差し替えられる |
| ブラウザ用のバンドル（demo の開発用） | `esbuild` 0.28.2（MIT）。実行時の依存はなく、プラットフォームごとのバイナリだけを持つ |
| e2e（demo の開発用） | `@playwright/test` 1.63.0（Apache-2.0）。依存は `playwright` だけ。Chromium の仮想認証器（CDP の `WebAuthn` ドメイン）で、ブラウザのパスキーを使ったログインを確かめる |

`TextDecoder("latin1")` は使いません。実際には Windows-1252 として扱われ、`0x80` が U+20AC（€）になるので、ET の obs-text が壊れます。

## 6. テスト
- テストは、対象のコードと同じパッケージに置きます。複数のパッケージを組み合わせるテストは、その両方に依存してよい場所（core、vectors、demo）に置きます。汎用パッケージどうしにテストのためだけの依存を作らないためです。
- 実装から独立した方法でも照合します。`node:crypto` で計算し直したり（`crosscheck.test.ts`）、テストの中で独自に書いたデコーダーを使ったりします（`v05-rules.test.ts`）。これらを実装の関数で置き換えないでください。
- 受け取る側の検査は、壊れたバイト列をデコーダーに直接渡して確かめます（`et-decode.test.ts`）。エンコーダーを通すテストだけでは、受け取る側の検査を消しても気づけません。
- 境界値は両側を確かめます。たとえば、`issuedAt` が 2^53−1 なら通り、2^53 なら拒否されることの両方です。片側だけだと、拒否された原因が検査なのか、データの壊れなのかが分かりません。
- 仕様のテストベクター（`spec/test-vectors/`）は `npm run vectors` で生成します。どの変更のあとでも、再生成して差分が出ないことを確認します。

## 7. TypeScript の書き方
- Node 22.18 以降が、TypeScript を変換せずに型を取り除いて実行します。そのため `erasableSyntaxOnly` を有効にしていて、`enum`、`namespace`、コンストラクタ引数のプロパティ宣言など、実行時のコードを生む構文は使えません。
- import には `.ts` の拡張子を付けます。型だけの import には `type` を付けます（`verbatimModuleSyntax`）。
- `noUncheckedIndexedAccess` を有効にしているので、配列の要素は `undefined` になりうる型になります。長さを検査済みの場所では `!` を使います。
- 各パッケージの `tsconfig.json` は、`tsconfig.base.json` を `extends` します。
- コメントは英語で短く書きます。core のファイルは、先頭のコメントに対応する仕様の § を書きます。汎用パッケージには § を書きません。
- 整形ツールは入れていません。import の重複や並び、インデントは、周りのコードに合わせて手で揃えます。

## 8. 新しいコードの置き場所
1. WAKE の仕様を知らなくても意味が通るか？
   - **はい** → 汎用パッケージに置く。バイト値・整数・型は bytes、符号化と文字列は codec、Web Crypto は crypto。どれにも収まらず、ほかの汎用パッケージに依存したくなったら、新しいパッケージにするか core に置くかを検討する（汎用パッケージどうしの依存は作らない）。
   - **いいえ** → core に置く。仕様全体で使う定義は `spec/`、それ以外は対応するモジュール（`keys/`、`kx/`、`msg/`、`ta/`、`et/`）。
   - WAKE のサーバー・クライアントとしての処理（HTTP の受け答え、状態の保存、WebAuthn の検証、再送）→ server または client。どちらにも必要な WAKE の定義は core に置く。
2. 乱数を固定するものや、制約のない符号化など、テストでしか使わないもの → `core/src/testing.ts`。サーバー側のテスト用の道具（`SoftAuthenticator`）→ `server/src/testing.ts`
3. テストベクターの生成と実行 → `vectors/src/`。コマンドラインの入口は `vectors/scripts/` に薄く置く。
4. client と server を組み合わせるテスト、デモ画面、e2e → demo
