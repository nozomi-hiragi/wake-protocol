# WAKE 仮実装（TypeScript）

[WAKE Protocol 仕様書](../../spec/wake-protocol.md) が実際に動くか、曖昧な所がないかを確かめるための仮実装です。**本番では使わないでください。**

コードの分け方・名前・エラーの扱いなどの方針は [DESIGN.md](DESIGN.md)、実装で見つかった仕様の曖昧点は [SPEC-NOTES.md](SPEC-NOTES.md) にまとめています。

## 構成

| パッケージ | 内容 |
|---|---|
| `core/bytes`（`@wake-protocol/bytes`） | 不変のバイト値、固定幅整数、ブランド型。依存なし |
| `core/codec`（`@wake-protocol/codec`） | `Uint8Array` 用の LP、文字列。依存なし |
| `core/crypto`（`@wake-protocol/crypto`） | `Uint8Array` 用の Web Crypto API ヘルパー。`@scure/base` 2.4.0 に依存 |
| `core/protocol`（`@wake-protocol/core`） | WAKE プロトコル。bytes / codec / crypto、`@scure/base` 2.4.0、`@nozomi-hiragi/i-json` 0.1.2 に依存 |
| `core/vectors`（`@wake-protocol/vectors`） | §16 テストベクターの生成と照合。core / bytes / codec と `@scure/base` 2.4.0 に依存 |
| `server`（`@wake-protocol/server`） | KX、SM、KR、TA、ET のサーバー。フレームワークに依存せず、`Request` を受け取り `Response` を返す。core / bytes / codec / crypto と `@scure/base` 2.4.0 に依存 |
| `client`（`@wake-protocol/client`） | KX、SM、KR、TA、ET のクライアント。ブラウザと Node で動く。core / bytes / codec と `@scure/base` 2.4.0 に依存 |
| `demo`（`@wake-protocol/demo`） | デモアプリ、client と server の結合テスト、Playwright の e2e（開発用）。server / client / codec / crypto、`@scure/base` 2.4.0、`@nozomi-hiragi/i-json` 0.1.2、`hono` 4.13.13、`@hono/node-server` 2.1.3 に依存 |

主なファイル（パスは `impl/ts/` からの相対。各パッケージの `index.ts` が入口）:

| ファイル | 仕様 |
|---|---|
| `core/bytes/src/bytes.ts` | §4.1 不変所有の `Bytes` と、`.number` を持つ固定幅 `Byte` / `Byte2` / `Byte4` / `Byte8` |
| `core/codec/src/length-prefixed.ts` | §4.2 LP とフィールド長の検査 |
| `core/codec/src/text.ts` | §4 ASCII、Latin-1、UTF-8 の変換 |
| `core/bytes/src/bigint.ts` | 整数の `number` / `bigint` 変換 |
| `core/bytes/src/brand.ts` | ブランド型の共通定義 |
| `core/crypto/src/hash.ts` | §5.1 SHA-256、HKDF、HMAC、乱数 |
| `core/crypto/src/aes.ts` | §8.3 AES-256-GCM |
| `core/crypto/src/p256.ts` | §5.2 汎用 ECDH P-256 |
| `core/crypto/src/ecdsa.ts` | §6.2 ECDSA の DER と `r‖s` の変換、P-256 の署名検証 |
| `core/crypto/src/index.ts` | 汎用暗号ヘルパーのエクスポート |
| `core/bytes/src/index.ts` | バイト値・整数・ブランド型のエクスポート |
| `core/codec/src/index.ts` | 汎用コーデックのエクスポート |
| `core/protocol/src/spec/crypto.ts` | §5.1、§8.3 鍵インポートと内部 AEAD 用の `Bytes` アダプター |
| `core/protocol/src/spec/domain.ts` | §4.2、§5 ドメイン分離付き LP とラベルの検査 |
| `core/protocol/src/spec/errors.ts` | §12 エラーコードと変換 |
| `core/protocol/src/spec/labels.ts` | §4.7、§5.3–5.7、§8.2、§11.2 ドメイン分離ラベル |
| `core/protocol/src/spec/limits.ts` | §12.3 長さ上限の検査 |
| `core/protocol/src/spec/types.ts` | §4 固定長の WAKE ブランド型と検査 |
| `core/protocol/src/keys/ids.ts` | §4.6、§5.3–5.4、§8.3、§10.3 固定長の識別子・Nonce・IV の生成 |
| `core/protocol/src/keys/ecdh.ts` | §5.2 一時鍵の生成、公開鍵の検査、共有秘密 |
| `core/protocol/src/kx/transcript.ts` | §5.3 ログイン・鍵更新の Transcript |
| `core/protocol/src/kx/binding.ts` | §5.4 TA承認の結び付け |
| `core/protocol/src/kx/challenge.ts` | §5.5 WebAuthn Challenge |
| `core/protocol/src/kx/schedule.ts` | §5.6 鍵導出 |
| `core/protocol/src/kx/finished.ts` | §5.7 Client / Server Finished と検証 |
| `core/protocol/src/msg/header.ts` | §8.2、§8.7 メッセージヘッダー、Wire の解析、平文長の検査 |
| `core/protocol/src/msg/aead.ts` | §8.3 暗号化メッセージの Seal / Open |
| `core/protocol/src/ta/content.ts` | §10.4 文面プロファイルの検査 |
| `core/protocol/src/ta/operation.ts` | §10.3 `hashInput`、`operationId`、操作識別子の生成 |
| `core/protocol/src/ta/bundle.ts` | 付録C 認否記録の検証（`verifyApprovalBundle`） |
| `core/protocol/src/et/types.ts` | §11.2 `EtRequest` / `EtResponse` の型、ラベル、上限 |
| `core/protocol/src/et/validate.ts` | §11.2–11.4 メソッド、パス、クエリー、ヘッダー、ステータスの検査 |
| `core/protocol/src/et/codec.ts` | §11.2 リクエスト・レスポンスのエンコード / デコード |
| `core/protocol/src/index.ts` | §4–§11 公開 API |
| `core/protocol/src/testing.ts` | §16 テスト専用ヘルパー |
| `core/vectors/src/index.ts` | §16 ベクター生成・実行ヘルパーのエクスポート |
| `core/vectors/src/generate-vectors.ts` | §16 固定入力から JSON ベクターを生成 |
| `core/vectors/src/vector-ops.ts` | §16 ベクター入力を公開 API で実行 |
| `core/vectors/scripts/generate-vectors.ts` | `src` の生成処理を呼ぶ CLI の入口 |
| `core/vectors/test/vectors.test.ts` | §16 保存済みベクターと実装の照合 |
| `core/vectors/test/generate.test.ts` | §16 生成結果の安定性の検査 |
| `server/src/server.ts` | §7、§8、§12 `createWakeServer`（`handle` と失効 API） |
| `server/src/options.ts` | §13 設定の既定値と検査 |
| `server/src/http.ts` | §4.4、§4.8、§12 本文の読み取りと上限、JSON、エラー応答 |
| `server/src/kx/start.ts` | §6.6、§7.2 `POST /auth/start` |
| `server/src/kx/complete.ts` | §7.5、§7.6 `POST /auth/complete` |
| `server/src/webauthn/verify.ts` | §6.2–§6.4 assertion の検証（KX・KR・TA の儀式ごとの origin とユーザーの照合） |
| `server/src/webauthn/counter.ts` | §6.4 署名カウンターの条件付き更新と、確定後の更新 |
| `server/src/webauthn/finalize.ts` | §6.5 確定後のセッションと credential の再確認 |
| `server/src/webauthn/options.ts` | §6.1 WebAuthn のオプション |
| `server/src/kr/start.ts` | §9.2 `wake/kr/start` |
| `server/src/kr/complete.ts` | §9.3、§9.4 `wake/kr/complete` |
| `server/src/kr/finish.ts` | §9.4 KR と TA+KR に共通の鍵導出と `clientFinished` の検証 |
| `server/src/ta/operations.ts` | §10.2、§10.9、§10.10 `createOperation` / `cancelOperation` / `getOperation` / `exportApprovalBundle` |
| `server/src/ta/list.ts` | §10.6 `wake/ta/list`、`wake/ta/get` |
| `server/src/ta/challenge.ts` | §10.6 `wake/ta/challenge`（承認試行と、TA+KR の KR 交換） |
| `server/src/ta/approve.ts` | §10.7、§10.8 `wake/ta/approve` |
| `server/src/ta/reject.ts` | §10.9 `wake/ta/reject` |
| `server/src/et/transport.ts` | §11 `POST /wake/transport` のルーティング |
| `server/src/sm/up.ts` | §8.3–§8.7、§12.3、§12.4 `POST /wake/up` と `POST /wake/transport` に共通の処理 |
| `server/src/sm/session.ts` | §12.2 `wake/session` の応答 |
| `server/src/sm/lifetime.ts` | §8.1 セッションの期限 |
| `server/src/store/types.ts` | §6.5、§7.4、§8.1 ストアのインターフェース |
| `server/src/store/memory.ts` | §7.4–§7.6、§8.9 メモリのストア |
| `server/src/testing.ts` | §6 テスト用のソフトウェアのパスキー `SoftAuthenticator` |
| `client/src/client.ts` | §7.7、§8、§9、§11 `WakeClient`（ログイン、暗号化通信、`rekey`、`wakeFetch`、ストアの読み直し `reload`） |
| `client/src/store.ts` | §8.7、§8.11、§9.7 セッションのストア（`memorySessionStore`、`indexedDbSessionStore`） |
| `client/src/ta.ts` | §10.6、§10.11 `listOperations` / `getOperation` / `approve` / `reject` |
| `client/src/display.ts` | §10.11 手順5 `hashInput` の表示用の分割（`segmentHashInput`） |
| `client/src/assertion.ts` | §6.1 ブラウザの `navigator.credentials.get` の呼び出し |
| `client/src/json.ts` | §4.4、§4.8 受け取った JSON と Base64url の検査 |
| `demo/src/app.ts` | デモのサーバー。WAKE の範囲外のパスキー登録と、ET のルート（`/api/me`、`/api/operations`、`/api/operation`）を含む |
| `demo/src/browser/main.ts` | デモの画面（ログイン、セッション、KR、ET、Operation の作成と確認） |
| `demo/src/browser/approve.ts` | §10.11 の承認画面 |
| `demo/test/integration.test.ts`、`demo/test/wake.test.ts` | client と server の結合テスト（KX、SM、KR、TA、TA+KR、ET） |
| `demo/test/e2e/login.spec.ts`、`demo/test/e2e/operations.spec.ts`、`demo/test/e2e/multi-tab.spec.ts` | Chromium の仮想認証器を使う e2e（`multi-tab.spec.ts` は2タブでのログインの共有） |

`npm test` は最初に `scripts/check-deps.ts` で、パッケージ間の依存と外部の実行時依存が許可した表（`allowedEdges`）のとおりかを、`package.json` の宣言と import の両方で検査します。表の外で許可するのは Node の組み込みモジュールだけです。ルートの開発用依存（`typescript`、`@types/node`）は、各パッケージの `test/` と `scripts/` からだけ import でき、宣言はパッケージ自身の `devDependencies` にだけできます。依存の方針は [DESIGN.md](DESIGN.md#22-依存は一方向にし汎用パッケージどうしは依存しない) を参照してください。各パッケージの `tsconfig.json` は `tsconfig.base.json` を `extends` します。

## 使い方

Node.js 22.18 以降（TypeScript を変換なしで実行します）。

```sh
cd impl/ts
npm ci
npm run typecheck
npm test          # 依存の検査、テストベクターの照合、node:crypto との突き合わせ、往復テスト、client と server の結合テスト
npm run vectors   # spec/test-vectors/*.json を再生成
npx playwright install chromium   # 初回だけ。e2e 用のブラウザ
npm run e2e       # demo の e2e（登録、ログイン、ログアウト、KR、Operation の承認・拒否、TA+KR、タブ間のログインの共有）
npm start         # デモを http://localhost:8787 で起動（手元のパスキーで試せる）
```

### デモでタブ間のログインを試す

1. `npm start` で起動し、http://localhost:8787 でパスキーを登録してログインします。
2. Operation を作り、「Open approve page」のリンクを新しいタブで開きます。承認ページはログインし直さずに Operation を読み込みます。両方のページの `session:` の行に、同じセッション ID とエポックが出ます。
3. 承認ページで「Approve + rekey」を押すと、元のタブの表示も、読み込み直さずに新しいエポックに変わります。「Who am I (ET)」も新しいエポックを返します。
4. どちらかのタブでログアウトすると、もう一方も `logged out` になります。

### サーバーとクライアント

```ts
import { createWakeServer, MemoryCredentialStore } from "@wake-protocol/server";

const wake = createWakeServer({
  rpId: "example.com",
  loginOrigins: ["https://example.com"],
  secret: crypto.getRandomValues(new Uint8Array(32)), // 偽の credential ID（§6.6）用
  credentials: new MemoryCredentialStore(),           // 実装者のストア（CredentialStore）
});
// どの Web フレームワークでも、Request を渡す。WAKE 以外のパスなら null
const response = await wake.handle(request);
```

```ts
import { WakeClient, indexedDbSessionStore, navigatorGetAssertion } from "@wake-protocol/client";

const store = indexedDbSessionStore(); // 省略するとメモリだけ（タブごとにログイン）
const client = new WakeClient({ baseUrl: "", getAssertion: navigatorGetAssertion, store });
await client.reload();               // 別のタブのログインがあれば使う（currentSession で確かめる）
store.subscribe(() => void client.reload()); // 別のタブの変更を反映する
await client.login({ mode: "discoverable" });
const info = await client.session(); // wake/session
await client.rekey();                // WAKE-KR（§9）
const op = await client.getOperation(operationIdHex); // §10.11 手順1〜4の検査つき
await client.approve(operationIdHex, { rekey: false }); // WAKE-TA（true で TA+KR）
const res = await client.wakeFetch("/api/me");          // WAKE-ET（Response を返す）
await client.logout();               // wake/logout
```

- Operation の作成・取消・結果の取得はサーバー側の API（`wake.createOperation` / `cancelOperation` / `getOperation`）で行います。利用者向けの作成 API はありません（§10.2）。
- ET のルートは `createWakeServer({ routes: [{ method, path, handler }] })` で登録します。ハンドラーは認証情報（`userId`、`sessionId`、`epoch` など）をプロセス内のオブジェクトで受け取ります（§11.5）。

- credential の公開鍵は SPKI（ブラウザの `getPublicKey()` の値）で保存します。対応する署名方式は ES256 だけです。
- 交換・セッションのストアは非同期のインターフェース（`WakeStore`）で、仮実装にはメモリのもの（`MemoryWakeStore`）だけがあります。鍵はプロセスのメモリに抽出不可の `CryptoKey` で置きます。DB に保存する場合は §8.10 の鍵の保護が必要です。`MemoryWakeStore` は交換を作るときに一定間隔（既定60秒）で期限切れの交換と終了したセッションを掃除します。要求が来ない間も掃除したい場合は、使う側が `sweep(now)` を定期的に呼びます。
- クライアントの鍵は `store` に置きます（§8.11）。既定はインスタンスごとのメモリのストアで、ページを読み込み直すと、もう一度ログインが必要です。
- `indexedDbSessionStore()` を渡すと、同じオリジンのタブでログインを共有します。
  - 抽出不可の `CryptoKey` を IndexedDB に Structured Clone で保存します。保存するのは `sessionId`、今の鍵世代（`k_c2s`、`k_s2c`、`th`）、時刻の offset、`baseUrl`、期限、KR 中の保留世代です。
  - `BroadcastChannel` は「変わった」という通知だけを運び、鍵や状態は運びません。受け取った側は IndexedDB を読み直します。
  - KR と TA+KR は Web Locks（`wake-kr:<sessionId>`）で1タブに限ります。ほかのタブが KR 中なら、待たずに `conflict` を返します（2つめの WebAuthn を出さないため）。
  - 自動では読み直しません。ページの読み込み時、`visibilitychange`・`focus` のとき、`store.subscribe` の通知のときに `reload()` を呼びます（demo の `common.ts`）。今の世代が `epoch_retired` で拒否されたときは、クライアントが自分で読み直します。
  - IndexedDB を使えない環境では、メモリのストアになります。
- §14.3 のレート制限は実装していません。本番で使わないでください。
- `MemoryWakeStore` は、確定した Operation を監査のために消しません（PENDING のまま期限が切れたものも残ります）。長く動かすとメモリが増え続けます。
- demo の `POST /api/operations` は、利用者が `content` を指定して自分宛ての Operation を作れる**デモ専用**の API です。§10.2 の「Operation は実装者のサーバーからだけ作成できる」から外れているので、実際のサービスでは、サーバーが業務の要求から `content` と認否者を決めてください。ユーザーごとの PENDING な Operation は20件までにしています。
- 仕様が決めていない点の扱いは [SPEC-NOTES.md](SPEC-NOTES.md) にまとめています。

WAKE API は core から、汎用ヘルパーは各パッケージから直接インポートします。core が汎用側から公開するのは、本文・平文用の `Bytes` と、導出鍵を取り込む `aesKey` / `hmacKey` だけです。

```ts
import { Bytes } from "@wake-protocol/core";
import { utf8ToBytes } from "@wake-protocol/codec";
import { hex } from "@scure/base";
import { sha256 } from "@wake-protocol/crypto";

const plaintext = new Bytes(utf8ToBytes('{"ok":true}'));
const digestHex = hex.encode(await sha256(plaintext.toUint8Array()));
```

- 16進・Base64url の変換は、`@scure/base` の `hex` / `base64urlnopad` を直接使います。
- codec / crypto は `Uint8Array` を受け取り、返します。`Bytes` を渡す場合は `.toUint8Array()` で変換します。
- 固定幅整数は `Byte` / `Byte2` / `Byte4` / `Byte8`、数値の読み出しは `.number`、バイト値の比較・連結は `.equals()` / `Bytes.concat()` を使います。
- LP の復号は codec の `decodeU32LengthPrefixed`、`number` / `bigint` の変換は bytes の `numberToBigInt` / `bigIntToNumber` を使います。

## API の要点

### `Bytes`

- `Bytes` は実行時のクラスです（`Uint8Array` の型別名ではありません）。`seal` の平文や ET の本文には `new Bytes(u8)` を渡し、`seal` の Wire や `open` の平文などの戻り値を配列として使う場合は `.toUint8Array()` で取り出します。
- 入力と取り出した配列はコピーします。配列要素は `Uint8Array` と同じ規則で変換するため、`new Bytes([256, -1, 1.5])` は `[0, 255, 1]` になります。
- コピーによって秘密の値が複数箇所に残りうるため、`Bytes` は秘密データの消去を保証する仕組みではありません。
- `fixedLength<B extends string>(name, len)` はブランド識別子を受け取り、`Brand<B>` を返す検査関数を作ります（例: `fixedLength<"Token">("token", 16)`）。`Byte4` などのクラス型を型引数に指定することはできません。

### 鍵

core の鍵インポートは、鍵の役割を型で区別します。ブランドは型検査用で、実行時には消えます。

| 関数 | 受け取るもの | 返すもの |
|---|---|---|
| `aesKey` | `C2sKey` / `S2cKey` | `C2sCryptoKey` / `S2cCryptoKey` |
| `hmacKey` | `FinishedKeyC` / `FinishedKeyS` | `FinishedCryptoKeyC` / `FinishedCryptoKeyS` |

```ts
import { aesKey, hmacKey } from "@wake-protocol/core";

// keys は deriveKeys の戻り値
const messageKey = await aesKey(keys.kC2s);  // C2sCryptoKey
const finishedKey = await hmacKey(keys.fkC); // FinishedCryptoKeyC
```

- 外部から受け取った鍵の配列は、`asC2sKey(u8)` などで長さと役割のブランドを付けてから渡します。
- `seal` / `sealWithHeader` / `open` / `openParsed` は、鍵の役割と方向を組にして受け取ります。`C2sCryptoKey` は `DIR_C2S`、`S2cCryptoKey` は `DIR_S2C` の場合だけ使えます（`open` / `openParsed` の `expectDir` も同じ）。testing の `sealWithIv` は `C2sCryptoKey | S2cCryptoKey` を受け取ります。
- `clientFinished` / `verifyClientFinished` は `FinishedKeyC | FinishedCryptoKeyC`、`serverFinished` / `verifyServerFinished` は `FinishedKeyS | FinishedCryptoKeyS` を受け取ります。
- 汎用 crypto の `aesGcmEncrypt` / `aesGcmDecrypt` は、AES-GCM・256ビット・必要な用途（encrypt / decrypt）を持つ鍵かを検査し、不一致は `TypeError` にします。IV が12バイトでなければ `RangeError` です。復号の `null` は認証失敗だけを表し、それ以外の例外は投げます。core の `seal` / `open` / `openParsed` でも、合わない鍵は `TypeError`、認証失敗は `WakeError("reauth")` になります。Finished の関数に合わない鍵を渡した場合は、Web Crypto の `DOMException`（`InvalidAccessError`）がそのまま伝わります。

### エラー

方針の全体は [DESIGN.md](DESIGN.md#3-エラーの扱い) を参照してください。

- 呼び出し側が固定幅の整数フィールドに範囲外の数値を渡すと、`RangeError` にします。
  - `encodeRekeyTranscript` / `rekeyTranscriptHash` の `epoch`: 整数の 1..2^32-1
  - メッセージヘッダーの `epoch`: 整数の 0..2^32-1
  - `issuedAt` / `serverTime` / `absoluteExpiresAt`: 整数の 0..2^53-1
  - `idleTimeoutSec`: 整数の 0..2^32-1
- `parseWire` / `decodeEtRequest` / `decodeEtResponse` が受け取ったデータの形式不正は、`WakeError` のコードにします。
- `checkContext`、`checkContent`、ET の意味の検査（status の範囲を含む）は、エンコード時も意図的に `WakeError` を投げます。オプションの検査は `invalid_option` です。
- ベクターで数値の失敗にコードが必要な場合は、ベクター実行側で付け替えます。

### ET のサイズ上限

core は、既定の ET 上限での最大エンコード長を `ET_REQUEST_MAX_ENCODED`（1,128,491バイト）と `ET_RESPONSE_MAX_ENCODED`（1,122,335バイト）として公開します。

- ヘッダーは名前が最低1バイト、値が空でもよいため、`ET_HEADERS_MAX` の8192バイトで最大8192組になります。入れ子の LP は各組に4バイトの長さを2つ付けるので、ヘッダー全体は `8192 + 8192 × 8 = 73728` バイトです。
- リクエストの最大長は、外側の LP（6 × 4）、ラベル（13）、最長のメソッド（DELETE、6）、パス（2048）、クエリー（4096）、ヘッダー（73728）、本文（1048576）の合計です。
- レスポンスの最大長は、外側の LP（4 × 4）、ラベル（13）、status（2）、ヘッダー（73728）、本文（1048576）の合計です。
- `DEFAULT_MAX_PLAINTEXT` は両者の最大値（1,128,491バイト）なので、既定の ET 上限で受け付けるデータは `seal` / `parseWire` / `open` でも受け付けます。`bodyLimit` を大きくする場合は、必要に応じて `maxPlaintext` も増やします。

### テスト専用 API

`@wake-protocol/core/testing` には、乱数を固定するものや制約のない符号化を置いています（`sealWithIv`、`importEcdhPrivateKey`、`encodeChallengeInput`）。本番のコードでは使いません。WebAuthn Challenge は、公開 API の儀式ごとの `kxChallenge` / `krChallenge` / `taChallenge` / `taKrChallenge` で作ります。

## テストベクター

[`spec/test-vectors/`](../../spec/test-vectors/) に §16 の形式で置いています。バイト列は小文字の16進、`ε` は空文字列です。
生成処理とベクターの実行処理は `core/vectors/src/` に置き、`@wake-protocol/vectors` から公開します。`npm run vectors` は `core/vectors/scripts/generate-vectors.ts` の薄い CLI から生成処理を呼びます。入力はすべて固定値のため、何度実行しても同じ内容になります。

`core/protocol/test/et-decode.test.ts` はエンコーダーを通さず、壊れた ET の受信バイト列をデコーダーへ直接渡します。LP の切断、余分なフィールド、ラベル、status の不正は `invalid_request`、意味や上限の違反は `invalid_method` / `invalid_path` / `invalid_header` / `too_large` を保つことを確認します。

## ロードマップ

- [x] M1: 暗号コアとテストベクター
- [x] M2: KX と SM をブラウザ（パスキー）と Node サーバーで端から端まで動かす
- [x] M3: KR、TA、ET
