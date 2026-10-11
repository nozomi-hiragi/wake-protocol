# WAKE 仮実装（TypeScript）

[WAKE Protocol 仕様書](../../spec/wake-protocol.md) が実際に動くか、曖昧な所がないかを確かめるための仮実装です。**本番では使わないでください。**

## 構成

| パッケージ | 内容 |
|---|---|
| `packages/bytes`（`@wake-protocol/bytes`） | 不変のバイト値、固定幅整数、ブランド型。依存なし |
| `packages/codec`（`@wake-protocol/codec`） | `Uint8Array` 用の LP、文字列。依存なし |
| `packages/crypto`（`@wake-protocol/crypto`） | `Uint8Array` 用の Web Crypto API ヘルパー。`@scure/base` 2.4.0 に依存 |
| `packages/core`（`@wake-protocol/core`） | WAKE プロトコル。bytes / codec / crypto と `@scure/base` 2.4.0 に依存 |
| `packages/vectors`（`@wake-protocol/vectors`） | §16 テストベクターの生成と照合。core / bytes / codec と `@scure/base` 2.4.0 に依存 |

`packages/` の主なファイル（各パッケージの `index.ts` が入口）:

| ファイル | 仕様 |
|---|---|
| `bytes/src/bytes.ts` | §4.1 不変所有の `Bytes` と、`.number` を持つ固定幅 `Byte` / `Byte2` / `Byte4` / `Byte8` |
| `codec/src/length-prefixed.ts` | §4.2 LP とフィールド長の検査 |
| `codec/src/text.ts` | §4 ASCII、Latin-1、UTF-8 の変換 |
| `bytes/src/bigint.ts` | 整数の `number` / `bigint` 変換 |
| `bytes/src/brand.ts` | ブランド型の共通定義 |
| `crypto/src/hash.ts` | §5.1 SHA-256、HKDF、HMAC、乱数 |
| `crypto/src/aes.ts` | §8.3 AES-256-GCM |
| `crypto/src/p256.ts` | §5.2 汎用 ECDH P-256 |
| `crypto/src/index.ts` | 汎用暗号ヘルパーのエクスポート |
| `bytes/src/index.ts` | バイト値・整数・ブランド型のエクスポート |
| `codec/src/index.ts` | 汎用コーデックのエクスポート |
| `core/src/spec/crypto.ts` | §5.1、§8.3 鍵インポートと内部 AEAD 用の `Bytes` アダプター |
| `core/src/spec/domain.ts` | §4.2、§5 ドメイン分離付き LP とラベルの検査 |
| `core/src/spec/errors.ts` | §12 エラーコードと変換 |
| `core/src/spec/labels.ts` | §4.7、§5.3–5.7、§8.2、§11.2 ドメイン分離ラベル |
| `core/src/spec/limits.ts` | §12.3 長さ上限の検査 |
| `core/src/spec/types.ts` | §4 固定長の WAKE ブランド型と検査 |
| `core/src/keys/ids.ts` | §4.6、§5.3–5.4、§8.3、§10.3 固定長の識別子・Nonce・IV の生成 |
| `core/src/keys/ecdh.ts` | §5.2 一時鍵の生成、公開鍵の検査、共有秘密 |
| `core/src/kx/transcript.ts` | §5.3 ログイン・鍵更新の Transcript |
| `core/src/kx/binding.ts` | §5.4 TA承認の結び付け |
| `core/src/kx/challenge.ts` | §5.5 WebAuthn Challenge |
| `core/src/kx/schedule.ts` | §5.6 鍵導出 |
| `core/src/kx/finished.ts` | §5.7 Client / Server Finished と検証 |
| `core/src/msg/header.ts` | §8.2、§8.7 メッセージヘッダー、Wire の解析、平文長の検査 |
| `core/src/msg/aead.ts` | §8.3 暗号化メッセージの Seal / Open |
| `core/src/ta/content.ts` | §10.4 文面プロファイルの検査 |
| `core/src/ta/operation.ts` | §10.3 `hashInput`、`operationId`、操作識別子の生成 |
| `core/src/et/types.ts` | §11.2 `EtRequest` / `EtResponse` の型、ラベル、上限 |
| `core/src/et/validate.ts` | §11.2–11.4 メソッド、パス、クエリー、ヘッダー、ステータスの検査 |
| `core/src/et/codec.ts` | §11.2 リクエスト・レスポンスのエンコード / デコード |
| `core/src/index.ts` | §4–§11 公開 API |
| `core/src/testing.ts` | §16 テスト専用ヘルパー |
| `vectors/src/index.ts` | §16 ベクター生成・実行ヘルパーのエクスポート |
| `vectors/src/generate-vectors.ts` | §16 固定入力から JSON ベクターを生成 |
| `vectors/src/vector-ops.ts` | §16 ベクター入力を公開 API で実行 |
| `vectors/scripts/generate-vectors.ts` | `src` の生成処理を呼ぶ CLI の入口 |
| `vectors/test/vectors.test.ts` | §16 保存済みベクターと実装の照合 |
| `vectors/test/generate.test.ts` | §16 生成結果の安定性の検査 |

`npm test` は最初に `scripts/check-deps.ts` でパッケージ間の依存方向を明示した一覧と宣言・import を照合し、検査器の回帰テストの後、すべてのパッケージのテストを実行します。汎用パッケージ同士は依存しません。import の抽出には TypeScript のコンパイラ API を使い、動的 import やコメントを挟んだ import も検査します。TypeScript 設定は `tsconfig.base.json` に共通化し、各パッケージから `extends` します。

## 使い方

Node.js 22.18 以降（TypeScript を変換なしで実行します）。

```sh
cd impl/ts
npm install
npm run typecheck
npm test          # テストベクターの照合、node:crypto との突き合わせ、往復テスト
npm run vectors   # spec/test-vectors/*.json を再生成
```

WAKE API は core から、汎用ヘルパーは各パッケージから直接インポートします。core は、本文・平文用の `Bytes` と、導出鍵を取り込む `aesKey` / `hmacKey` を公開します。

```ts
import { Bytes } from "@wake-protocol/core";
import { utf8ToBytes } from "@wake-protocol/codec";
import { hex } from "@scure/base";
import { sha256 } from "@wake-protocol/crypto";

const plaintext = new Bytes(utf8ToBytes('{"ok":true}'));
const digestHex = hex.encode(await sha256(plaintext.toUint8Array()));
```

16進・Base64url の変換は `@scure/base` の `hex` / `base64urlnopad` を直接使います。

codec / crypto は `Uint8Array` を受け取り、返します。`Bytes` を渡す場合は `.toUint8Array()` で変換します。固定幅整数は `Byte` / `Byte2` / `Byte4` / `Byte8`、数値の読み出しは `.number`、バイト値の比較・連結は `.equals()` / `Bytes.concat()` を使います。LP の復号は codec の `decodeU32LengthPrefixed`、`number` / `bigint` の変換は bytes の `numberToBigInt` / `bigIntToNumber` を使います。

`bytesToAscii` が大きな ASCII 入力でスタックあふれを起こす問題を修正しました。ASCII の厳密な検査は維持しています。

`Bytes` は `Uint8Array` の型別名から実行時のクラスに変わりました。`seal` の平文や ET の本文には `new Bytes(u8)` を渡し、`seal` の Wire や `open` の平文などの戻り値を配列として使う場合は `.toUint8Array()` で取り出します。導出鍵は `aesKey(keys.kC2s)` / `hmacKey(keys.fkC)` のように役割付きの値を渡し、外部の鍵配列は `asC2sKey(u8)` などで長さと役割のブランドを付けます。

`Bytes` は入力と取り出した配列をコピーします。配列要素は `Uint8Array` と同じ規則で変換するため、`new Bytes([256, -1, 1.5])` は `[0, 255, 1]` になります。コピーによって秘密の値が複数箇所に残りうるため、`Bytes` は秘密データの消去を保証する仕組みではありません。

`fixedLength<B extends string>(name, len)` はブランド識別子を受け取り、`Brand<B>` を返す検査関数を作ります。たとえば `fixedLength<"Token">("token", 16)` と書きます。`Byte4` などのクラス型を型引数に指定することはできません。

core の鍵インポートは用途を型で区別します。`aesKey` は `C2sKey` / `S2cKey` だけを受け取り、それぞれ `C2sCryptoKey` / `S2cCryptoKey` を返します。`hmacKey` は `FinishedKeyC` / `FinishedKeyS` だけを受け取り、それぞれ `FinishedCryptoKeyC` / `FinishedCryptoKeyS` を返します。4つの読み込み済み鍵型も core から公開します。これらのブランドは型検査用で、実行時には消えます。

```ts
import { aesKey, hmacKey } from "@wake-protocol/core";

// keys は deriveKeys の戻り値
const messageKey = await aesKey(keys.kC2s);  // C2sCryptoKey
const finishedKey = await hmacKey(keys.fkC); // FinishedCryptoKeyC
```

`seal` / `open` / `openParsed` と testing の `sealWithIv` は `C2sCryptoKey | S2cCryptoKey` を受け取ります。`clientFinished` / `verifyClientFinished` は `FinishedKeyC | FinishedCryptoKeyC`、`serverFinished` / `verifyServerFinished` は `FinishedKeyS | FinishedCryptoKeyS` を受け取ります。`open` の `expectDir` は `MsgHeader["dir"]`（`DIR_C2S | DIR_S2C`）に限定します。

汎用 crypto の `aesGcmEncrypt` / `aesGcmDecrypt` は AES-GCM、256ビット、必要な用途（encrypt / decrypt）を持つ鍵を検査し、不一致は `TypeError` にします。IV が12バイトでなければ `RangeError` です。復号の `null` は認証失敗だけを表し、それ以外の例外は伝播します。core でもローカルの鍵の誤りは `TypeError`、認証失敗は `WakeError("reauth")` になります。

`encodeChallengeInput` は `@wake-protocol/core/testing` に移しました。公開 API では儀式ごとの `kxChallenge` / `krChallenge` / `taChallenge` / `taKrChallenge` を使います。

呼び出し側が渡した範囲外の数値は `RangeError` にします。`encodeRekeyTranscript` / `rekeyTranscriptHash` の `epoch` は整数の 1..2^32-1、メッセージヘッダーの `epoch` は整数の 0..2^32-1、`issuedAt` / `serverTime` / `absoluteExpiresAt` は整数の 0..2^53-1、`idleTimeoutSec` は整数の 0..2^32-1 です。一方、`parseWire` / `decodeEtRequest` / `decodeEtResponse` が受け取ったデータの形式不正は `WakeError` のコードに変換します。`checkContext`、`checkContent`、ET の意味の検査はエンコード時も意図的に `WakeError` を投げ、オプションの検査は `invalid_option` を保ちます。ベクターで数値の失敗にコードが必要な場合は、ベクター実行側で付け替えます。

core は既定の ET 上限での最大エンコード長を `ET_REQUEST_MAX_ENCODED`（1,128,491バイト）と `ET_RESPONSE_MAX_ENCODED`（1,122,335バイト）として公開します。ヘッダーは名前が最低1バイト、値が空でもよいため、`ET_HEADERS_MAX` の8192バイトで最大8192組になります。入れ子の LP は各組に4バイトの長さを2つ付けるので、ヘッダー全体は `8192 + 8192 × 8 = 73728` バイトです。

リクエストの最大長は外側の LP（6 × 4）、ラベル（13）、最長のメソッド（DELETE、6）、パス（2048）、クエリー（4096）、ヘッダー（73728）、本文（1048576）の合計です。レスポンスは外側の LP（4 × 4）、ラベル（13）、status（2）、ヘッダー（73728）、本文（1048576）の合計です。`DEFAULT_MAX_PLAINTEXT` は両者の最大値に変更し、既定の ET 上限で受け付けるデータを `seal` / `parseWire` / `open` でも受け付けます。`bodyLimit` を大きくする場合は、必要に応じて `maxPlaintext` も増やします。

## テストベクター

[`spec/test-vectors/`](../../spec/test-vectors/) に §16 の形式で置いています。バイト列は小文字の16進、`ε` は空文字列です。
生成処理とベクターの実行処理は `packages/vectors/src/` に置き、`@wake-protocol/vectors` から公開します。`npm run vectors` は `packages/vectors/scripts/generate-vectors.ts` の薄い CLI から生成処理を呼びます。入力はすべて固定値のため、何度実行しても同じ内容になります。

`packages/core/test/et-decode.test.ts` はエンコーダーを通さず、壊れた ET の受信バイト列をデコーダーへ直接渡します。LP の切断、余分なフィールド、ラベル、status の不正は `invalid_request`、意味や上限の違反は `invalid_method` / `invalid_path` / `invalid_header` / `too_large` を保つことを確認します。

## ロードマップ

- [x] M1: 暗号コアとテストベクター
- [ ] M2: KX と SM をブラウザ（パスキー）と Node サーバーで端から端まで動かす
- [ ] M3: KR、TA、ET

仮実装で見つかった仕様の曖昧点は [SPEC-NOTES.md](SPEC-NOTES.md) にまとめています。
