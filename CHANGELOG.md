# Changelog

## v0.5.0（未リリース）

- TypeScript の仮実装（暗号コア）を `impl/ts/` に追加
- §16 のテストベクターを `spec/test-vectors/` に追加
- TypeScript の仮実装を `@wake-protocol/bytes`、`@wake-protocol/codec`、`@wake-protocol/crypto`、`@wake-protocol/core`、`@wake-protocol/vectors` のワークスペースに分割
- パッケージ間の依存方向を明示し、宣言と import を検査。動的 import やコメントを挟んだ import も TypeScript のコンパイラ API で抽出し、検査器の回帰テストを追加。TypeScript 設定は `tsconfig.base.json` に共通化
- `bytesToAscii` が大きな ASCII 入力でスタックあふれを起こす問題を修正
- 16進・Base64url の変換に `@scure/base` 2.4.0 を採用
- TypeScript API の破壊的変更: `u8` / `u16` / `u32` / `u64` と `readU*` を `@wake-protocol/bytes` の `Byte` / `Byte2` / `Byte4` / `Byte8` と `.number` に置換。`equalBytes` は `Bytes.equals`、`concat` は `Bytes.concat`、`lpDecodeAll` は `@wake-protocol/codec` の `decodeU32LengthPrefixed`、`timeToU64` / `u64ToTime` は `@wake-protocol/bytes` の `numberToBigInt` / `bigIntToNumber` に置換
- `Bytes` の移行（破壊的変更）: `Uint8Array` の型別名から実行時のクラスへ変更。`seal(key, header, new Bytes(u8))` や ET の `body: new Bytes(u8)` のように本文・平文を包む。`seal` / `encodeHeader` / `encodeEtRequest` / `encodeEtResponse` の戻り値、`open` / `openParsed` の平文、ET デコード後の本文は `Bytes` なので、配列が必要なら `.toUint8Array()` を使う。鍵インポートも配列の直接渡しを廃止し、`aesKey(asC2sKey(u8))` / `hmacKey(asFinishedKeyC(u8))` または `deriveKeys` の役割付き鍵を渡す。`new Bytes(u8)` と `.toUint8Array()` はどちらもコピーし、元の配列とは共有しない。TypeScript の型注釈だけでは変換されないため、JavaScript の呼び出し側も同様に移行が必要
- コーデック API の破壊的変更: `lp` / `lpDecode` / `checkLpLengths` を `encodeU32LengthPrefixed` / `decodeU32LengthPrefixed` / `checkFieldLengths` に改名。16進・Base64url のヘルパー（旧 `hex` / `fromHex` / `b64u` / `fromB64u`）を API から削除し、`@scure/base` の `hex` / `base64urlnopad` を直接使う。文字列は `ascii` → `asciiToBytes`、`readAscii` → `bytesToAscii`、`utf8` → `utf8ToBytes`、`readUtf8` → `bytesToUtf8`、`latin1` → `latin1ToBytes`、`readLatin1` → `bytesToLatin1` に改名
- `@wake-protocol/core` は汎用ヘルパーの再エクスポートを廃止。汎用ヘルパーは bytes / codec / crypto から直接インポートする。WAKE API に必要な `Bytes` と鍵インポート用の `aesKey` / `hmacKey` は core に残す
- core の鍵 API の破壊的変更: `aesKey` は `C2sKey` / `S2cKey` のみを受け取り、それぞれ新しい `C2sCryptoKey` / `S2cCryptoKey` を返す。`hmacKey` は `FinishedKeyC` / `FinishedKeyS` のみを受け取り、それぞれ新しい `FinishedCryptoKeyC` / `FinishedCryptoKeyS` を返す。4型は core から公開し、`seal` / `open` / `openParsed` / testing の `sealWithIv` と Finished の生成・検証も用途に合う鍵型に限定
- AES の破壊的変更: メッセージ暗号化・復号と汎用 `aesGcmEncrypt` / `aesGcmDecrypt` は AES-GCM の256ビット鍵と必要な用途を検査し、不一致は `TypeError`、12バイト以外の IV は `RangeError` にする。復号の `null` は認証失敗だけに限定し、その他の例外は伝播
- core の API の破壊的変更: `encodeChallengeInput` をメインのエクスポートから `@wake-protocol/core/testing` に移動。`open` の `expectDir` を `MsgHeader["dir"]`（`DIR_C2S | DIR_S2C`）に限定
- core の鍵と方向の破壊的変更: `seal` / `sealWithHeader` / `open` / `openParsed` は、鍵の役割と `dir` の組み合わせを型で確かめるようになった。旧: `seal(key: C2sCryptoKey | S2cCryptoKey, h: SealInput, plaintext, opts?)`、`sealWithHeader(key: C2sCryptoKey | S2cCryptoKey, h: MsgHeader, plaintext, opts?)`、`open(key: C2sCryptoKey | S2cCryptoKey, wire, expectDir: MsgHeader["dir"], opts?)`、`openParsed(key: C2sCryptoKey | S2cCryptoKey, p)`。新: `seal(key: C2sCryptoKey, h: SealInput & { dir: typeof DIR_C2S }, plaintext, opts?)` と `seal(key: S2cCryptoKey, h: SealInput & { dir: typeof DIR_S2C }, plaintext, opts?)`、`sealWithHeader` も同様に `MsgHeader & { dir: ... }` の組にする。`open(key: C2sCryptoKey, wire, expectDir: typeof DIR_C2S, opts?)` と S2c 版、`openParsed(key: C2sCryptoKey, p, expectDir: typeof DIR_C2S)` と S2c 版（`expectDir` は必須になった）。`openParsed` は解析した `dir` と `expectDir` が違えば、復号の前に `bad_request` を投げる。
- `fixedLength` の型引数をブランド識別子の文字列に変更し、`Brand<B>` を返す形に限定。`fixedLength<"Token">(...)` のように使い、固定幅整数のクラス型は指定できない
- 数値のエラー方針を README と JSDoc に明記。`encodeRekeyTranscript` / `rekeyTranscriptHash` の `epoch` が整数でない・1未満・u32超過のいずれも `RangeError` に統一し、ベクター用の `bad_request` への変換は実行側へ移動。受信データのエラー変換は汎用の復号処理に限定
- `Bytes` の配列要素は `Uint8Array` と同じ変換規則を使い、コピーにより秘密データの消去を保証できないことを文書化
- core に `ET_REQUEST_MAX_ENCODED`（1,128,491バイト）と `ET_RESPONSE_MAX_ENCODED`（1,122,335バイト）を追加。ET の全上限と外側・入れ子の LP 長を含めて計算し、`DEFAULT_MAX_PLAINTEXT` を従来の1,114,112から両者の最大値である1,128,491バイトへ変更。既定の ET 上限の最悪ケースが暗号化・復号まで通ることをテストで確認
- ベクターの再利用可能な生成・実行処理を `packages/vectors/src/` に移動し、scripts は生成 CLI の入口に限定。`@wake-protocol/vectors` のエクスポートと生成内容は維持
- ET 受信デコーダーに不正なバイト列を直接渡すテストを追加し、構造エラーと意味・上限のエラーコードを確認。core のヘッダーテストをメッセージ用のファイルへ整理し、汎用テストの重複を削除
- 仕様書を v0.5 に更新（変更点は [仕様書 §0](spec/wake-protocol.md#0-v04からの主な変更)）。TA文面のプロファイル簡素化、ETの責任範囲の整理、テストベクターのエラーコード定義など

## v0.4.0 (2026-10-10)

v0.3 からの主な変更は [仕様書 §0.1](spec/wake-protocol.md#01-v03からv04への主な変更) を参照してください。

## v0.3（2026-10-09、タグなし）

- 初版の設計ドラフト
