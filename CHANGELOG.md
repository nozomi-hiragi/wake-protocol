# Changelog

## v0.6.0 (2026-10-16)

- TypeScript 仮実装の 6 パッケージを、バージョン 0.6.0 で npm / JSR に公開するためのビルド、配布物・バージョンの検査、CI と公開ワークフローを追加。vectors / demo とテスト専用の `./testing` は公開対象に含めない

## v0.5.0 (2026-10-16)

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
- ベクターの再利用可能な生成・実行処理を `core/vectors/src/` に移動し、scripts は生成 CLI の入口に限定。`@wake-protocol/vectors` のエクスポートと生成内容は維持
- ET 受信デコーダーに不正なバイト列を直接渡すテストを追加し、構造エラーと意味・上限のエラーコードを確認。core のヘッダーテストをメッセージ用のファイルへ整理し、汎用テストの重複を削除
- 仮実装 M2: `@wake-protocol/server`（KX と SM のサーバー。フレームワーク非依存の `handle(req: Request)`、§6.2 の WebAuthn 検証、§7.5・§7.6 の原子的で冪等な確定、`/wake/up` の §8.3 の処理順と §8.6 の鍵世代の表、`wake/session`・`wake/logout`、失効 API、メモリのストア、テスト用の `SoftAuthenticator`）を追加
- 仮実装 M2: `@wake-protocol/client`（ブラウザと Node で動く KX と SM のクライアント。抽出不可の鍵、`/auth/complete` の同一本文での再送、`serverFinished` の検証、時刻の補正、`stale_request` での再送、ログアウト）を追加
- 仮実装 M2: `@wake-protocol/demo`（Hono によるデモアプリ、パスキーの登録画面、client と server の結合テスト、Chromium の仮想認証器を使う Playwright の e2e）を追加
- 仮実装 M3: WAKE-KR（§9）を server と client に追加。鍵世代の原子的な更新、旧世代の猶予期間、同一平文の再送と `epoch_retired` からの回復、同時に PENDING にできる KR 交換の上限
- 仮実装 M3: WAKE-TA と TA+KR（§10）を追加。server に Operation の作成・取消・取得と認否記録（付録C の形式での書き出しを含む）、`wake/ta/list`・`get`・`challenge`・`approve`・`reject`。client に §10.11 の検査つきの取得と承認、承認画面の表示用の `segmentHashInput`。core に認否記録の検証 `verifyApprovalBundle`
- 仮実装 M3: WAKE-ET（§11）を追加。server に `/wake/transport` と完全一致のルート登録、client に `wakeFetch`
- 仮実装 M3: demo に KR・TA・ET の画面、承認画面、結合テストと e2e を追加
- client に複数タブでのセッションの共有（§8.11、§9.7）を追加。`WakeClient` の `store` オプションに `SessionStore` を渡すと、ログイン、鍵世代の切り替え、ログアウトをタブ間で共有する。既定はインスタンスごとのメモリのストアで、これまでと同じ動き（ページの読み込みごとにログイン）
  - `indexedDbSessionStore()`: IndexedDB を正とし、`BroadcastChannel` は変更の通知だけに使う。KR の排他は Web Locks（`wake-kr:<sessionId>`、待たずに `conflict`）。IndexedDB を使えない環境ではメモリのストアになる
  - `memorySessionStore()`: 同じプロセスの複数の `WakeClient` で共有できるストア（テストや Node 用）
  - `reload()` と `currentSession` を追加。ストアを読み直し、別のタブが確定した世代に切り替える。今の世代が `epoch_retired` で拒否されたときも読み直し、新しい世代で1回だけ送り直す。保存された保留世代があれば、§9.6 の手順で `wake/session` を送って回復する
  - 暗号化の回数は、ストアの共有カウンターからブロック単位（既定4096回、`encryptionBlockSize`）で予約し、`maxEncryptionsPerKey` をタブ全体で守る（§8.7）
- demo の画面がタブ間でログインを共有する。承認ページはログインし直さずに Operation を読み込み、両方のページにセッション ID とエポックを表示する。e2e に2タブのテストを追加
- `@wake-protocol/server` のストアの破壊的変更（M2 からの移行）: 自作のストアは次を実装する必要がある。`createWakeServer` は足りないメソッドがあると `invalid_option` を投げる
  - `CredentialStore`: 旧 `getCredential` / `findUserByUsername` / `compareAndSetSignCount` / `updateSignCount`。新 `findUserCredentials(userId): Promise<WakeCredential[]>` を追加（KR・TA の `allowCredentials` 用。ユーザーのすべての credential を返し、サーバーが active のものに絞る）
  - `WakeStore`: 新 `createRekey` / `commitRekey` / `supersedeExchange`（KR）、`createOperation` / `getOperation` / `listOperations` / `cancelOperation` / `rejectOperation` / `createApproval` / `getApproval` / `commitApproval`（TA）を追加。`commitRekey` と `commitApproval` は M2 の `commitLogin` と同じく、条件の確認と書き込みを1つの原子的操作で行う。`clearSignCountUpdate(id)` は交換 ID に加えて承認試行の ID も受け取る
  - `EpochKeys`: 旧 `{ c2s, s2c, th, c2sCount, s2cCount }`。新 `authTime`（その鍵世代を確立した認証の時刻）と `credentialId`（その認証の credential）が必須。保存済みのセッションを移行する場合は、現世代に `authTime = SessionRecord.authTime`、`credentialId = lastAuthCredentialId` を入れる
  - `ExchangeRecord` に KR 用の任意の項目（`targetEpoch`、`prevTh`、`createdAt`、`boundApprovalId`、`reauthenticatedCredentialId`）が加わる。保存・読み出しで項目を落とさないこと。M2 からある `SessionRecord` の `prevKeys` / `prevValidUntil` は、KR で実際に使われるようになる
  - `SessionRecord`: 新 `authCredentialIds`（ログインと各 KR・TA+KR で使った credential ID の集合）が必須。`revokeSessionsByCredential` はこのどれかに一致するセッションを失効させる（§6.5）。保存済みのセッションには、`loginCredentialId` と `lastAuthCredentialId` を入れる
- M3 で見つかった仕様の論点（TA+KR の `prevTh` は §10.7 の文面どおりに決着、`already_decided` と `expired` の返し方、ET での §8.3 のエラーなど）を `impl/ts/SPEC-NOTES.md` に記録
- codec に厳密な I-JSON のパーサー `parseIJson`、crypto に ECDSA の DER と `r‖s` の変換（`ecdsaDerToRaw` / `ecdsaRawToDer`）と P-256 の署名検証（`importP256SpkiPublicKey` / `p256EcdsaVerify`）、定数時間の比較（`constantTimeEqual`）を追加
- 依存を追加: demo の実行時に `hono` 4.13.13（MIT）と `@hono/node-server` 2.1.3（MIT）、開発用に `esbuild` 0.28.2（MIT）と `@playwright/test` 1.63.0（Apache-2.0）。いずれもバージョンを完全に固定
- M2 で見つかった仕様の論点（公開鍵を SPKI で保存、署名カウンターの更新の原子性、期限の境界など）を `impl/ts/SPEC-NOTES.md` に記録
- 仕様: `/auth/start` の応答に `serverTime` を追加（§7.2）。クライアントは `/auth/complete` の再送の期限を `expiresAt − serverTime` から端末の時刻で求める（§7.7）。端末の時計がずれていると、`/auth/complete` を1回も送らずに失敗していたため
- core に、受け取った JSON と Base64url の項目を検査する `parseJsonObject` / `decodeBase64urlField` を追加し、server と client で共有
- 仕様書を v0.5 に更新（変更点は [仕様書 §0](spec/wake-protocol.md#0-v04からの主な変更)）。TA文面のプロファイル簡素化、ETの責任範囲の整理、テストベクターのエラーコード定義など
- TypeScript の仮実装のフォルダを `impl/ts/{core,client,server,demo}` に整理。共通の `bytes` / `codec` / `crypto` / `vectors` と WAKE 本体（`core/protocol`、パッケージ名は `@wake-protocol/core` のまま）は `core/` の下に置く。パッケージ名と API は変更なし
- コーデック API の破壊的変更: `parseIJson` を削除。旧 `parseIJson(text)` と同等の検査を行うには core の `parseJsonObject` を使う（UTF-8 のバイト列とエラーコードを受け取り、トップレベルはオブジェクトに限る）。`@nozomi-hiragi/i-json` の `parse` を直接呼ぶ場合は `{ strict: true, maxDepth: 64 }` を指定し、値全体をたどって絶対値が 2⁵³ 以上の整数を別途拒否する。非文字と、倍精度で表せない精度の小数は拒否する

## v0.4.0 (2026-10-10)

v0.3 からの主な変更は [仕様書 §0.1](spec/wake-protocol.md#01-v03からv04への主な変更) を参照してください。

## v0.3（2026-10-09、タグなし）

- 初版の設計ドラフト
