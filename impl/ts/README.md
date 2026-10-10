# WAKE 仮実装（TypeScript）

[WAKE Protocol 仕様書](../../spec/wake-protocol.md) が実際に動くか、曖昧な所がないかを確かめるための仮実装です。**本番では使わないでください。**

## 構成

| パッケージ | 内容 |
|---|---|
| `packages/core` | 暗号コア。Web Crypto APIだけで書かれており、ブラウザとNodeの両方で動く |

`packages/core/src` の内容:

| ファイル | 仕様 |
|---|---|
| `encoding.ts` | §4 整数、LP、文字列、Base64url、16進 |
| `crypto.ts` | §5.1–5.2 SHA-256、HKDF、HMAC、AES-256-GCM、ECDH P-256 |
| `kx.ts` | §5.3–5.7 Transcript、TA承認の結び付け、WebAuthn Challenge、鍵導出、Finished |
| `msg.ts` | §8.2–8.4 暗号化メッセージ（`MsgHeader`、Seal / Open） |
| `ta.ts` | §10.3–10.4 文面プロファイル、`hashInput`、`operationId` |
| `et.ts` | §11.2–11.6 `EtRequest` / `EtResponse`、パス・ヘッダーの検査 |

## 使い方

Node.js 22.18 以降（TypeScript を変換なしで実行します）。

```sh
cd impl/ts
npm install
npm run typecheck
npm test          # テストベクターの照合、node:crypto との突き合わせ、往復テスト
npm run vectors   # spec/test-vectors/*.json を再生成
```

## テストベクター

[`spec/test-vectors/`](../../spec/test-vectors/) に §16 の形式で置いています。バイト列は小文字の16進、`ε` は空文字列です。
生成は `packages/core/scripts/generate-vectors.ts` で、入力はすべて固定値のため、何度実行しても同じ内容になります。

## ロードマップ

- [x] M1: 暗号コアとテストベクター
- [ ] M2: KX と SM をブラウザ（パスキー）と Node サーバーで端から端まで動かす
- [ ] M3: KR、TA、ET

仮実装で見つかった仕様の曖昧点は [SPEC-NOTES.md](SPEC-NOTES.md) にまとめています。
