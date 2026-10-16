# @wake-protocol/crypto

Web Crypto API のラッパー（SHA-256、HMAC、HKDF、AES-256-GCM、P-256 ECDH / ECDSA）を提供します。ブラウザと Node.js の両方で動きます。[WAKE Protocol](https://github.com/nozomi-hiragi/wake-protocol) 仮実装のコアライブラリです。

> [!WARNING]
> これは仕様の動作確認のための仮実装です。本番では使わないでください。

## インストール

```sh
# npm
npm install @wake-protocol/crypto

# JSR（npm など）
npx jsr add @wake-protocol/crypto

# JSR（Deno）
deno add jsr:@wake-protocol/crypto
```

## 関連リンク

- [WAKE Protocol 仕様書](https://github.com/nozomi-hiragi/wake-protocol/blob/main/spec/wake-protocol.md)
- [仮実装（TypeScript）](https://github.com/nozomi-hiragi/wake-protocol/tree/main/impl/ts)
