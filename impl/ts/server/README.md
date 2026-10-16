# @wake-protocol/server

WAKE Protocol のサーバー（KX、SM、KR、TA、ET）です。Web フレームワークに依存せず、`Request` を受け取って `Response` を返します。WebAuthn の assertion の検証も含みます。

> [!WARNING]
> これは仕様の動作確認のための仮実装です。本番では使わないでください。

## インストール

```sh
# npm
npm install @wake-protocol/server

# JSR（npm など）
npx jsr add @wake-protocol/server

# JSR（Deno）
deno add jsr:@wake-protocol/server
```

## 関連リンク

- [WAKE Protocol 仕様書](https://github.com/nozomi-hiragi/wake-protocol/blob/main/spec/wake-protocol.md)
- [仮実装（TypeScript）](https://github.com/nozomi-hiragi/wake-protocol/tree/main/impl/ts)
