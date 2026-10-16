# @wake-protocol/client

WAKE Protocol のクライアント（KX、SM、KR、TA、ET）です。ブラウザと Node.js で動きます。セッションの保存先として、メモリと IndexedDB（タブ間で共有）を用意しています。

> [!WARNING]
> これは仕様の動作確認のための仮実装です。本番では使わないでください。

## インストール

```sh
# npm
npm install @wake-protocol/client

# JSR（npm など）
npx jsr add @wake-protocol/client

# JSR（Deno）
deno add jsr:@wake-protocol/client
```

## 関連リンク

- [WAKE Protocol 仕様書](https://github.com/nozomi-hiragi/wake-protocol/blob/main/spec/wake-protocol.md)
- [仮実装（TypeScript）](https://github.com/nozomi-hiragi/wake-protocol/tree/main/impl/ts)
