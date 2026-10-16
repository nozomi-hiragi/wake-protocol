# @wake-protocol/core

WAKE Protocol の本体です。KX（鍵交換）、SM（セッション管理）、ET（暗号化トランスポート）、TA（操作の認否）、KR（鍵更新）のメッセージの組み立てと検証、鍵の導出、エラーの定義を提供します。

> [!WARNING]
> これは仕様の動作確認のための仮実装です。本番では使わないでください。

## インストール

```sh
# npm
npm install @wake-protocol/core

# JSR（npm など）
npx jsr add @wake-protocol/core

# JSR（Deno）
deno add jsr:@wake-protocol/core
```

## 関連リンク

- [WAKE Protocol 仕様書](https://github.com/nozomi-hiragi/wake-protocol/blob/main/spec/wake-protocol.md)
- [仮実装（TypeScript）](https://github.com/nozomi-hiragi/wake-protocol/tree/main/impl/ts)
