# 開発の進め方

仕様書・仮実装・テストベクターを変更するときの運用です。仕様への質問や攻撃の指摘は [Issues](../../issues)、設計の議論は [Discussions](../../discussions)、脆弱性は [SECURITY.md](SECURITY.md) の方法で非公開に報告してください。

## リポジトリの構成

| パス | 内容 |
|---|---|
| `spec/wake-protocol.md` | 仕様書。実装と食い違ったときは仕様書が正 |
| `spec/test-vectors/` | §16 のテストベクター。`impl/ts` から生成するので、手で編集しない |
| `impl/ts/` | TypeScript の仮実装。設計方針は [impl/ts/DESIGN.md](impl/ts/DESIGN.md)、仕様の曖昧点は [impl/ts/SPEC-NOTES.md](impl/ts/SPEC-NOTES.md) |
| `CHANGELOG.md` | 版ごとの変更 |
| `AGENTS.md` | コーディングエージェント向けの指示 |

## ブランチ

`main` に直接コミットせず、作業ごとにブランチを作って PR でマージします。

名前は [Conventional Branch](https://conventionalbranch.org/)（v1.1.0）に倣って `<種類>/<内容>` にします。

| 種類 | 使う場面 |
|---|---|
| `feat/` | 機能の追加 |
| `fix/` | 不具合の修正 |
| `refactor/` | 構造の整理（API の整理を含む） |
| `spec/` | 仕様書の改訂 |
| `docs/` | ドキュメントだけの変更 |
| `chore/` | 依存の更新、設定、CI など |

`refactor/`、`spec/`、`docs/` は、このリポジトリで追加した種類です（Conventional Branch は、種類を追加して文書化することを認めています）。

- `<内容>` は、何をするかが分かる2〜4語の英語にします。小文字の英数字とハイフンだけを使います。
- 作った人やツールの名前（`<ユーザー名>/`、`claude/`、`codex/` など）は付けません。Conventional Branch には AI エージェント名の接頭辞も任意で用意されていますが、このリポジトリでは使いません。1つの作業を人や複数のエージェントで引き継ぐことが多く（Codex で始めて Claude で続けるなど）、作った道具の名前では中身が分からないためです。誰が関わったかは、コミットの作者と `Co-Authored-By` で残します。
- 例: `refactor/ts-package-split`、`fix/et-header-limit`、`spec/ta-content-profile`、`docs/agents-guide`

## コミット

- 1つのコミットには、1つのまとまった変更を入れます。**どのコミットの時点でも**型チェックとテストが通り、テストベクターを再生成しても差分が出ない状態にします。レビューと `git bisect` のためです。
  - 例: パッケージ分割は「汎用パッケージの追加」→「core の作り直し」→「依存の検査」の3つに分けました。
- 生成物（`spec/test-vectors/`）は、生成元の変更と同じコミットに入れます。
- メッセージは英語にします。件名は命令形で短く（`Add …`、`Fix …`、`Move …`）、本文には空行を挟んで、何をなぜ変えたかを書きます（72文字程度で折り返し、箇条書き可）。
- AI エージェントが書いたコミットには、`Co-Authored-By:` を付けます。
- プロジェクト全体で共有する設定（`.vscode/settings.json` のスペルチェックの単語など）はコミットします。個人の環境の設定はコミットしません。

## プルリクエスト

- タイトルは日本語で、変更の内容を一言で書きます（例: `仮実装 M1: 暗号コアとテストベクター`）。
- 本文は次の形にします。
  - **Before**: 変更前の状態
  - **After**: 変更後の状態。主な変更を箇条書きで
  - **How**: どう変えて、どう確かめたか。確認に使うコマンドも書く
- `main` へは squash マージします。件名には `(#番号)` が付きます。

## 変更の確認

```sh
cd impl/ts
npm ci
npm run typecheck
npm test                              # 依存の検査、すべてのパッケージのテスト
npm run vectors                       # spec/test-vectors/*.json を再生成
git status --short ../../spec         # 意図した変更がなければ空
```

## CHANGELOG

- 未リリースの節（例: `## v0.5.0（未リリース）`）に、日本語で1項目ずつ追記します。
- 破壊的変更は「〜の破壊的変更:」で始め、旧名と新名、移行のしかたを書きます。
- 仕様書の変更点は、仕様書の §0 にもまとめます。

## 依存ライブラリの追加

採用の条件（ライセンス、監査、依存の少なさ、仕様との厳密な一致、バージョンの固定）は [impl/ts/DESIGN.md](impl/ts/DESIGN.md#5-外部ライブラリ) にまとめています。条件を満たすことを PR に書いてください。

## リリース（npm / JSR）

### バンプ手順

以下のコマンドは `impl/ts` で実行します。

1. 6 つの公開パッケージ（`core/bytes`、`core/codec`、`core/crypto`、`core/protocol`、`client`、`server`）の `package.json` と `jsr.json` の `"version"` を新しいバージョンに書き換える
2. すべてのワークスペース（vectors / demo を含む）の `package.json` 内の公開パッケージへの内部依存と、各 `jsr.json` の `imports` 内の `jsr:@wake-protocol/*@…` を同じ完全固定のバージョンに揃える。vectors / demo 自身のバージョンは `0.0.0` のままにする
3. `npm install` を実行して `package-lock.json` を更新する
4. `node scripts/check-version.ts` を実行して整合性を確認する
5. CHANGELOG.md の未リリース節の見出しを更新する（例: `## v0.6.0（未リリース）` → `## v0.6.0 (YYYY-MM-DD)`。日付は公開日）
6. タグを打って push する（例: `impl/ts/v0.6.0`）

### タグ名の形式

`impl/ts/vX.Y.Z` — Go モジュール方式に倣い、実装ごとのパスを接頭辞にします（将来 `impl/go/v*` なども同じ形式で管理できます）。

### CI が行うこと（`.github/workflows/ts-ci.yml`）

pull_request と main へのプッシュで、`impl/ts/**`、`spec/**`、CI ワークフロー自身に変更があると起動します。Node 22 で実行し、e2e は含めません。

- `npm ci` → `npm run typecheck` → `npm test` → `npm run vectors` → `spec/` の差分チェック → `npm run check-pack` → JSR の dry-run（`npx jsr@0.14.3 publish --dry-run`。手元で未コミットの変更があるときは `--allow-dirty` を付ける）

### 公開ワークフロー（`.github/workflows/ts-publish.yml`）

`impl/ts/v*` タグの push で起動します。環境名は `npm-jsr`（GitHub Environments）、Node は 24、npm は 11.5.1 以降を使います。

- 同じ確認を行い、タグのバージョンとパッケージバージョンを照合してから公開します
- npm: trusted publisher（OIDC）で公開し、provenance を付けます。`NPM_TOKEN` があれば、trusted publisher が未設定のパッケージ（初回）はトークンで公開します。すでに公開されたバージョンはスキップします。`0.6.0` のような通常のバージョンを `latest` dist-tag で公開し、`-alpha` は付けません
- JSR: OIDC で公開。JSR はすでに公開済みのバージョンをスキップします

1.0 未満の GitHub Release は、既存の v0.4.0 / v0.5.0 と同じく **Pre-release** にします。これは npm の dist-tag とは別の設定です。

### 初回のセットアップ

最初のタグを push する前に、一度だけ行います。

1. **GitHub**: `npm-jsr` 環境を作成します（必要なら Required reviewers を設定して、公開の前に承認を求めます）
2. **npm**: `wake-protocol` org を作成し、公開できる granular access token を `NPM_TOKEN` として `npm-jsr` 環境のシークレットに登録します。npm の trusted publisher は既存のパッケージにしか設定できないため、初回だけトークンで公開します
3. **JSR**: `@wake-protocol` スコープと 6 パッケージを作成し、各パッケージの設定で GitHub リポジトリ `nozomi-hiragi/wake-protocol` をリンクします（[JSR の手順](https://jsr.io/docs/publishing-packages#publishing-from-github-actions)）
4. タグを push して公開します
5. 公開後、npmjs.com の各パッケージで trusted publisher を設定し（リポジトリ `nozomi-hiragi/wake-protocol`、ワークフロー `ts-publish.yml`、環境 `npm-jsr`。[npm の手順](https://docs.npmjs.com/trusted-publishers/)）、Allowed actions で `npm publish` による直接の公開も許可してから（2026-09-03 以降に作る設定は、既定では `npm stage publish` しか許可されません）、`NPM_TOKEN` を削除してトークンも失効させます。以後は OIDC だけで公開します
