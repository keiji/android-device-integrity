# AGENTS.md

このリポジトリの AI エージェント向けガイド。対話・計画・完了報告は**日本語**で行うこと。

## 構成と主要コマンド（検証済み）

- `android/`: Android クライアント（Kotlin / Compose マルチモジュール）。`android/` で実行:
  ```bash
  ./gradlew assembleDebug testDebugUnitTest lintDebug
  ```
  初回ビルドは `android/AGENTS.md` の手順で SDK をセットアップし `android/local.properties` に `sdk.dir` を作成。JDK 21、compileSdk 36（`android/gradle/libs.versions.toml` が正）。
- `server/`: Python / Flask の独立アプリ 2 つ（`key_attestation/`、`play_integrity/`）。リポジトリルートで実行:
  ```bash
  pip install -r server/key_attestation/requirements.txt
  python -m unittest discover server/key_attestation/tests
  python -m unittest discover server/play_integrity/tests
  ```

## CI / API

- CI: `android_ci.yml`（android/** 変更時）、`server-test.yml`（対象サービスのみ）、`openapi_lint.yml`。Cloud Run デプロイは `cloud_run_deploy*.yml` の workflow_dispatch（手動）のみ。
- サーバー API はコードと `server/*/openapi.yaml` の両方を変更すること。エンドポイントは `server/play_integrity/api.py` が正（`/play-integrity/classic/v1/nonce` 等、README の旧パスに注意）。`PLAY_INTEGRITY_PACKAGE_NAME` 環境変数でパッケージ名を指定（デフォルト `dev.keiji.deviceintegrity`）。

## コード編集ルール

- **禁止コメント**: 作業メモ・変更経緯の注釈（`// Changed ...`、`# Added ...`、タスク範囲外の `TODO`/`FIXME`）、自明な処理の説明、`openapi.yaml` 内の注釈。コメントは意図が複雑な場合に限り簡潔に。
- 削除はコメントアウトで残さずシンプルに削除する（履歴は Git が管理）。変更履歴コメントも不要。

## スコープと Git 運用

- タスクスコープ外の変更（リファクタリング、Lint 警告修正、改善実装）は承認なしに行わない。「ついでに」は認めない。スコープ外の改善案はタスク完了後に独立した提案として提示する。
- Lint エラー修正はビルド失敗の原因である場合のみ、最小限の変更で許可。判断に迷う点は憶測で進めず質問する。
- issue につき PR は 1 つ。指定された単一ブランチでのみ作業し、ブランチ名を変更・切替しない。
- コミットメッセージは Conventional Commits に従い**英語**で記述。
- 「完了」報告は全仕様の実装・検証が済んだ場合のみ。事実のみを報告し、問題や不明点は隠さず直ちに伝える。

## 編集直後の自己レビュー

- 編集後、直ちに変更箇所（diff と前後数行）を目視確認し禁止コメントがないことを確認。複数ファイルは 1 つずつ確認する。コミット前に全変更ファイルを再確認。
