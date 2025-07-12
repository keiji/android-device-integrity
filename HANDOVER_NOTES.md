## タスク: Android Key Attestation 証明書のパース処理デバッグ (pyasn1)

**現状の問題点:**
特定のAndroid Key Attestation証明書（テストケース `test_parse_keiji_device_integrity_beta_cert` で使用）の `KeyDescription` エクステンションを `pyasn1.der_decoder.decode()` でパースする際に問題が発生しています。
- スキーマ (`asn1Spec`) を指定してデコードを試みても、`pyasn1` が指定されたスキーマを適用せず、汎用的な `pyasn1.type.univ.Sequence` オブジェクトを返します（期待されるのは指定したスキーマクラスのインスタンス）。
- この結果、デコードされたオブジェクトのフィールド解釈がズレてしまい（例: `attestationVersion` が `4` ではなく `400` となる）、テストが失敗します。
- テストログには `DEBUG_PRINT` による詳細な出力が含まれており、`der_decoder.decode()` が返すオブジェクトの型や `prettyPrint()` の内容から、この誤解釈が確認できます。
- ログには `Failed to decode KeyDescription ASN.1 sequence with pyasn1: Not single-octet Boolean payload` というエラーも別の（不正な入力値をテストする）テストケースで表示されており、`pyasn1` のASN.1解釈に何らかの根本的な問題がある可能性が示唆されています。しかし、問題の証明書では、このエラーが直接的な失敗原因というよりは、スキーマが適用されないことが主因と考えられます。

**直近の試みと状態:**
- `attestation_parser.py` 内の `parse_key_description` 関数で、`KeyDescription` の構造を定義した `KeyDescriptionTopLevelSchema` や、さらに単純化した `ExtremelySimpleKeyDescriptionSchema` を `asn1Spec` として `der_decoder.decode()` に渡しました。
- しかし、いずれの場合も `pyasn1` は指定されたスキーマを適用せず、汎用 `univ.Sequence` を返しました（`DEBUG_PRINT` ログで確認済み）。
- 現在のコードは、`parse_key_description` が `ExtremelySimpleKeyDescriptionSchema` を使ってデコードを試みる状態で、多数の `print()` 文によるデバッグログ出力が有効になっています。
- テストケース `test_parse_keiji_device_integrity_beta_cert` は実行可能な状態（スキップされていません）です。
- `parse_authorization_list` のエラーハンドリングは厳格化済みです。
- `RootOfTrust` のパースには部分的なスキーマ (`RootOfTrustAsn1`) が適用されています（ただし、今回の問題の主要因ではない可能性が高いです）。

**次の担当者への依頼事項:**
1.  **`pyasn1` のスキーマ適用問題の根本原因調査:**
    *   なぜ `pyasn1.der_decoder.decode(key_desc_bytes, asn1Spec=...)` が、提供された `asn1Spec` を無視する（あるいは適用できないと判断してフォールバックする）のかを特定してください。
    *   考えられる原因：
        *   `key_desc_bytes` の内容が、スキーマ（たとえ単純なものでも）の最初の数バイトと致命的に不整合であるため、`pyasn1` がスキーマ適用を即座に断念している。
        *   使用している `pyasn1` のバージョンや環境に特有の問題。
        *   スキーマクラスの定義方法や `componentType` の指定に、まだ見落としている微妙な誤りがある。
    *   対策：
        *   問題の `key_desc_bytes` と `ExtremelySimpleKeyDescriptionSchema` (または `KeyDescriptionTopLevelSchema`) を使った最小限の独立したPythonスクリプトを作成し、`pyasn1` の挙動を隔離して詳細に検証してください。
        *   `pyasn1` のドキュメントやコミュニティで、同様の問題やスキーマ適用の詳細な条件について調査してください。
        *   可能であれば、`pyasn1` の内部動作をステップ実行するなどして、スキーマがどのように扱われているか追跡してください。

2.  **スキーマの段階的構築と検証:**
    *   上記調査でスキーマ適用が機能するようになったら、まず `ExtremelySimpleKeyDescriptionSchema` （`attestationVersion` のみ）で `attestationVersion` が正しく `4` として取得できることを確認します。
    *   次に、`KeyDescriptionTopLevelSchema` にフィールドを一つずつ追加（`attestationSecurityLevel`, `keymasterVersion`...の順に）し、その都度テストを実行して、どのフィールド定義を追加した時点で問題が発生するか（または解決するか）を特定します。
    *   `softwareEnforced` および `hardwareEnforced` については、最終的には詳細な `AuthorizationListSchema` を定義する必要がありますが、まずはトップレベルのフィールドが正しくパースされることを優先してください（これらは当面 `univ.Any` または空の `univ.Sequence` のままでも可）。

3.  **`AuthorizationList` のパース改善:**
    *   トップレベルの `KeyDescription` がスキーマで正しくパースされるようになった後、`softwareEnforced` と `hardwareEnforced` (これらは `AuthorizationList` 型) のパースに移ります。
    *   現在の `parse_authorization_list` は `.items()` を使った非標準的なイテレーションを行っています。これを、スキーマベースのアクセス（もし `AuthorizationList` のスキーマを定義する場合）または、より標準的な `pyasn1.univ.Sequence` のコンポーネントアクセスメソッド（インデックスアクセスや `getComponentByPosition`）に置き換えることを検討してください。
    *   `TAG_ATTESTATION_APPLICATION_ID` や `TAG_ROOT_OF_TRUST` (これは既に一部スキーマ対応済み) などの個々のタグのパースも、この文脈で見直してください。

4.  **テストの成功とクリーンアップ:**
    *   最終的に `test_parse_keiji_device_integrity_beta_cert` がすべてのフィールドを正しく検証し、パスすることを目指します。
    *   すべてのデバッグ用 `print()` 文を削除してください。ロガーによるエラー/警告出力は適切に残してください。

**関連ファイル:**
- `server/key_attestation/attestation_parser.py`
- `server/key_attestation/tests/test_attestation_parser.py`

**テスト実行コマンド:**
`python -m unittest discover server/key_attestation/tests`

**直近のテスト実行時のログの要点:**
Keiji証明書のテストケース(`test_parse_keiji_device_integrity_beta_cert`)において、`attestation_parser.py` 内の `DEBUG_PRINT` ログにより以下の点が確認されています：
- `der_decoder.decode(key_desc_bytes, asn1Spec=ExtremelySimpleKeyDescriptionSchema())` を呼び出しても、返されるオブジェクトの型は `<class 'pyasn1.type.univ.Sequence'>` であり、`ExtremelySimpleKeyDescriptionSchema` のインスタンスではありません。
- その結果、オブジェクトの `prettyPrint()` は `field-0=400` のような誤った内容を示します。
- テストは最終的に `ValueError: Malformed or unexpected KeyDescription structure: Failed to parse tag 709 in AuthorizationList: AttestationApplicationId not a valid SEQUENCE.` で失敗します。これは、トップレベルの誤ったデコード結果を引き継いで `softwareEnforced` の処理に進み、そこでエラーが発生するためです。

この情報が次のステップに役立つことを願っています。
