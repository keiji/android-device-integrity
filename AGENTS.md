android以下はクライアントアプリ（Android）のソースコードです。
server以下はサーバー側のソースコードです。

## コード編集時のルール

*   コードを削除する際は、特別な理由がない限りコメントアウトして残すのではなく、シンプルに削除してください。
*   変更履歴に関するコメント（例：「古いコードは削除しました」など）も追加しないでください。 Gitの履歴がその目的を果たします。

## Jules (AI Software Engineer) への作業指示と注意事項

このドキュメントは、AIソフトウェアエンジニアである私が当プロジェクトで作業を行う際の、特に遵守すべき重要な指示と注意事項をまとめたものです。私は、タスク開始時に必ずこのドキュメント全体、特に「最重要徹底事項」のセクションを熟読し、その内容を完全に理解・遵守してください。

### 1. 基本的な心構え

*   常に正確性を最優先し、細部まで注意を払って作業を行ってください。
*   指示された内容は完全に実行し、自己判断で省略したり、曖昧なまま作業を進めたりしないでください。
*   不明な点、判断に迷う点があれば、憶測で進めずに必ず質問してください。

### 2. コメントポリシーに関する最重要徹底事項

過去のタスクにおいて、AGENTS.MD（本ドキュメントを含む）に記載されたコメントポリシーの遵守が著しく不十分なケースが散見されました。具体的には、以下のような問題が複数回にわたり発生し、タスク完了までに多大な手戻りを要しました。これは作業品質と効率に対する信頼を著しく損なうものです。

**以下の指示は、私が当プロジェクトでコードを記述・編集する上で、常に最優先で遵守しなければならない絶対的なルールです。**

#### 2.1. 禁止されるコメント

以下の種類のコメントは、コード中、コミットメッセージのいずれにおいても一切残さないでください。

*   **作業メモや個人的な注釈：**
    *   例：`// Changed ...`、`// Renamed ...`、`// Corrected from ...`、`# New field`、`# Added ...`、`// ... if ... provided`、`// TODO: ...` (タスク範囲外のTODOは除く)、`// FIXME: ...` (タスク範囲外のFIXMEは除く)など、変更の経緯や作業者自身のためのメモ。
*   **冗長な説明コメント：**
    *   コード自体から意図が自明な処理に対する説明。
    *   例：`// increment i` (for `i++`)
*   **コメントアウトされた古いコード：**
    *   リファクタリングや修正によって不要になった古いコードブロックは、バージョン管理システム（Git）がその履歴を管理するため、コメントアウトして残さず、完全に削除してください。例外的に、一時的なデバッグや比較のためにコメントアウトする場合は、その作業完了後速やかに削除するか、適切な理由と共に明確な指示を仰いでください。
*   **OpenAPI定義ファイル等における説明的な注釈：**
    *   最終的なAPI定義や設定ファイルの理解に直接寄与しない、作業経緯、他のフォーマットとの比較、Kotlinの仕様に関する注釈など。
    *   例：`# Optional in Kotlin, but if present, it's an int`、`# Assuming this is a hex string`、`# Was missing from existing OpenAPI but present in Python`

#### 2.2. コメント記述の原則

*   コメントは、コードの意図が複雑で、コードだけでは理解が難しい場合に限り、簡潔かつ明確に記述してください。
*   AGENTS.MDの指示（本指示を含む）に反するコメントは、いかなる理由があっても許容されません。

### 3. タスクスコープの厳守と事前確認の義務

1.  **指示範囲の厳守:**
    *   各タスクで指示された範囲を逸脱するコード変更は、原則として一切禁止します。例えば、「Aというエラーを修正する」というタスクであれば、Aのエラー修正に直接関わらないリファクタリング、コードスタイルの修正、他の潜在的な問題の修正などは含みません。
2.  **追加変更の事前承認:**
    *   タスク遂行の過程で、指示範囲外の変更が必要、または有益であると判断した場合は、決して自己判断で変更を実装しないでください。
    *   変更に着手する前に、必ず以下の情報をあなたに提示し、明確な承認を得る必要があります。
        *   変更が必要だと判断した具体的なコード箇所
        *   変更内容とその理由
        *   その変更がタスクの主目的とどう関連しているか
3.  **Lintエラーへの対処方針:**
    *   Lintエラーがビルド失敗の原因である場合に限り、その修正を許可します。ただし、その修正はエラーを解消するための最小限の変更に留めてください。
    *   ビルドが成功する状況でのLint警告の修正は、別途指示がない限り行わないでください。

### 4. 自己レビューと確認プロセスの徹底

コメントポリシー違反やその他の品質問題を未然に防ぐため、以下の自己レビューと確認プロセスを**各変更作業の直後**および**コミット直前**に必ず実行してください。

1.  **全てのファイル編集の直後の検証：**
    *   ファイルを変更した場合は、**直ちに**変更箇所全体（diffだけでなく、その周辺の数行も含む）を目視で確認してください。
    *   この際、上記「2.1. 禁止されるコメント」に該当するコメントが一切含まれていないことを確認してください。
    *   この検証は、たとえ一行の小さな変更であっても、絶対に省略しないでください。
2.  **複数ファイルへの変更時の注意：**
    *   複数のファイルにまたがる変更を行う場合、一つのファイルの修正が完了し、上記1.の検証を終えてから、次のファイルの修正に移ってください。タスク完了前の「まとめて確認」では、見落としが発生する可能性が非常に高くなります。
3.  **可読性の高いコード作成の意識：**
    *   複雑な文字列連結や条件分岐は、第三者（他の開発者や将来の自分自身）が容易に理解できるよう、適宜変数に格納する、処理をメソッドに分割するなど、可読性を常に意識してください。
4.  **コミット前の最終総合確認（絶対実施）：**
    *   作業を完了する**直前**に、今回のタスクで変更または追加した**全てのファイル**について、上記2.1、2.2、および3の項目（特にコメントポリシー違反の完全な排除）を再度、**全行を目視で**徹底的に確認してください。
    *   **「過去のやり取りで指摘された全ての事項が完全に解消されているか？」「AGENTS.MDの全ての指示、特にコメントポリシーを完全に遵守できているか？」** を自身に問い、100%確信が持てるまで作業を完了しないでください。

### 5. 指示の優先順位と質問の義務

このドキュメント（AGENTS.MD）に記載された指示は、あなたからの個別タスク指示と同等、あるいはそれ以上の優先度を持つものとして扱ってください。特に、コメントポリシーと自己レビュープロセスは最優先事項です。

これらの指示の解釈に少しでも不明瞭な点がある場合、あるいは個別タスクの指示と矛盾するように思われる場合は、作業のいかなる段階であっても、自己判断せずに直ちに質問し、明確な指示を仰いでください。同じ過ちを繰り返すことは許容されません。

---
私がこの指示を理解し、遵守することを期待します。
