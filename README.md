# アセンブラによる SHA1 の実装

* SHA1 は脆弱性があるため新規に利用されるものではないが、WebSocket アプリケーションを作成する途中で SHA1 に触れる機会があった。
* たまたま運良く、intel の中の人がアセンブラで SHA1 を実装したコードを公開していたのを発見した。
* 以前から SSE命令等を利用したいと思っていたため、アセンブラをいじるには良い機会であった。

# ファイルについて

* SHA1.txt が、intel の中の人が書いたオリジナルコード  
https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1  

* SHA1.asm は、SHA1.txt を分かりやすくするために書き換えたコード  
（分かりやすくしたため、実行速度が犠牲になっている）

* main.cpp は、SHA1.asm を呼び出すだけの確認用コード
* memo.txt は、単なるメモ

# その他

* memo.txt の更新を手伝ってくれると有り難いです！temp2019@knmail.jpn.org に連絡をお願いします。
* さらなる高速化など気付いたことがあれば、よければ是非教えて下さい。（Skylake 以降に実装された SHA1拡張命令を利用することは除きます）
