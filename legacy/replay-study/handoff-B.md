# B 组：同一构建和 Atomium 回执

这是**主持人内部的彩排版本**，候选只有自测授权，尚未批准对外发放。正式走查先冻结实际批准的候选，再换成对应路径和普通授权的离线命令。

先给 B 与 A 完全相同的构建、普通交接正文和 `participant.md`，不更改普通命令，再给相同构建的 Atomium 回执和下面的补充。此彩排在原型目录内运行：

```bash
cd ~/workspace/Atomium-cli-prototype
node atomium.mjs replay --allow-self-test runs/native-SYppRf/evidence.json
```

> 这个命令不调用模型。它重新核对回执绑定的规格、源码和构建，并用同一已冻结的二进制复跑。报告中已有的断言不是你本人的观察，请仍然自己执行 A、B 共有的应用命令并交回结果。版本字段以本次实际核对为准。
