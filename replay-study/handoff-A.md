# A 组：普通构建和说明

这是**主持人内部的彩排版本**，候选只有自测授权，尚未批准对外发放。正式走查前，用实际批准的构建重新生成两组材料。A、B 两组给同一份构建、下面同一段说明，以及同一份 `participant.md`。A 不收 Atomium 回执。

> 请复核 “Atomium Native Draft v2” 的候选 `4d3b04b27bc0`。这是 Mac 命令行样例。构建文件名为 `app`，初始已存在 `Aster`，本轮先用同名创建草稿，再试提交；随后改成 `Birch` 并重新提交。以下命令在构建所在目录运行：
>
> ```bash
> ./app version
> shasum -a 256 ./app
> ./app Aster Aster save show submit show rename:Birch submit show
> ```
>
> 第二行应与候选标识 `4d3b04b27bc0` 的开头一致。第三行是一次有状态的演示，`show` 显示当时状态；在另一进程单独输入将从零开始。请按参与者任务交回实际观察，不必登录 AI。
