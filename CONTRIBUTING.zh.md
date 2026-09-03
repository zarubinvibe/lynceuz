# 参与贡献

<p align="center"><img src="docs/assets/pantheon/doc-contributing.png" alt="大理石桌上放着空白的证据石板，一条蓝色水流从它们通向封好印的箱子，桌边立着一架免费路径的梯子" width="100%"></p>

谢谢你来看。Lynceuz 故意做得很小，所以新代码的门槛主要落在证据上：一处改动要能被证明，而且不能扩大这个工具被允许够到的范围。

## 动手写代码之前

先读 [AGENTS.md](AGENTS.md)。不变量都写在那里，破坏其中任何一条的合并请求都会被关掉，代码写得再好也一样。简短版本：花费为零、只访问公开目标、运行时不加新依赖、宁可诚实拒绝也不编造结果。

## 开发

```bash
git clone https://github.com/zarubinvibe/lynceuz.git
cd lynceuz
node scripts/onboard.mjs --selftest   # 工具自己检查自己
npm test                              # 全套测试，不需要联网
npm run check                         # 检查 src/ 下的语法
```

`npm test` 必须以零失败、零跳过结束。被跳过的测试等同于失败：它什么都证明不了，还把原因藏了起来。

## 一个好的合并请求长什么样

- 只做一件事，并在正文里用大白话写清楚。
- 一个在你改动之前失败、改动之后通过的测试。新的网络行为如果没有对抗性测试，不予接受。
- 不在 `package.json` 里加新依赖。如果你认为实在避不开，请先开 issue，说清楚它换来了什么。
- 不动已有的测试。如果某个测试是错的，请在合并请求里说明理由，而不是悄悄改写它。

## 流程

```text
fork -> 分支 -> commit -> push -> Pull Request
```

提交信息使用 `类型: 描述`：`feat`、`fix`、`refactor`、`docs`、`test`、`chore`。

## 发现问题往哪里说

缺陷和疑问去 [Issues](https://github.com/zarubinvibe/lynceuz/issues)。可被利用的问题走 [SECURITY.zh.md](SECURITY.zh.md)，不要开公开 issue。
