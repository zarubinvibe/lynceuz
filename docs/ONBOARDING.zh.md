<!-- 语言：[English](ONBOARDING.md) · [Русский](ONBOARDING.ru.md) · 简体中文（本文件） -->

# 上手指南 —— 与 Lynceuz 的第一个小时

<p align="center"><img src="assets/pantheon/doc-onboarding.png" alt="瞭望者 Lynceus 抬手遮住视线，站在封好印的证据箱旁，旁边是免费路径的梯子和空白的地址石" width="100%"></p>

这份指南带第一次使用的人，从一个空文件夹走到一次可验证的抓取。你输入命令，看清
屏幕上出现了什么，再进行下一步。这里的每一步都不会安装软件包，也不会改动系统设置。
如果某一步亮起红灯，就先停在那里把它解决，别跳过——被忽略的红灯，之后照样会冒出来。

其他语言：[English](ONBOARDING.md) · [Русский](ONBOARDING.ru.md)。

1. **确认 Node 版本。** Lynceuz 需要 Node 20 或更高版本，并且运行时零依赖，所以这是
   唯一真正必须满足的条件。

   ```bash
   node --version
   ```

   你应当看到类似 `v24.15.0` 的输出。如果数字小于 20，或者终端提示
   `command not found`，请先安装 Node 20 以上版本，再回到这里。

2. **获取代码。** 把仓库克隆到你选定的文件夹。

   ```bash
   git clone https://github.com/zarubinvibe/lynceuz.git
   ```

   Git 会显示进度，并以 `done.` 结束。把 `OWNER` 换成托管你这份副本的账号。

3. **进入文件夹。** 之后的每条命令都默认你已经在里面。

   ```bash
   cd lynceuz
   ```

   现在命令行提示符以 `lynceuz` 结尾。我们不会再离开这个目录。

4. **有意跳过安装。** 项目没有运行时依赖，因此没有东西需要下载。如果你出于习惯运行
   `npm install`，它只会回复 `up to date`，什么也不添加。这个空结果正是项目的承诺，
   而不是出错。

5. **运行就绪探测。** 这是对你的机器当下能做什么的一次诚实快照。

   ```bash
   node scripts/onboard.mjs
   ```

   你会得到一份简短报告：Node 版本、平台、`0 runtime dependencies`、有多少源码模块
   通过了解析，以及哪些能力已就绪或被关闭。当一切就位时，最后一行会显示
   `Ready: mandatory checks are green.`。

6. **把同一份快照当作数据。** 当你需要机器可读的格式——用于脚本、日志或问题报告——
   就要一份 JSON。

   ```bash
   node scripts/onboard.mjs --json
   ```

   它会打印一个对象，包含 `"kind": "lynceuz_onboarding"` 和
   `"runtime_dependencies": 0`。只要任一必需检查是红的，命令就会以非零码退出，所以
   可以放心地用它来把关流水线。

7. **让脚本自检。** 在信任这份探测之前，先让它跑一遍自己的断言。

   ```bash
   node scripts/onboard.mjs --selftest
   ```

   健康的副本会回答 `onboard selftest: ok`，并以 `0` 退出。

8. **确认源码可以解析。** 这是项目自带的检查：Node 逐个读取每个核心模块，不发起任何
   网络操作。

   ```bash
   npm run check
   ```

   没有输出且干净退出，说明所有源码完好。若出现某个文件名加错误，则表示副本已损坏或
   不兼容。

9. **问 Lynceuz 哪些路线是通的。** health 快照会列出每个引擎，以及它是 `ready`、
   `disabled`，还是被安全闸门挡在后面。

   ```bash
   node src/lynceuz.mjs health --json
   ```

   预期 `native` 是 `ready`，而浏览器引擎处于 `unavailable_security_gate`。这是全新
   副本的正常状态，不是故障。

10. **抓取你的第一个真实页面。** 选一个不靠 JavaScript 就能显示正文的公开网址，作为
    单个带引号的参数传入。

    ```bash
    node src/lynceuz.mjs url 'https://example.org/' --json
    ```

    成功时，你会得到结果路径、一份清单（manifest）和一个 SHA-256。如果站点拒绝，你会
    收到带确切原因的、类型化的 `blocked`——绝不会有编造的文字。

11. **在磁盘上找到证据。** 每次运行都会把产物和清单写进 `.lynceuz/`，这个目录不会进入
    git。

    ```bash
    ls .lynceuz
    ```

    清单记录了引擎、尝试过程、网址、时间、哈希和各种警告——这些就是你日后可以出示的
    凭据。

12. **用 `lynceuz-update` 保持最新。** 想要最新版本时，运行 `lynceuz-update` 技能。它会
    先给你看差异，只接受快进（fast-forward），重新跑一遍检查，并且绝不动你在
    `.lynceuz/` 里的结果或本地设置。

## 浏览器路线（可选，仅限 macOS）

浏览器引擎会执行不受信任的页面代码，因此在机器主人亲手安装隔离（containment）之前，
它们一直保持关闭。在 macOS 上，你可以自己审阅并运行
`ops/macos/install-containment.sh`；在 Linux 和 Windows 上目前还没有受支持的浏览器
路线——请改用 native 路线或公开导出。运行 `node scripts/onboard.mjs --json` 会准确列出
浏览器路线所需的条件。

## 点亮星标，再回馈一个改动

如果 Lynceuz 为你省了时间，请[给仓库点亮星标](https://github.com/zarubinvibe/lynceuz)——这能帮更多人找到一个诚实、零成本的抓取器。

已经装好了，想要最新版本？在 Claude Code 里运行 `/lynceuz-update`。它会先告诉你哪些地方变了，
再动手；只做 fast-forward 拉取；不碰你的设置和已保存的结果；结束后重新跑一遍项目自带的检查。

如果你改进了什么，路径很短：

**fork -> 分支 -> commit -> push -> Pull Request。**

```bash
# 先在 GitHub 上 fork，然后：
git checkout -b my-improvement
git commit -am "docs: 打磨上手指南的措辞"
git push -u origin my-improvement
# 在 GitHub 上从你的 fork 发起 Pull Request
```

改动尽量小，并说明你在改动前后看到了什么。清晰、具体的 Pull Request 合并得最快。
