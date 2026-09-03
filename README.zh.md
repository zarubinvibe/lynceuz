# Lynceuz

自动、免费地从公开网站收集信息。做不到的时候，它会直说，而不是编一个出来。

[English](README.md) · [Русский](README.ru.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Stars](https://img.shields.io/github/stars/zarubinvibe/lynceuz?style=flat&color=C9A87A)](https://github.com/zarubinvibe/lynceuz/stargazers) [![Status](https://img.shields.io/badge/status-v0.1%20early-brightgreen.svg)](https://github.com/zarubinvibe/lynceuz) [![Olympuz](https://img.shields.io/badge/olympuz-family-B8D6EA.svg)](https://github.com/zarubinvibe/athena#olympuz-family)

<p align="center"><img src="docs/assets/pantheon/hero.png" alt="瞭望者林叩斯站在白色大理石柱旁，望向明亮的象牙色地平线" width="100%"></p>

<!-- owner-welcome:start -->

> 我常常需要大量和自己问题相关的信息。不是一页，是几百页。用手一页页找，要花好几天。那些替你做这件事的服务要收钱，而且从不告诉你文字是从哪儿来的。
>
> 我想要一个能自己去收集的东西：不花一分钱，还留下痕迹——网址在这里，时间在这里，文件的指纹在这里。这样一个月之后你可以自己核对，而不是听别人说。
>
> 做出来了。能用。
>
> — Filipp Zarubin

<!-- owner-welcome:end -->

## 目录

- [这是什么](#这是什么)
- [它解决什么问题](#它解决什么问题)
- [最大的优势](#最大的优势)
- [工作流程](#工作流程)
- [快速开始](#快速开始)
- [简单对比](#简单对比)
- [简单词汇](#简单词汇)
- [安全与隐私](#安全与隐私)
- [局限](#局限)
- [点亮星标与参与](#点亮星标与参与)

<!-- beginner-readme:start -->

## 这是什么

Lynceuz 是一个命令行程序。你给它一个网址，它把页面取回来，并在旁边存一张小卡片：从哪儿来的、什么时候取的、文件的指纹是什么。指纹的用处是：以后你能证明这段文字没有被人换过。名字来自阿尔戈号的瞭望者林叩斯，他能看穿大地与海水，并如实报告他看见的东西。

## 它解决什么问题

用手收集很慢。付费服务收你的钱，交回一个页面，却什么都不附上：从哪儿来的、几点取的、现在还是不是同一段文字。没有可核对的东西。

Lynceuz 每跑一次都留下凭据。一个月之后，你能说清是哪条路径给出的回应、在什么时候，并证明这个页面此后没有变过。

## 最大的优势

**最大的优势：** 它什么都不编：取到什么就交什么，取不到的地方直说。

**为什么这样更好：** 门关着的时候，Lynceuz 会指出是哪扇门。它不用猜测去填补空缺，也不会绕到付费的路子上，好让报告看起来体面一点。这个取舍很实在：结果更少，但每一个你都担得起。

## 工作流程

五个步骤，顺序固定。每一步要么把工作交给下一步，要么带着原因停下。

<!-- workflow-diagram:start -->

<p align="center"><img src="docs/assets/pantheon/takt-zh.png" alt="五块大理石板排成一行，每块刻着运行中的一步，一条蓝色水流把它们串起来，最后汇入封好印的证据箱" width="100%"></p>

<!-- workflow-diagram:end -->

| 阶段 | 会发生什么 |
|---|---|
| 1. 地址 | 先检查地址，然后才去取内容。 |
| 2. 阶梯 | 按顺序尝试免费路径，先试最省的那条。 |
| 3. 浏览器 | 只有当「人的路径」是唯一路径时才打开浏览器。 |
| 4. 证据 | 每次运行都会留下别人可以复核的东西。 |
| 5. 停下 | 安全的路都走完了，它就直说并停下。 |

### 第 1 步：检查地址

Lynceuz 先读地址。内网段、回环地址、链路本地地址和云元数据地址一律拒绝，任何想跳到这些地址的重定向也一样。接着它会完整读一遍 `robots.txt`，不是只看写着「禁止」的那几行。

**你会得到：** 一个公开的目标，或者在传输任何字节之前就拒绝。

### 第 2 步：走完免费阶梯

先发普通请求。如果页面靠 JavaScript 渲染，Lynceuz 就去找网站自己留下的门：`robots.txt` 里写明的站点地图、文档页本身、RSS 源、打印版本。每一级都会记录下来，成功和落空都记。

**你会得到：** 来自第一级真正给出回应的内容。

### 第 3 步：打开受限浏览器

大多数页面用不上它。如果某个网站只以对人的方式作答，浏览器就以一个独立的非特权账号运行，它的出站流量被包过滤规则拦住，只留一个回环端口。页面加载之前，探针会先验证这条规则是否真的生效。

**你会得到：** 一个渲染好的页面，或者一扇写明被哪条规则挡住的门。

### 第 4 步：写下证据

Lynceuz 会把收到的字节和一份 JSON 清单一起写下来：胜出的引擎、试过的每一级、网址、时间戳、内容的 SHA-256、花费，以及它提出的任何警告。花费那一行写着零，因为预算就是零。

**你会得到：** 一份产物和一份清单，可以直接交给别人。

### 第 5 步：诚实停下

被挡住的运行会返回一个带类型的拒绝，附上原因和已经试过的所有层级。不猜测，不凭记忆补齐，也不会悄悄打开付费路径去救那个数字。一个读得懂的拒绝，胜过一个不敢信的结果。

**你会得到：** 一个写明的原因，以及路走到头的确切位置。

## 快速开始

你只需要 Node 20 或更新的版本。安装时不会下载任何东西，因为本来就没有可下载的。

```bash
# без установки, прямо из GitHub:
npx github:zarubinvibe/lynceuz health

# или забрать себе:
git clone https://github.com/zarubinvibe/lynceuz.git
cd lynceuz
node scripts/onboard.mjs

# без git, одним архивом:
curl -L https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip -o lynceuz.zip

# дальше открывайте, чем привычнее:
claude          # Claude Code: скажите /lynceuz-setup, установка пройдет разговором
codex           # Codex CLI: те же правила уже лежат внутри проекта
code .          # VS Code: агент открывается внутри редактора
node src/lynceuz.mjs url 'https://example.org/' --json   # обычный терминал, без агента
```

不想 clone？`npx github:zarubinvibe/lynceuz health` 可以直接从 GitHub 运行，[ZIP 压缩包](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip)解压后离线也能用。任何一次首装，用对话的方式都更顺：在 Claude Code 里运行 `/lynceuz-setup`，它会一步步带着你走，动手之前先问你。

第一次做这件事？[上手引导](docs/ONBOARDING.zh.md) 会一步一步带你走完第一次运行，并写清楚每条命令之后你会看到什么。

**你会得到：** 一张表，显示哪些路径现在开着、哪些关着，以及你的第一张结果卡片。

## 简单对比

| 方案 | 这是什么 | 在哪里运行 | 带指纹的来源卡 | 会不会闯关着的门 | 诚实拒绝 | 价格 |
|---|---|---|---|---|---|---|
| **Lynceuz** | 从公开网页收集证据的命令行工具 | 在你自己的机器上 | 每一页都有 | 不闯，关着的门就让它关着 | 会，并说出理由 | 零 |
| 纯手工复制 | 浏览器加剪贴板 | 在你的浏览器里 | 没有 | 不闯 | 你自己判断 | 你的时间 |
| Firecrawl | 按量付费的页面采集 API | 在厂商云端 | 没有，只有内容 | 有时候，用它自己的通道 | 只给错误码，不给理由 | 订阅 |
| Apify、ScrapeGraphAI | 带现成脚本的采集平台 | 在厂商云端 | 没有 | 经常，用它自己的通道 | 取决于脚本 | 订阅加用量 |
| Playwright 或 Puppeteer | 你自己写的浏览器脚本 | 在你自己的机器上 | 自己写了才有 | 取决于你能坚持多久 | 你自己判断 | 你花在修脚本上的时间 |
| curl 和 jq | 一个普通终端 | 在你自己的机器上 | 没有 | 不闯 | 一个状态码，仅此而已 | 零 |
| Wayback Machine、archive.today | 公开的网页存档 | 在别人的服务器上 | 有快照日期，没有指纹 | 不闯 | 没有快照时就是空的 | 免费 |

名称归各自所有者。这张表描述的是用途，不是实测：别人的产品会变，这个页面不替它们做承诺。

## 简单词汇

| 词 | 简单解释 |
|---|---|
| Repository | 仓库：Git 保存并记录版本的项目文件夹 |
| Terminal | 终端：你输入命令的窗口 |
| Command | 命令：给电脑的一条指令 |
| Branch | 分支：不影响 `main` 的另一条修改线 |
| Pull Request | 合并请求：请别人审阅并接受你的修改 |
| Manifest | 清单：与内容并排保存的小 JSON，说明它从哪儿来 |
| SHA-256 | 文件的指纹：改动一个字节，指纹就变 |
| robots.txt | 网站用来告诉爬虫哪些欢迎、哪些不欢迎的文件 |
| Containment | 封禁：一条操作系统规则，阻止程序连接网络 |

## 安全与隐私

- 只针对公开目标。回环地址、内网段和云元数据地址一律拒绝，重定向也算。
- `robots.txt` 会被完整读取。`Disallow` 绝不绕过，用浏览器也不行。
- 绝不抓取搜索引擎的结果页。Google、Bing 及同类都不在范围内。
- 金钱预算为零，没有任何开关会悄悄打开付费路径。
- 没有遥测。关于你运行的一切都不会离开你的机器。
- 浏览器路径以一个独立的非特权账号运行，它的出站流量在包过滤层被拦住。

完整的模型，包括封禁规则如何安装与回滚，见 [SECURITY.md](SECURITY.md)。

## 局限

早期阶段。核心、路径阶梯和证据链已经完成，并由无需联网的测试覆盖。浏览器封禁已在 macOS 上得到验证，在其他系统上宁可关闭也不假装可用。命令界面还会变动。

- 封禁目前只在 macOS 上得到验证。在其他系统上，浏览器路径选择拒绝而不是猜测。
- 会拦你的站点还是会拦你。Lynceuz 会报告那扇关着的门，但不会去开它。
- 验证码只识别，不破解。运行会放慢或停下，由人来决定。
- 没有托管服务，也没有账号。要么在你自己的机器上跑，要么就不跑。

继续阅读：[上手指南](docs/ONBOARDING.zh.md)介绍第一次运行，[探索阶梯](docs/discovery-ladder.md)说明路径的排序，[访问策略](docs/access-policy.md)划出边界，[封禁验证](docs/wave2-containment-proof.md)记录浏览器规则是怎么测出来的。

## 点亮星标与参与

觉得有用？给 Lynceuz 点亮星标：[https://github.com/zarubinvibe/lynceuz](https://github.com/zarubinvibe/lynceuz)。这只要一秒，却决定别人能不能找到这个项目。

想改点什么？流程很短：先 fork 仓库，建一个分支 branch，提交 commit，推送 push，然后开一个 Pull Request。请不要直接向 `main` 推送，发布闸门会拒绝。

发现问题？到 [https://github.com/zarubinvibe/lynceuz/issues](https://github.com/zarubinvibe/lynceuz/issues) 开一个 issue，写清楚你运行了什么、发生了什么。

<!-- beginner-readme:end -->

<!-- pantheon-family:start -->
## Olympuz 家族

这是 [Olympuz 家族](https://github.com/zarubinvibe/athena#olympuz-family) 的公开项目之一。表格里的每一行都可以打开仓库，或者直接下载源码压缩包。

| 类型 | 名称 | 做什么 | 获取 |
|---|---|---|---|
| 项目 | Athena | 可携带的智能体操作系统：在新的 Mac 上重建 Claude 与 Codex 的工作环境。 | [仓库](https://github.com/zarubinvibe/athena) · [ZIP](https://github.com/zarubinvibe/athena/archive/refs/heads/main.zip) |
| 项目 | Helioz | 全天候的智能体工作传送带，带可验证的完成标记和按目标做出的夜间决策。 | [仓库](https://github.com/zarubinvibe/helioz) · [ZIP](https://github.com/zarubinvibe/helioz/archive/refs/heads/main.zip) |
| 项目 | Mnemazine | 本地优先的记忆系统：把原始材料变成可复用的、已核验的知识。 | [仓库](https://github.com/zarubinvibe/mnemazine) · [ZIP](https://github.com/zarubinvibe/mnemazine/archive/refs/heads/main.zip) |
| 项目 | Themiz | 面向俄罗斯诉讼的多智能体助手，本地识别扫描件，五位法学家组成合议审阅。 | [仓库](https://github.com/zarubinvibe/themiz) · [ZIP](https://github.com/zarubinvibe/themiz/archive/refs/heads/main.zip) |
| 项目 | Zeuz | 工作流工厂：把一个想法变成带规则、闸门、可观测性和回放的多智能体系统。 | [仓库](https://github.com/zarubinvibe/zeuz) · [ZIP](https://github.com/zarubinvibe/zeuz/archive/refs/heads/main.zip) |
| 项目 | Lynceuz | 以零成本收集公开网页证据；安全路径走完时，它会给出诚实的理由并停下。 | [仓库](https://github.com/zarubinvibe/lynceuz) · [ZIP](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip) |
<!-- pantheon-family:end -->

## 许可证

MIT。见 [LICENSE](LICENSE)。
