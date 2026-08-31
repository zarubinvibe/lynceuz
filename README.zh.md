# Lynceuz

以零金钱成本收集公开网页证据，或者给出诚实的理由并停下。

[English](README.md) · [Русский](README.ru.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Stars](https://img.shields.io/github/stars/zarubinvibe/lynceuz?style=flat&color=C9A87A)](https://github.com/zarubinvibe/lynceuz/stargazers) [![Status](https://img.shields.io/badge/status-v0.1-early-brightgreen.svg)](https://github.com/zarubinvibe/lynceuz) [![Olympuz](https://img.shields.io/badge/olympuz-family-B8D6EA.svg)](https://github.com/zarubinvibe/athena#olympuz-family)

<p align="center"><img src="docs/assets/pantheon/hero.png" alt="瞭望者林叩斯站在白色大理石柱旁，望向明亮的象牙色地平线" width="100%"></p>

<!-- owner-welcome:start -->

> 我做 Lynceuz，是因为一个悄悄换路线、悄悄花钱、或者干脆编出结果的抓取工具，比没有结果更糟。我想要一个小工具，它待在公开的地面上，并留下别人可以核验的证据。
>
> 它交给你的是它真正取到的字节、一份清单和一个哈希。当访问被拒绝，或者安全的路都走完了，它会直说并停下。
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

Lynceuz 是一个命令行工具：抓取公开网页，并把自己做过的事记下来。你给它一个网址。它挑一条免费路径，保存内容，并在旁边保存一份清单，里面有网址、时间、SHA-256 和花费。林叩斯是阿尔戈号的瞭望者，能看穿大地与海水，并如实报告他看见的东西。

## 它解决什么问题

大多数抓取工具很难被信任第二次。它们要么退回到付费方案，要么把页面丢给你，却没有任何办法判断它从哪儿来。Lynceuz 把凭据留着。一个月后你依然能说清是哪个引擎回应的、在几点，并证明那些字节没有变过。

## 最大的优势

**最大的优势：** 一个读得懂的拒绝，而不是一个无法核验的结果。

**为什么这样更好：** 门关着的时候，Lynceuz 会指出是哪扇门。它不用猜测去填补空缺，也不会伸手去够付费路径，好让数字看着体面一些。这就是全部的取舍：结果更少，但每一个都站得住。

## 工作流程

五个步骤，顺序固定。每一步要么把工作交给下一步，要么带着原因停下。

<!-- workflow-diagram:start -->

```text
  ┌────────┐   ┌────────┐   ┌────────┐
  │ 地址   │ ▶ │ 阶梯   │ ▶ │ 浏览器 │
  └────────┘   └────────┘   └────────┘
       ▼
  ┌────────┐   ┌────────┐
  │ 证据   │ ▶ │ 停下   │
  └────────┘   └────────┘
```

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
node --version
git clone https://github.com/zarubinvibe/lynceuz.git
cd lynceuz
node scripts/onboard.mjs
node src/lynceuz.mjs health
node src/lynceuz.mjs url 'https://example.org/' --json
```

不想 clone？`npx github:zarubinvibe/lynceuz health` 可以直接从 GitHub 运行，[ZIP 压缩包](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip)解压后离线也能用。任何一次首装，用对话的方式都更顺：在 Claude Code 里运行 `/lynceuz-setup`，它会一步步带着你走，动手之前先问你。

第一次做这件事？[上手引导](docs/ONBOARDING.zh.md) 会一步一步带你走完第一次运行，并写清楚每条命令之后你会看到什么。

**你会得到：** 一张健康表，显示哪些引擎开着，以及你的第一份清单。

## 简单对比

| 方案 | 适合什么时候 | 你会得到 | 代价 |
|---|---|---|---|
| Lynceuz | 你需要证明这次抓取确实照你说的方式发生 | 内容、清单、哈希、花费，以及试过的每一条路 | 页面更少：关着的门就是关着的 |
| 付费抓取 API | 你要快速拿到大量页面，账单不成问题 | 高吞吐量和别人的代理 | 每月费用，以及字节来源只能听他们说 |
| 自己写的浏览器自动化脚本 | 任务只针对一个你很熟的站点 | 对页面的完全控制 | 维护归你，而且通常不留证据 |
| 人工复制粘贴 | 一个页面，只做一次 | 你看见的就是那样 | 事后无从复核，也没法扩大规模 |

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
| 项目 | Themis | 面向俄罗斯诉讼的多智能体助手，本地识别扫描件，五位法学家组成合议审阅。 | [仓库](https://github.com/zarubinvibe/themis) · [ZIP](https://github.com/zarubinvibe/themis/archive/refs/heads/main.zip) |
| 项目 | Zeuz | 工作流工厂：把一个想法变成带规则、闸门、可观测性和回放的多智能体系统。 | [仓库](https://github.com/zarubinvibe/zeuz) · [ZIP](https://github.com/zarubinvibe/zeuz/archive/refs/heads/main.zip) |
| 项目 | Lynceuz | 以零成本收集公开网页证据；安全路径走完时，它会给出诚实的理由并停下。 | [仓库](https://github.com/zarubinvibe/lynceuz) · [ZIP](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip) |
<!-- pantheon-family:end -->

## 许可证

MIT。见 [LICENSE](LICENSE)。
