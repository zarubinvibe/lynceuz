# Бесплатные скраперы для проектов

Проверено: 2026-08-26, MSK.

Цель этой справки: собрать бесплатный стек веб-сбора, который можно потом объяснить одному инструменту. Не как список библиотек, а как рабочий роутер: какая задача пришла, какой движок брать, где лимит денег, где лимит права, где риск зависания.

## Короткий вывод

Бесплатность бывает двух типов:

1. Бесплатно по деньгам, но на своей машине. Это `curl`, `fetch`, `BeautifulSoup`, `selectolax`, `trafilatura`, `Playwright`, `Crawl4AI`, `Scrapy`, `Crawlee`, `Scrapling`, `browser-use`.
2. Бесплатный облачный лимит. Это `Firecrawl` и `ScrapeGraphAI`. Удобно для быстрых задач, но есть кредиты и rate limits.

Для наших проектов нормальный порядок такой:

```text
API/RSS/sitemap
-> curl/fetch + parser
-> Crawl4AI
-> Playwright
-> browser-use
-> Firecrawl free credits
-> ScrapeGraphAI free credits
-> ручная проверка / останов
```

Если задача из старого Helioz-плана прямо требует `$0 строго: Firecrawl -> ScrapeGraphAI -> WebSearch/WebFetch`, то порядок можно оставить, но с бюджетным предохранителем: Firecrawl и ScrapeGraphAI использовать только в free tier, без платных апгрейдов, без регистрации новых аккаунтов и без прокси за деньги.

## Базовые правила

- Сначала ищем официальный API, RSS, sitemap, JSON-LD, `robots.txt`, публичный CSV, GitHub API, npm API. Скрейпинг только если нормального входа нет.
- Не логинимся в чужие аккаунты, не обходим paywall, CAPTCHA и запреты ToS без отдельного решения.
- Для повторяемого сбора делаем rate limit, cache, user-agent, retry, дедупликацию URL.
- Для LLM-задач сначала получаем чистый Markdown/JSON локально, потом отдаём модели малый фрагмент.
- Для юридических/финансовых фактов храним source URL, дату доступа, hash/cache, статус проверки.
- Прокси, residential proxies, CAPTCHA-solving и платные scraping API считаем не `$0`.

## Роутер по задачам

| Задача | Первый выбор | Почему |
|---|---|---|
| Одна статичная HTML-страница | `curl`/`fetch` + `BeautifulSoup`/`cheerio`/`selectolax` | Самое дешёвое, быстрое, мало движущихся частей |
| Чистый текст статьи | `trafilatura` | Хорошо режет навигацию, отдаёт content-first текст |
| Документация/RAG/много страниц | `Crawl4AI` | Markdown, links, deep crawl, JS при нужде |
| JS-сайт, lazy loading, формы | `Playwright` | Реальный браузер, ожидания, клики, скриншоты |
| Агент должен сам ходить по сайту | `browser-use` | LLM управляет браузером, полезно для разведки |
| Production crawling на Python | `Scrapy` | Очереди, пайплайны, retry, масштаб |
| Production crawling на Node/Python | `Crawlee` | Готовые crawlers, Playwright/Puppeteer/Cheerio, storage |
| Сайт часто меняет DOM | `Scrapling` | Адаптивные селекторы, переобнаружение элементов |
| Быстрый URL -> Markdown без настройки | `Firecrawl` free tier | Удобный облачный API, но кредиты |
| Prompt -> structured JSON | `ScrapeGraphAI` free tier или OSS локально | Удобно для нерегулярных страниц |

## Инструменты

### 1. `curl`, native `fetch`, `urllib`, `requests`

Статус: бесплатно, локально.

Для чего:
- проверка живости ссылок;
- HEAD/GET;
- RSS/Atom/XML/JSON;
- sitemap;
- простые страницы без JavaScript.

Не брать:
- если контент появляется только после JS;
- если нужна навигация, cookies, infinite scroll;
- если структура грязная и нужна чистка статьи.

Минимальный шаблон:

```bash
curl -sL -A 'Mozilla/5.0' 'https://example.com' > page.html
```

Для наших проектов: первый слой почти всегда. Особенно для проверки ссылок в `blog`, `helioz`, `mnemazine`, `themis`.

### 2. `BeautifulSoup` / `cheerio`

Статус: бесплатно, open-source.

Для чего:
- достать заголовки, ссылки, таблицы, карточки;
- быстро написать parser под один сайт;
- обработать HTML, который уже получили через `curl` или браузер.

Python: `BeautifulSoup`.
Node: `cheerio`.

Плюсы:
- простой код;
- дешево по CPU;
- легко тестировать фикстурами.

Минусы:
- не рендерит JavaScript;
- ломается при редизайне;
- сам не crawler, только parser.

Источник: https://beautiful-soup-4.readthedocs.io/en/latest/

### 3. `selectolax`

Статус: бесплатно, open-source parser.

Для чего:
- быстрый HTML parsing в Python;
- большие пачки страниц;
- когда `BeautifulSoup` медленный.

Плюсы:
- быстрый backend на Lexbor;
- удобен для простых CSS-селекторов.

Минусы:
- parser, не crawler;
- для сложной логики всё равно нужен свой слой загрузки, retry и storage.

Для наших проектов: хороший кандидат для массовых проверок ссылок, карточек, таблиц, каталогов.

### 4. `trafilatura`

Статус: бесплатно, open-source.

Для чего:
- извлечь основной текст статьи;
- убрать меню, футер, рекламу;
- получить Markdown/text для LLM.

Плюсы:
- меньше мусора в контексте;
- хорошо подходит под Mnemazine и research.

Минусы:
- короткие документы и нестандартные страницы могут извлечься криво;
- не браузер, JS сам не исполнит.

Для наших проектов: слой "web page -> clean text" перед Мнемозиной.

### 5. `Crawl4AI`

Статус: бесплатно при self-host/local, Apache-2.0.

Для чего:
- LLM-friendly crawling;
- чистый Markdown;
- structured JSON;
- deep crawl;
- JS-render через Playwright;
- RAG/documentation ingestion.

Плюсы:
- сделан именно под AI/RAG;
- есть CLI, Python API, Docker/FastAPI server;
- умеет Markdown, links, media, screenshots, CSS/XPath/Regex extraction;
- можно держать локально без API-кредитов.

Минусы:
- браузерный режим тяжелее, чем `curl`;
- Docker/API server требует security: auth, firewall, SSRF-защита;
- для protected sites всё равно нужны rate limits и иногда прокси.

Для наших проектов:
- `mnemazine`: основной бесплатный кандидат вместо облачного Firecrawl;
- `themis`: публичные правовые страницы, карточки, clean Markdown;
- `blog/helioz`: сбор источников, каналов, RSS-страниц, документации;
- `todocups/market research`: каталоги и цены, если нет API.

Источники:
- https://docs.crawl4ai.com/
- https://github.com/unclecode/crawl4ai
- лицензия Apache-2.0: https://github.com/unclecode/crawl4ai/blob/main/LICENSE

### 6. `Playwright`

Статус: бесплатно, open-source browser automation.

Для чего:
- открыть Chromium/Firefox/WebKit;
- дождаться JS;
- кликнуть, заполнить форму;
- снять скриншот;
- достать DOM после рендера;
- проверить визуальное состояние.

Плюсы:
- реальный браузер;
- стабильный API;
- подходит и для тестов, и для scraping.

Минусы:
- тяжелее и медленнее HTTP parser;
- сайты могут детектить headless automation;
- нужен аккуратный sandbox, если используются профили/cookies.

Для наших проектов:
- `themis`: судебные сайты, где HTML появляется после JS;
- `mnemazine`: визуальная проверка источников;
- `helioz/blog`: проверка каналов, страниц, RSS discovery;
- frontend QA.

Источник: https://playwright.dev/

### 7. `browser-use`

Статус: open-source, бесплатно как библиотека; LLM-провайдер может стоить денег.

Для чего:
- агент сам ходит по сайту;
- задача описана словами, а не CSS-селекторами;
- надо исследовать неизвестный интерфейс;
- надо пройти несколько экранов.

Плюсы:
- быстрее прототипировать разведку;
- хорошо для неструктурированных web tasks;
- можно подключать к локальным или платным LLM.

Минусы:
- не для bulk crawling;
- дороже по времени и токенам;
- риск безопасности: агент с браузером может видеть сессии и аккаунты;
- нужен sandbox/read-only режим.

Для наших проектов: точечная разведка, не массовый сбор. Особенно если сайт надо "понять глазами".

Источник: https://github.com/browser-use/browser-use

### 8. `Scrapy`

Статус: бесплатно, open-source, BSD.

Для чего:
- устойчивые production crawlers;
- большие очереди URL;
- retry, throttling, pipelines;
- структурированные выгрузки.

Плюсы:
- зрелый Python framework;
- много документации;
- подходит для долгих регулярных сборов.

Минусы:
- требует писать spider;
- JavaScript не решает сам, нужен Playwright/Splash/другой слой;
- больше boilerplate, чем у `Crawl4AI` для one-shot AI задач.

Для наших проектов: если сбор становится регулярным продуктовым пайплайном, а не разовой разведкой.

Источники:
- https://docs.scrapy.org/
- https://www.scrapy.org/
- https://github.com/scrapy/scrapy

### 9. `Crawlee`

Статус: бесплатно, Apache-2.0, JS/TS и Python.

Для чего:
- crawler с готовой очередью, storage, session management;
- HTTP + Cheerio/JSDOM + Playwright/Puppeteer;
- RAG/data extraction.

Плюсы:
- сильный batteries-included слой;
- хорошо для Node-проектов;
- можно начать с простого crawler и перейти к браузерному.

Минусы:
- больше зависимостей;
- для совсем простой задачи избыточен;
- cloud Apify отдельно платный, но сама библиотека бесплатная.

Для наших проектов: Node-краулеры в `helioz/blog`, когда `curl` уже мало, а Scrapy тащить не хочется.

Источники:
- https://crawlee.dev/
- https://github.com/apify/crawlee

### 10. `Scrapling`

Статус: бесплатно, BSD-3-Clause.

Для чего:
- адаптивный scraping;
- страницы, где CSS-селекторы ломаются после редизайна;
- anti-bot aware fetching;
- экспорт JSON/CSV/XML.

Плюсы:
- parser учится переобнаруживать элементы после изменений сайта;
- есть разные fetcher modes;
- полезен для каталогов и страниц с нестабильной версткой.

Минусы:
- менее стандартный выбор, чем Scrapy/Crawlee/Playwright;
- надо проверять на конкретном сайте;
- anti-bot режимы не означают право обходить запреты.

Для наших проектов: мониторинг конкурентов, каталогов, карточек, где верстка плавает.

Источники:
- https://github.com/D4Vinci/Scrapling
- https://scrapling.readthedocs.io/en/latest/

### 11. `Firecrawl`

Статус: облако с free tier, self-host open-source под AGPL-3.0.

Текущая бесплатность:
- официальная pricing page показывает 1000 free credits/month;
- scrape/crawl/map/monitor обычно стоят credits per page;
- Search и Interact имеют отдельную тарификацию;
- self-host бесплатен по лицензии, но требует свою инфраструктуру.

Для чего:
- быстро получить Markdown по URL;
- map/crawl сайта без настройки crawler;
- agent-friendly web data API;
- когда важнее скорость результата, чем контроль.

Плюсы:
- самый удобный быстрый слой;
- хороший формат для AI agents;
- можно использовать CLI/MCP;
- self-host возможен.

Минусы:
- free credits конечны;
- self-host тяжелее: Docker Compose, API, workers, Playwright, Redis/queues/storage;
- AGPL-3.0 важен для закрытых продуктов и сетевого использования;
- cloud-only возможности могут отличаться от self-host.

Для наших проектов:
- хороший первый облачный слой для разовой разведки;
- не основной engine для регулярного `$0` bulk;
- перед каждым batch проверять credits.

Команды из локальной заметки:

```bash
firecrawl --status
firecrawl scrape <url> --only-main-content
firecrawl map <url>
firecrawl search "<query>" --limit 3
firecrawl crawl <url> --limit 20
```

Источники:
- https://www.firecrawl.dev/pricing
- https://www.firecrawl.dev/
- https://docs.firecrawl.dev/contributing/self-host
- https://github.com/firecrawl/firecrawl

### 12. `ScrapeGraphAI`

Статус: cloud free tier + open-source library.

Текущая бесплатность:
- pricing page: Free Plan, 500 API credits, one-time;
- 10 requests/min;
- 1 monitor;
- 1 concurrent crawl;
- open-source library можно запускать самому.

Для чего:
- prompt-based extraction;
- "достань вот эти поля" из страницы;
- structured JSON;
- нерегулярные страницы, где CSS schema писать долго.

Плюсы:
- удобный prompt -> JSON подход;
- есть cloud API и OSS core;
- хорошо для прототипа.

Минусы:
- cloud free credits быстро кончатся;
- LLM extraction не всегда детерминирована;
- для регулярного production лучше CSS/XPath schema + tests.

Команды из локальной заметки:

```bash
sgai validate --json
sgai scrape <url> --html-mode reader --json
sgai extract <url> -p "<prompt>" --json
sgai search "<query>" --num-results 3 -p "<prompt>" --json
sgai crawl <url> --max-pages 20 --max-depth 2 -f markdown --json
```

Источники:
- https://scrapegraphai.com/pricing
- https://scrapegraphai.com/
- https://github.com/ScrapeGraphAI/Scrapegraph-ai
- https://docs.scrapegraphai.com/contribute/opensource

### 13. `Colly`

Статус: бесплатно, Go, Apache-2.0.

Для чего:
- быстрые Go crawlers;
- structured extraction;
- небольшие бинарники;
- проекты, где Go уже основной стек.

Плюсы:
- быстрый и лёгкий;
- коммерческое использование бесплатно;
- чистый crawler API.

Минусы:
- не наш основной стек;
- меньше пользы для LLM/RAG из коробки, чем Crawl4AI.

Источник: https://go-colly.org/

### 14. `Katana`

Статус: кандидат, требует отдельной свежей проверки перед внедрением.

Для чего:
- быстрый crawling/recon;
- standard/headless режимы;
- discovery URL, XHR, формы.

Плюсы:
- может быть полезен как быстрый URL-discovery слой перед Crawl4AI/Playwright.

Минусы:
- больше security/recon профиль, чем content extraction;
- перед включением в общий инструмент надо проверить лицензию, релизы, CLI flags, output contract.

Для наших проектов: пока "проверить позже", не core.

## Архитектура одного инструмента

Рабочее имя: `free-scrape`.

Идея: одна команда принимает URL или query, сама выбирает бесплатный backend и пишет воспроизводимый artifact.

```bash
free-scrape url https://example.com --goal markdown --budget 0
free-scrape crawl https://docs.example.com --max-pages 20 --goal rag
free-scrape extract https://example.com/products --schema products.json
free-scrape search "site:example.com RSS feed" --limit 5
```

### Decision engine

1. Если URL похож на RSS/Atom/XML/JSON/sitemap - брать native fetch.
2. Если HTML статичный и задача простая - fetch + parser.
3. Если нужна чистая статья - trafilatura.
4. Если много страниц и нужен Markdown/RAG - Crawl4AI.
5. Если нужен JS/render/click/scroll - Playwright.
6. Если нужен человекоподобный исследовательский проход - browser-use в sandbox.
7. Если локальные движки не справились и разрешены free credits - Firecrawl.
8. Если надо prompt -> JSON и есть free credits - ScrapeGraphAI.
9. Если всё упало - report, не придумывать данные.

### Output contract

Каждый запуск должен писать:

```json
{
  "url": "https://example.com",
  "engine": "crawl4ai",
  "cost_money": 0,
  "credits_used": 0,
  "fetched_at": "2026-08-26T12:15:40Z",
  "status": "ok",
  "source_hash": "...",
  "content_path": "out/example.md",
  "evidence": ["https://example.com/source"],
  "warnings": []
}
```

### Storage

```text
.scrape/
  cache/
    raw/
    rendered/
    markdown/
  runs/
    2026-08-26T121540Z.json
  out/
    page.md
    data.json
```

### Обязательные предохранители

- `--budget 0` по умолчанию.
- Cloud engines выключены, пока явно не указан `--allow-free-cloud`.
- Перед Firecrawl/ScrapeGraphAI проверять remaining credits.
- `max_pages`, `max_depth`, `timeout`, `concurrency` обязательны.
- Никаких paid proxies.
- Никаких CAPTCHA solvers.
- Никаких login-backed страниц без отдельного разрешения.
- Для каждого факта: source URL или `unverified`.

## Матрица для наших проектов

### Mnemazine

Главный стек:

```text
URL -> Crawl4AI/trafilatura -> Markdown -> hash cache -> atomization -> vault
```

Firecrawl держать как быстрый fallback на малые задачи. ScrapeGraphAI брать только когда нужна prompt extraction и локально слишком долго писать schema.

Улучшение: добавить watchdog для deep-worker. Если дочерний worker не создал `out.json` за N минут, писать partial-report, retry один раз, потом продолжать следующий файл.

### Helioz / Blog

Главный стек:

```text
RSS/API -> curl/fetch -> parser -> link verifier
```

Для каналов YouTube лучше не scrape HTML, а использовать RSS:

```text
https://www.youtube.com/feeds/videos.xml?channel_id=<ID>
```

Для pages/discovery: Crawl4AI или Playwright. Firecrawl только на маленькую разведку.

### Themis / Legal

Главный стек:

```text
official source -> Playwright/Crawl4AI -> structured evidence -> manual/legal verification
```

Не выдумывать реквизиты. Каждый судебный акт, дата, номер дела и сторона должны иметь первоисточник.

### Competitor / Market Research

Главный стек:

```text
sitemap/API -> Crawlee/Scrapy -> parser schema -> periodic diff
```

Если JS-heavy магазин: Playwright или Crawl4AI browser mode. Если верстка часто меняется: Scrapling проверить на пилоте.

## Что не считать бесплатным

- Bright Data, Oxylabs, ScrapingBee, ScraperAPI и аналоги после trial.
- Residential/mobile proxies.
- CAPTCHA solving.
- Cloud browser infra, если free trial закончился.
- LLM extraction через paid model, если задача могла быть решена CSS/XPath/Regex.
- Firecrawl/ScrapeGraphAI сверх free credits.

## Рекомендуемый дефолт

Для будущего единого инструмента я бы зафиксировал такой default:

```text
budget: 0
network: public-only
auth: none
engine_order:
  - native_fetch
  - trafilatura_or_parser
  - crawl4ai
  - playwright
  - browser_use_sandbox
  - firecrawl_free
  - scrapegraphai_free
stop_on:
  - paid_required
  - login_required
  - captcha_required
  - source_unverifiable
```

Это честный `$0`: сначала свой компьютер, потом бесплатные облачные кредиты, потом останов. Данные не выдумывать, платный обход не включать исподтишка.

## Источники

- Firecrawl pricing: https://www.firecrawl.dev/pricing
- Firecrawl docs self-host: https://docs.firecrawl.dev/contributing/self-host
- Firecrawl GitHub: https://github.com/firecrawl/firecrawl
- ScrapeGraphAI pricing: https://scrapegraphai.com/pricing
- ScrapeGraphAI open-source: https://github.com/ScrapeGraphAI/Scrapegraph-ai
- Crawl4AI docs: https://docs.crawl4ai.com/
- Crawl4AI GitHub: https://github.com/unclecode/crawl4ai
- Playwright docs: https://playwright.dev/
- Scrapy docs: https://docs.scrapy.org/
- Scrapy site: https://www.scrapy.org/
- Crawlee docs: https://crawlee.dev/
- Crawlee GitHub: https://github.com/apify/crawlee
- Scrapling docs: https://scrapling.readthedocs.io/en/latest/
- Scrapling GitHub: https://github.com/D4Vinci/Scrapling
- browser-use GitHub: https://github.com/browser-use/browser-use
- BeautifulSoup docs: https://beautiful-soup-4.readthedocs.io/en/latest/
- Colly docs: https://go-colly.org/

