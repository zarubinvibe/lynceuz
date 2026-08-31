#!/usr/bin/env python3
"""Strict render-only Playwright helper. It is never launched without a proven sandbox."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys


MAX_INPUT_BYTES = 64 * 1024
MAX_DOM_BYTES = 5 * 1024 * 1024
MAX_WAIT_MS = 5_000
MAX_SCROLL_STEPS = 10
MAX_SCROLL_Y = 2_000
SAFE_KEYS = {
    "version", "id", "operation", "url", "output_path", "wait_ms",
    "scroll_steps", "scroll_y", "proxy",
}


def response(request_id: str, ok: bool, **fields: object) -> None:
    value = {"version": 1, "id": request_id, "ok": ok, **fields}
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")


def contained_output(raw_path: object) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("invalid output path")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        raise ValueError("output path must be absolute")
    root = Path.cwd().resolve(strict=True)
    parent = candidate.parent.resolve(strict=True)
    if parent != root and root not in parent.parents:
        raise ValueError("output escaped scratch")
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("output already exists")
    return candidate


def validate(request: object) -> dict[str, object]:
    if not isinstance(request, dict) or set(request) - SAFE_KEYS:
        raise ValueError("invalid request")
    request_id = request.get("id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise ValueError("invalid request id")
    if request.get("version") != 1:
        raise ValueError("invalid version")
    if request.get("operation") != "render":
        return {"id": request_id, "unsupported": True}
    url = request.get("url")
    if not isinstance(url, str) or len(url) > 8_192 or not url.startswith(("http://", "https://")):
        raise ValueError("invalid URL")
    wait_ms = request.get("wait_ms", 0)
    scroll_steps = request.get("scroll_steps", 0)
    scroll_y = request.get("scroll_y", 0)
    if not isinstance(wait_ms, int) or not 0 <= wait_ms <= MAX_WAIT_MS:
        raise ValueError("invalid wait")
    if not isinstance(scroll_steps, int) or not 0 <= scroll_steps <= MAX_SCROLL_STEPS:
        raise ValueError("invalid scroll steps")
    if not isinstance(scroll_y, int) or not 0 <= scroll_y <= MAX_SCROLL_Y:
        raise ValueError("invalid scroll distance")
    proxy = request.get("proxy")
    if not isinstance(proxy, dict) or set(proxy) != {"server", "username", "password"}:
        raise ValueError("invalid proxy")
    if not all(isinstance(proxy[key], str) and proxy[key] for key in proxy):
        raise ValueError("invalid proxy")
    return {**request, "output": contained_output(request.get("output_path"))}


async def render(request: dict[str, object]) -> dict[str, object]:
    from playwright.async_api import async_playwright

    browser = None
    context = None
    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(
                headless=True,
                proxy=request["proxy"],
                args=["--disable-quic"],
            )
            context = await browser.new_context(
                accept_downloads=False,
                service_workers="block",
                permissions=[],
            )

            async def route_handler(route: object, playwright_request: object) -> None:
                method = playwright_request.method
                url = playwright_request.url
                if method not in {"GET", "HEAD"} or not url.startswith(("http://", "https://")):
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", route_handler)
            await context.route_web_socket("**/*", lambda route: route.close())
            page = await context.new_page()
            page.on("download", lambda download: asyncio.create_task(download.cancel()))
            page.on("popup", lambda popup: asyncio.create_task(popup.close()))
            await page.goto(
                str(request["url"]),
                wait_until="domcontentloaded",
                timeout=15_000,
            )
            wait_ms = int(request["wait_ms"])
            if wait_ms:
                await page.wait_for_timeout(wait_ms)
            for _ in range(int(request["scroll_steps"])):
                await page.mouse.wheel(0, int(request["scroll_y"]))
            dom = (await page.content()).encode("utf-8")
            if not dom or len(dom) > MAX_DOM_BYTES:
                raise ValueError("rendered DOM size is invalid")
            output = request["output"]
            temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(dom)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, output)
            finally:
                if temporary.exists():
                    temporary.unlink()
            return {
                "output_path": str(output),
                "source_hash": "sha256:" + hashlib.sha256(dom).hexdigest(),
                "bytes": len(dom),
                "final_url": page.url,
            }
        finally:
            if context is not None:
                await context.close()
            if browser is not None:
                await browser.close()


def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES or sys.stdin.buffer.read(1):
        response("invalid", False, code="invalid_request")
        return 0
    try:
        request = json.loads(raw)
        validated = validate(request)
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        request_id = request.get("id", "invalid") if isinstance(locals().get("request"), dict) else "invalid"
        response(str(request_id), False, code="invalid_request")
        return 0
    if validated.get("unsupported"):
        response(str(validated["id"]), False, code="unsupported_operation")
        return 0
    try:
        payload = asyncio.run(render(validated))
        response(str(validated["id"]), True, payload=payload)
    except Exception:
        response(str(validated["id"]), False, code="render_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
