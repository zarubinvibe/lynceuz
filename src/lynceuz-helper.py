#!/usr/bin/env python3
"""Deterministic, networkless transforms over files already stored by Lynceuz."""

from __future__ import annotations

import socket
import sys


class NetworkDenied(RuntimeError):
    pass


class InputHashMismatch(RuntimeError):
    pass


class HelperBoundaryError(RuntimeError):
    pass


def install_network_tripwire() -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise NetworkDenied("network access is disabled")

    class DeniedSocket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            denied()

    socket.socket = DeniedSocket  # type: ignore[assignment]
    socket.create_connection = denied  # type: ignore[assignment]
    socket.getaddrinfo = denied  # type: ignore[assignment]
    socket.gethostbyname = denied  # type: ignore[assignment]
    socket.gethostbyname_ex = denied  # type: ignore[assignment]
    socket.gethostbyaddr = denied  # type: ignore[assignment]


install_network_tripwire()

try:
    from bs4 import BeautifulSoup, NavigableString, Tag, __version__ as BS4_VERSION
except Exception:  # optional capability: absence is reported, not fatal to core
    BeautifulSoup = None  # type: ignore[assignment]
    NavigableString = None  # type: ignore[assignment]
    Tag = None  # type: ignore[assignment]
    BS4_VERSION = None

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit


MAX_REQUEST_BYTES = 128 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
OPS = {"self_check", "parse_html", "extract_schema"}
SPACE = re.compile(r"[ \t\f\v]+")
BLANKS = re.compile(r"\n{3,}")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def response(request_id: str, ok: bool, **fields: Any) -> dict[str, Any]:
    return {"version": 1, "id": request_id, "ok": ok, **fields}


def failure(request_id: str, code: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {"code": code}
    if details is not None:
        fields["details"] = details
    return response(request_id, False, **fields)


def emit(payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write(data + "\n")
    sys.stdout.flush()


def self_check(request_id: str) -> dict[str, Any]:
    if BeautifulSoup is None:
        return failure(request_id, "dependency_unavailable", {"parser": "beautifulsoup4"})
    return response(
        request_id,
        True,
        payload={
            "helper_version": "1",
            "network_tripwire": True,
            "parser": {"name": "beautifulsoup4", "version": BS4_VERSION},
            "python": sys.version.split()[0],
            "isolated": bool(sys.flags.isolated),
        },
    )


def normalized_url(value: str | None, base_url: str) -> str | None:
    if not value or len(value) > 4096:
        return None
    try:
        split = urlsplit(urljoin(base_url, value.strip()))
    except ValueError:
        return None
    if split.scheme not in {"http", "https"} or not split.hostname:
        return None
    if split.username or split.password:
        return None
    return urlunsplit((split.scheme, split.netloc, split.path or "/", split.query, ""))


def clean_text(value: str) -> str:
    lines = [SPACE.sub(" ", line).strip() for line in value.replace("\r", "\n").split("\n")]
    return BLANKS.sub("\n\n", "\n".join(line for line in lines if line)).strip()


def visible_text(node: Any) -> str:
    return clean_text(node.get_text("\n", strip=True))


def inline_markdown(node: Any, base_url: str) -> str:
    output: list[str] = []
    for child in node.children:
        if NavigableString is not None and isinstance(child, NavigableString):
            output.append(SPACE.sub(" ", str(child)))
            continue
        if Tag is None or not isinstance(child, Tag):
            continue
        name = child.name.lower()
        if name in {"script", "style", "template", "noscript"}:
            continue
        text = inline_markdown(child, base_url).strip()
        if name == "a":
            target = normalized_url(child.get("href"), base_url)
            output.append(f"[{text}]({target})" if text and target else text)
        elif name in {"strong", "b"} and text:
            output.append(f"**{text}**")
        elif name in {"em", "i"} and text:
            output.append(f"*{text}*")
        elif name == "code" and text:
            output.append(f"`{text}`")
        elif name == "br":
            output.append("\n")
        else:
            output.append(text)
    return SPACE.sub(" ", "".join(output)).strip()


def markdown(node: Any, base_url: str) -> str:
    blocks: list[str] = []
    for child in node.descendants:
        if Tag is None or not isinstance(child, Tag):
            continue
        name = child.name.lower()
        if name in {"script", "style", "template", "noscript"}:
            continue
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            text = inline_markdown(child, base_url)
            if text:
                blocks.append(f"{'#' * int(name[1])} {text}")
        elif name in {"p", "blockquote"}:
            text = inline_markdown(child, base_url)
            if text:
                blocks.append(f"> {text}" if name == "blockquote" else text)
        elif name == "li":
            text = inline_markdown(child, base_url)
            if text:
                blocks.append(f"- {text}")
    if not blocks:
        text = visible_text(node)
        if text:
            blocks.append(text)
    return "\n\n".join(blocks).strip()


def json_ld_documents(soup: Any) -> list[Any]:
    documents: list[Any] = []
    for tag in soup.find_all("script"):
        media_type = str(tag.get("type", "")).split(";", 1)[0].strip().lower()
        if media_type != "application/ld+json":
            continue
        raw = tag.string if tag.string is not None else tag.get_text()
        if not raw or len(raw) > MAX_INPUT_BYTES:
            continue
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(value, (dict, list)):
            documents.append(value)
    return documents


def parsed_html(raw: bytes, base_url: str) -> tuple[Any, dict[str, Any]]:
    if BeautifulSoup is None:
        raise RuntimeError("dependency_unavailable")
    soup = BeautifulSoup(raw.decode("utf-8", errors="replace"), "html.parser")
    json_ld = json_ld_documents(soup)

    title = clean_text(soup.title.get_text(" ", strip=True)) if soup.title else ""
    canonical_url = None
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical is not None:
        canonical_url = normalized_url(canonical.get("href"), base_url)

    metadata: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("itemprop")
        content = tag.get("content")
        if isinstance(key, str) and isinstance(content, str) and len(metadata) < 128:
            metadata[key.strip().lower()] = clean_text(content)[:4096]

    alternatives: dict[tuple[str, str], dict[str, str]] = {}
    for tag in soup.find_all("link"):
        rel_values = tag.get("rel") or []
        if isinstance(rel_values, str):
            rel_values = rel_values.split()
        if "alternate" not in {str(value).lower() for value in rel_values}:
            continue
        target = normalized_url(tag.get("href"), base_url)
        media_type = str(tag.get("type") or "text/html").strip().lower()
        if target:
            alternatives[(media_type, target)] = {"type": media_type, "url": target}

    links = {
        target
        for tag in soup.find_all("a")
        if (target := normalized_url(tag.get("href"), base_url)) is not None
    }
    for tag in soup.find_all(["script", "style", "template", "noscript"]):
        tag.decompose()
    main = soup.find("main") or soup.find("article") or soup.body or soup
    result = {
        "title": title,
        "canonical_candidate": canonical_url,
        "text": visible_text(main),
        "markdown": markdown(main, base_url),
        "links": sorted(links),
        "metadata": dict(sorted(metadata.items())),
        "alternate_candidates": [alternatives[key] for key in sorted(alternatives)],
        "jsonld": json_ld,
    }
    return soup, result


def follow_path(value: Any, path: list[Any]) -> tuple[bool, Any]:
    current = value
    for segment in path:
        if isinstance(segment, int) and isinstance(current, list) and 0 <= segment < len(current):
            current = current[segment]
        elif isinstance(segment, str) and isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return False, None
    return True, current


def primitive_matches(value: Any, expected: str | None) -> bool:
    if expected is None:
        return value is None or isinstance(value, (str, int, float, bool))
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def coerce_primitive(value: Any, expected: str | None) -> Any:
    if expected is None:
        return value
    if expected == "number" and isinstance(value, str):
        if not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", value.strip()):
            return value
        try:
            number = float(value.strip())
        except ValueError:
            return value
        if not math.isfinite(number):
            return value
        return int(number) if number.is_integer() else number
    if expected == "boolean" and isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return value


def schema_values(soup: Any, documents: list[Any], schema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    result: dict[str, Any] = {}
    invalid: list[str] = []
    for name, field in schema["fields"].items():
        many = bool(field.get("many", False))
        required = bool(field.get("required", False))
        expected_type = field.get("type")
        values: list[Any] = []
        if field["source"] == "css":
            try:
                matches = soup.select(field["selector"])
            except Exception:
                invalid.append(name)
                continue
            for match in matches:
                if field["take"] == "text":
                    value: Any = clean_text(match.get_text(" ", strip=True))
                else:
                    value = match.get(field["take"][1:])
                    if isinstance(value, list):
                        value = " ".join(str(item) for item in value)
                if value not in (None, ""):
                    values.append(coerce_primitive(value, expected_type))
        else:
            for document in documents:
                found, value = follow_path(document, field["path"])
                if found:
                    if many and isinstance(value, list):
                        values.extend(coerce_primitive(item, expected_type) for item in value)
                    else:
                        values.append(coerce_primitive(value, expected_type))

        selected: Any = values if many else (values[0] if values else None)
        checked = values if many else ([] if selected is None else [selected])
        if checked and not all(primitive_matches(value, expected_type) for value in checked):
            if required:
                invalid.append(name)
            continue
        if not checked:
            if required:
                invalid.append(name)
            continue
        result[name] = selected
    return result, sorted(set(invalid))


def input_bytes(path_value: Any, hash_value: Any) -> bytes:
    if not isinstance(path_value, str) or not os.path.isabs(path_value):
        raise HelperBoundaryError("invalid input path")
    if not isinstance(hash_value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", hash_value):
        raise HelperBoundaryError("invalid input hash")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path_value, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise HelperBoundaryError("invalid input file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_INPUT_BYTES:
        raise HelperBoundaryError("input too large")
    if "sha256:" + hashlib.sha256(data).hexdigest() != hash_value:
        raise InputHashMismatch("input hash mismatch")
    return data


def write_output(path_value: Any, value: Any) -> tuple[str, int]:
    if not isinstance(path_value, str) or not os.path.isabs(path_value):
        raise HelperBoundaryError("invalid output path")
    cwd = Path.cwd().resolve(strict=True)
    path = Path(path_value)
    parent = path.parent.resolve(strict=True)
    try:
        parent.relative_to(cwd)
    except ValueError as error:
        raise HelperBoundaryError("output path escapes scratch") from error
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_OUTPUT_BYTES:
        raise HelperBoundaryError("output too large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return str(path), len(data)


def handle(request: dict[str, Any]) -> dict[str, Any]:
    request_id = request.get("id")
    if request.get("version") != 1 or not isinstance(request_id, str) or not SAFE_ID.fullmatch(request_id):
        return failure("invalid", "parse_failed")
    operation = request.get("operation")
    if operation not in OPS:
        return failure(request_id, "unsupported")
    if operation == "self_check":
        if set(request) != {"version", "id", "operation"}:
            return failure(request_id, "parse_failed", {"reason": "invalid_request"})
        return self_check(request_id)
    allowed = {"version", "id", "operation", "input_path", "input_hash", "base_url", "output_path"}
    if operation == "extract_schema":
        allowed.add("schema")
    if not set(request).issubset(allowed):
        return failure(request_id, "parse_failed", {"reason": "invalid_request"})
    if BeautifulSoup is None:
        return failure(request_id, "dependency_unavailable", {"parser": "beautifulsoup4"})
    base_url = request.get("base_url")
    if not isinstance(base_url, str) or normalized_url(base_url, base_url) is None:
        return failure(request_id, "parse_failed")
    try:
        raw = input_bytes(request.get("input_path"), request.get("input_hash"))
        soup, parsed = parsed_html(raw, base_url)
        if operation == "parse_html":
            output_path, size = write_output(request.get("output_path"), parsed)
            return response(
                request_id,
                True,
                payload={"output_path": output_path, "bytes": size},
            )
        schema = request.get("schema")
        if not isinstance(schema, dict):
            return failure(request_id, "parse_failed")
        values, invalid = schema_values(soup, parsed["jsonld"], schema)
        if invalid:
            return failure(
                request_id,
                "required_fields_missing",
                {"reason": "required_fields_missing", "missing": invalid},
            )
        output_path, size = write_output(request.get("output_path"), values)
        return response(
            request_id,
            True,
            payload={"output_path": output_path, "bytes": size},
        )
    except InputHashMismatch:
        return failure(request_id, "hash_mismatch")
    except (HelperBoundaryError, OSError, RuntimeError, TypeError):
        return failure(request_id, "adapter_error")
    except ValueError:
        return failure(request_id, "parse_failed")


def read_request() -> dict[str, Any]:
    line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not line or len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
        raise ValueError("invalid request framing")
    if sys.stdin.buffer.read(1):
        raise ValueError("extra request data")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    return value


def main() -> int:
    if sys.argv[1:] == ["--self-check"]:
        result = self_check("cli-self-check")
        if result.get("ok") and isinstance(result.get("payload"), dict):
            result["python"] = result["payload"].get("python")
        emit(result)
        return 0 if BeautifulSoup is not None else 3
    if sys.argv[1:]:
        emit(failure("invalid", "unsupported"))
        return 0
    try:
        emit(handle(read_request()))
    except (json.JSONDecodeError, UnicodeError, ValueError):
        emit(failure("invalid", "parse_failed"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
