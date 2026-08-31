import { readFile } from 'node:fs/promises';

import { parsePublicUrl } from './policy.mjs';

const SNIFF_BYTES = 8 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const FORMATS = new Set(['raw', 'markdown', 'metadata', 'links', 'json']);
const XML_KINDS = new Set(['xml', 'rss', 'atom', 'sitemap']);

class RepresentationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RepresentationError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new RepresentationError(code, message);
}

function headerValue(headers, wantedName) {
  if (headers?.get instanceof Function) {
    const value = headers.get(wantedName);
    return Array.isArray(value) ? value[0] : value;
  }
  if (!headers || typeof headers !== 'object') return undefined;
  const entry = Object.entries(headers).find(([name]) => name.toLowerCase() === wantedName);
  const value = entry?.[1];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeMediaType(value) {
  if (typeof value !== 'string') return '';
  const mediaType = value.split(';', 1)[0].trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(mediaType) ? mediaType : '';
}

function declaredKind(mediaType) {
  if (['text/html', 'application/xhtml+xml'].includes(mediaType)) return 'html';
  if (['text/markdown', 'text/x-markdown', 'application/markdown'].includes(mediaType)) return 'markdown';
  if (mediaType === 'application/rss+xml') return 'rss';
  if (mediaType === 'application/atom+xml') return 'atom';
  if (mediaType === 'application/sitemap+xml') return 'sitemap';
  if (['application/json', 'text/json'].includes(mediaType) || mediaType.endsWith('+json')) return 'json';
  if (['application/xml', 'text/xml'].includes(mediaType) || mediaType.endsWith('+xml')) return 'xml';
  return null;
}

function sniffKind(prefixBytes) {
  const prefix = Buffer.isBuffer(prefixBytes)
    ? prefixBytes.subarray(0, SNIFF_BYTES)
    : Buffer.from(prefixBytes ?? '').subarray(0, SNIFF_BYTES);
  if (prefix.length === 0) return null;

  let text = prefix.toString('utf8').replace(/^\ufeff/u, '').trimStart();
  const lower = text.toLowerCase();
  if (/^<!doctype\s+html(?:\s|>)/u.test(lower) || /^<html(?:\s|>)/u.test(lower)) return 'html';
  if (text[0] === '{' || text[0] === '[') return 'json';

  for (let pass = 0; pass < 4; pass += 1) {
    const before = text;
    text = text
      .replace(/^<\?xml\b[^?]*(?:\?>|$)\s*/iu, '')
      .replace(/^<!--[^]*?(?:-->|$)\s*/u, '')
      .replace(/^<!doctype\b[^>]*(?:>|$)\s*/iu, '');
    if (text === before) break;
  }
  const root = text.match(/^<\s*([a-z_][\w:.-]*)(?:\s|\/?>)/iu)?.[1]?.toLowerCase();
  if (!root) return null;
  const localRoot = root.includes(':') ? root.slice(root.lastIndexOf(':') + 1) : root;
  if (localRoot === 'rss') return 'rss';
  if (localRoot === 'feed') return 'atom';
  if (localRoot === 'urlset' || localRoot === 'sitemapindex') return 'sitemap';
  if (['html', 'head', 'body'].includes(localRoot)) return 'html';
  return 'xml';
}

export function detectRepresentation({ headers = {}, prefixBytes = Buffer.alloc(0) } = {}) {
  const mediaType = normalizeMediaType(headerValue(headers, 'content-type')) || 'application/octet-stream';
  const declared = declaredKind(mediaType);
  const sniffed = sniffKind(prefixBytes);
  let kind = declared;

  if (!kind) kind = sniffed;
  if (kind === 'xml' && ['rss', 'atom', 'sitemap'].includes(sniffed)) kind = sniffed;
  if (!kind) kind = 'binary';

  const warnings = kind === 'binary' ? ['unknown_mime_raw_preserved'] : [];
  const result = {
    kind,
    mediaType,
    declaredType: declared,
    warnings: Object.freeze(warnings),
  };
  if (sniffed && sniffed !== declared) result.sniffedType = sniffed;
  return Object.freeze(result);
}

function artifactLimit(value) {
  const limit = value === undefined ? DEFAULT_MAX_ARTIFACT_BYTES : value;
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    fail('hard_limit', 'maxArtifactBytes must be a positive finite integer');
  }
  return limit;
}

function checkedArtifact(bytes, limit) {
  const artifact = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (artifact.length > limit) {
    const error = new RepresentationError('hard_limit', 'derived artifact exceeds maxArtifactBytes');
    error.limit = 'artifact_bytes';
    error.maxBytes = limit;
    error.actualBytes = artifact.length;
    throw error;
  }
  return artifact;
}

async function loadSource(sourcePath) {
  if (typeof sourcePath !== 'string' || sourcePath.length === 0) {
    fail('output_failure', 'sourcePath must name a stored source object');
  }
  try {
    return await readFile(sourcePath);
  } catch (cause) {
    const error = new RepresentationError('output_failure', 'unable to read stored source bytes');
    error.cause = cause;
    throw error;
  }
}

function stableJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('output_failure', 'JSON contains a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`);
  return `{${entries.join(',')}}`;
}

function jsonBytes(value) {
  return Buffer.from(`${stableJson(value)}\n`, 'utf8');
}

function parseJson(source) {
  let parsed;
  try {
    parsed = JSON.parse(source.toString('utf8'));
  } catch (cause) {
    const error = new RepresentationError('output_failure', 'stored source is not valid JSON');
    error.cause = cause;
    throw error;
  }
  return parsed;
}

function decodeHtmlEntities(value) {
  const named = new Map([
    ['amp', '&'], ['apos', "'"], ['gt', '>'], ['lt', '<'], ['nbsp', ' '], ['quot', '"'],
  ]);
  return value.replace(/&(#(?:x[0-9a-f]+|[0-9]+)|[a-z][a-z0-9]+);/giu, (entity, name) => {
    const normalized = name.toLowerCase();
    if (!normalized.startsWith('#')) return named.get(normalized) ?? entity;
    const hexadecimal = normalized[1] === 'x';
    const digits = normalized.slice(hexadecimal ? 2 : 1);
    const codePoint = Number.parseInt(digits, hexadecimal ? 16 : 10);
    if (!Number.isInteger(codePoint)
      || codePoint <= 0
      || codePoint > 0x10ffff
      || (codePoint >= 0xd800 && codePoint <= 0xdfff)) return '\ufffd';
    return String.fromCodePoint(codePoint);
  });
}

function attributeValue(tag, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const match = tag.match(new RegExp(`(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\u0060]+))`, 'iu'));
  return match ? decodeHtmlEntities(match[1] ?? match[2] ?? match[3] ?? '') : null;
}

function publicUrl(candidate, baseUrl) {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate !== candidate.trim()) return null;
  if (candidate.length > 8192 || /[\\\u0000-\u001f\u007f]/u.test(candidate)) return null;
  let resolved;
  try {
    resolved = new URL(candidate, baseUrl).href;
    return parsePublicUrl(resolved).canonicalUrl;
  } catch {
    return null;
  }
}

function withoutNonDataMarkup(source) {
  return source
    .replace(/<!--[^]*?(?:-->|$)/gu, '')
    .replace(/<(script|style|template|noscript|iframe|object|svg|canvas)\b[^>]*>[^]*?<\/\1\s*>/giu, '')
    .replace(/<(script|style|template|noscript|iframe|object|svg|canvas)\b[^>]*\/?\s*>/giu, '');
}

function markupCandidates(source) {
  const cleaned = withoutNonDataMarkup(source);
  const values = [];
  for (const match of cleaned.matchAll(/<[^>]+>/gu)) {
    const href = attributeValue(match[0], 'href');
    if (href !== null) values.push(href);
  }
  for (const match of cleaned.matchAll(/<(?:loc|link)\b[^>]*>([^<]*)<\/(?:loc|link)\s*>/giu)) {
    values.push(decodeHtmlEntities(match[1].trim()));
  }
  return values;
}

function markdownCandidates(source) {
  const values = [];
  for (const match of source.matchAll(/!?\[[^\]]*\]\(([^\s)]+)(?:\s+["'][^"']*["'])?\)/gu)) values.push(match[1]);
  for (const match of source.matchAll(/<(https?:\/\/[^\s<>]+)>/giu)) values.push(match[1]);
  return values;
}

function jsonCandidates(value, values = []) {
  if (typeof value === 'string') {
    if (/^(?:https?:\/\/|\/\/|\/|\.\.?\/)/iu.test(value)) values.push(value);
    return values;
  }
  if (Array.isArray(value)) {
    for (const item of value) jsonCandidates(item, values);
    return values;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) jsonCandidates(item, values);
  }
  return values;
}

function extractLinks(source, kind, finalUrl) {
  let candidates = [];
  const text = source.toString('utf8');
  if (kind === 'html' || XML_KINDS.has(kind)) candidates = markupCandidates(text);
  else if (kind === 'markdown') candidates = markdownCandidates(text);
  else if (kind === 'json') candidates = jsonCandidates(parseJson(source));

  const links = new Set();
  for (const candidate of candidates) {
    const safe = publicUrl(candidate, finalUrl);
    if (safe) links.add(safe);
  }
  return [...links].sort();
}

function appendBreak(output, count = 2) {
  const withoutSpaces = output.replace(/[ \t]+$/u, '');
  const trailing = withoutSpaces.match(/\n*$/u)?.[0].length ?? 0;
  return `${withoutSpaces}${'\n'.repeat(Math.max(0, count - trailing))}`;
}

function markdownLinkUrl(url) {
  return url.replace(/\\/gu, '%5C').replace(/\(/gu, '%28').replace(/\)/gu, '%29');
}

function htmlMarkdown(source, finalUrl) {
  const body = withoutNonDataMarkup(source).replace(/<head\b[^>]*>[^]*?<\/head\s*>/giu, '');
  const tokens = body.match(/<[^>]*>|[^<]+/gu) ?? [];
  const anchors = [];
  let output = '';

  for (const token of tokens) {
    if (!token.startsWith('<')) {
      const compact = decodeHtmlEntities(token).replace(/\s+/gu, ' ');
      if (compact.trim() === '') {
        if (output !== '' && !/[\s]$/u.test(output)) output += ' ';
      } else {
        const text = /(?:^|[\s])$/u.test(output) ? compact.trimStart() : compact;
        output += text;
      }
      continue;
    }

    const parsed = token.match(/^<\s*(\/?)\s*([a-z][\w:-]*)/iu);
    if (!parsed) continue;
    const closing = parsed[1] === '/';
    const name = parsed[2].toLowerCase();

    if (name === 'a') {
      if (!closing) {
        anchors.push({ start: output.length, url: publicUrl(attributeValue(token, 'href'), finalUrl) });
      } else {
        const anchor = anchors.pop();
        if (anchor?.url) {
          const before = output.slice(0, anchor.start);
          const label = output.slice(anchor.start).trim().replace(/([\[\]\\])/gu, '\\$1');
          output = `${before}[${label || anchor.url}](${markdownLinkUrl(anchor.url)})`;
        }
      }
      continue;
    }

    const heading = name.match(/^h([1-6])$/u);
    if (heading) {
      output = appendBreak(output);
      if (!closing) output += `${'#'.repeat(Number(heading[1]))} `;
      continue;
    }
    if (name === 'br') {
      output = appendBreak(output, 1);
      continue;
    }
    if (name === 'li') {
      output = appendBreak(output, 1);
      if (!closing) output += '- ';
      continue;
    }
    if (['p', 'div', 'section', 'article', 'main', 'header', 'footer', 'nav', 'aside', 'blockquote', 'pre', 'table', 'tr', 'ul', 'ol'].includes(name)) {
      output = appendBreak(output);
      continue;
    }
    if (name === 'img' && !closing) {
      const alt = attributeValue(token, 'alt')?.replace(/\s+/gu, ' ').trim();
      if (alt) output += alt;
    }
  }

  output = output
    .replace(/[ \t]+\n/gu, '\n')
    .replace(/\n{3,}/gu, '\n\n')
    .trim();
  return output === '' ? '' : `${output}\n`;
}

function fencedSource(source, language) {
  const text = source.toString('utf8');
  let fenceLength = 3;
  for (const run of text.matchAll(/`+/gu)) fenceLength = Math.max(fenceLength, run[0].length + 1);
  const fence = '`'.repeat(fenceLength);
  return `${fence}${language}\n${text}${text.endsWith('\n') ? '' : '\n'}${fence}\n`;
}

function safeFinalUrl(finalUrl) {
  try {
    return parsePublicUrl(finalUrl).canonicalUrl;
  } catch (cause) {
    const error = new RepresentationError('output_failure', 'finalUrl is not a safe public HTTP(S) URL');
    error.cause = cause;
    throw error;
  }
}

export async function deriveRepresentation({
  format,
  sourcePath,
  mediaType,
  finalUrl,
  maxArtifactBytes,
} = {}) {
  if (!FORMATS.has(format)) fail('unsupported_format', 'requested representation format is unsupported');
  const limit = artifactLimit(maxArtifactBytes);
  const source = await loadSource(sourcePath);
  const normalizedMediaType = normalizeMediaType(mediaType) || 'application/octet-stream';
  const detected = detectRepresentation({
    headers: { 'content-type': normalizedMediaType },
    prefixBytes: source.subarray(0, SNIFF_BYTES),
  });
  const warnings = [...detected.warnings];

  if (format === 'raw') {
    return Object.freeze({
      format: 'raw',
      mediaType: normalizedMediaType,
      bytes: checkedArtifact(source, limit),
      warnings: Object.freeze(warnings),
    });
  }

  const canonicalFinalUrl = safeFinalUrl(finalUrl);
  let bytes;
  let effectiveFormat = format;

  if (format === 'metadata') {
    bytes = jsonBytes({
      bytes: source.length,
      final_url: canonicalFinalUrl,
      media_type: normalizedMediaType,
    });
  } else if (format === 'links') {
    bytes = jsonBytes(extractLinks(source, detected.kind, canonicalFinalUrl));
  } else if (format === 'json') {
    bytes = jsonBytes(parseJson(source));
  } else if (detected.kind === 'markdown') {
    bytes = source;
  } else if (detected.kind === 'json') {
    bytes = Buffer.from(fencedSource(source, 'json'), 'utf8');
  } else if (XML_KINDS.has(detected.kind)) {
    bytes = Buffer.from(fencedSource(source, 'xml'), 'utf8');
  } else if (detected.kind === 'html') {
    bytes = Buffer.from(htmlMarkdown(source.toString('utf8'), canonicalFinalUrl), 'utf8');
  } else {
    effectiveFormat = 'raw';
    bytes = source;
    if (!warnings.includes('unknown_mime_raw_preserved')) warnings.push('unknown_mime_raw_preserved');
  }

  return Object.freeze({
    format: effectiveFormat,
    mediaType: normalizedMediaType,
    bytes: checkedArtifact(bytes, limit),
    warnings: Object.freeze(warnings),
  });
}
