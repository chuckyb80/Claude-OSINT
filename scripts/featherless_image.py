#!/usr/bin/env python3
"""featherless_image.py — describe images with a vision model on Featherless AI.

Stdlib-only (urllib, no `openai` package, no `requests`) so it runs anywhere
python3 does. Featherless exposes an OpenAI-compatible /chat/completions
endpoint, so the request body below is the same shape the OpenAI SDK sends.

Recon use: caption or transcribe screenshots, leaked photos, marketing assets,
login-page captures and org-chart images collected during a passive engagement,
without hand-reading each one. It describes images you already hold — it does
not fetch anything except the image URLs you pass it.

The API key is read from the environment (or a file), never from a flag —
an --api-key argument leaks into shell history and into `ps` output on a
shared host.

Usage:
  export FEATHERLESS_API_KEY=...           # required
  export FEATHERLESS_MODEL=<vision-model>  # or pass --model

  # A remote image
  python3 featherless_image.py https://example.com/banner.png

  # A local file (inlined as a base64 data URI) with a custom prompt
  python3 featherless_image.py shot.png -p "Transcribe every string you can read."

  # Several images in one message, JSON output for piping
  python3 featherless_image.py a.png b.jpg --json

  # Show the exact request without sending it (key redacted)
  python3 featherless_image.py shot.png --dry-run

  # Key on disk instead of in the environment
  python3 featherless_image.py shot.png --api-key-file ~/.config/featherless.key

Exit codes:
  0 — completed
  2 — invalid arguments or unreadable/oversized input
  3 — API or transport error (after retries)
  4 — unexpected response shape
  130 — interrupted
"""

import argparse
import base64
import json
import mimetypes
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://api.featherless.ai/v1"
DEFAULT_PROMPT = "Describe the image in one paragraph."
DEFAULT_TIMEOUT = 120.0
DEFAULT_RETRIES = 3
DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024

# Sniffed from content, not from the file name: an attacker-supplied name is
# not evidence of type, and a wrong mime in the data URI is rejected by the
# server as a decode error rather than as "unsupported format".
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
]

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


def die(msg, code=2):
    print(f"featherless_image: {msg}", file=sys.stderr)
    sys.exit(code)


def sniff_mime(head, path):
    for magic, mime in MAGIC:
        if head.startswith(magic):
            return mime
    # RIFF....WEBP — the size field sits between the two markers.
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    guess, _ = mimetypes.guess_type(path)
    if guess and guess.startswith("image/"):
        return guess
    return None


def is_url(s):
    return urllib.parse.urlparse(s).scheme in ("http", "https")


def load_image(spec, max_bytes, mime_override):
    """Return the value for an image_url part: a URL passed through, or a
    local file inlined as a data URI."""
    if is_url(spec):
        return spec
    if not os.path.isfile(spec):
        die(f"not a URL and not a readable file: {spec}")
    size = os.path.getsize(spec)
    if size == 0:
        die(f"empty file: {spec}")
    if size > max_bytes:
        # base64 inflates by 4/3 on top of this, so the wire cost is larger
        # still; refuse before reading rather than after.
        die(f"{spec} is {size} bytes, over the {max_bytes}-byte limit "
            f"(raise it with --max-image-bytes)")
    with open(spec, "rb") as f:
        data = f.read()
    mime = mime_override or sniff_mime(data[:16], spec)
    if mime is None:
        die(f"cannot determine image type of {spec} (pass --mime to force it)")
    return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")


def read_api_key(path):
    if path:
        try:
            with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
                key = f.read().strip()
        except OSError as e:
            die(f"cannot read --api-key-file: {e}")
        if not key:
            die(f"--api-key-file {path} is empty")
        return key
    key = os.environ.get("FEATHERLESS_API_KEY", "").strip()
    if not key:
        die("no API key: set FEATHERLESS_API_KEY or pass --api-key-file")
    return key


def build_payload(args, image_values):
    content = [{"type": "text", "text": args.prompt}]
    for value in image_values:
        content.append({"type": "image_url", "image_url": {"url": value}})
    messages = []
    if args.system:
        messages.append({"role": "system", "content": args.system})
    messages.append({"role": "user", "content": content})

    payload = {"model": args.model, "messages": messages}
    if args.max_tokens is not None:
        payload["max_tokens"] = args.max_tokens
    if args.temperature is not None:
        payload["temperature"] = args.temperature
    return payload


def redacted(payload):
    """A copy safe to print: data URIs are megabytes of base64 that would
    bury the part of the request a human is actually checking."""
    clone = json.loads(json.dumps(payload))
    for message in clone["messages"]:
        if not isinstance(message.get("content"), list):
            continue
        for part in message["content"]:
            url = part.get("image_url", {}).get("url", "")
            if url.startswith("data:"):
                head = url.split(",", 1)[0]
                part["image_url"]["url"] = f"{head},<{len(url)} chars elided>"
    return clone


def post(url, payload, api_key, timeout):
    """One attempt. Returns (status, body_bytes, retry_after_seconds_or_None)."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "claude-osint-featherless-image/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        retry_after = e.headers.get("Retry-After") if e.headers else None
        try:
            retry_after = float(retry_after) if retry_after else None
        except ValueError:
            retry_after = None  # HTTP-date form; fall back to our own backoff
        return e.code, e.read(), retry_after


def call_api(url, payload, api_key, timeout, retries, verbose):
    delay = 1.0
    last = None
    for attempt in range(1, retries + 1):
        try:
            status, body, retry_after = post(url, payload, api_key, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # Transport-level: no status to inspect, so treat as retryable.
            status, body, retry_after = None, None, None
            last = f"transport error: {e}"
        else:
            if 200 <= status < 300:
                return body
            detail = (body or b"").decode("utf-8", "replace").strip()
            last = f"HTTP {status}: {detail[:800]}"
            if status not in RETRY_STATUS:
                die(last, 3)

        if attempt == retries:
            break
        wait = retry_after if retry_after is not None else delay
        wait += random.uniform(0, 0.25 * wait)  # jitter, so parallel runs
        if verbose:                             # don't retry in lockstep
            print(f"featherless_image: attempt {attempt}/{retries} failed "
                  f"({last}); retrying in {wait:.1f}s", file=sys.stderr)
        time.sleep(wait)
        delay = min(delay * 2, 60.0)

    die(f"giving up after {retries} attempt(s) — {last}", 3)


def main():
    p = argparse.ArgumentParser(
        prog="featherless_image.py",
        description="Describe images with a vision model on Featherless AI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The API key comes from FEATHERLESS_API_KEY or --api-key-file, "
               "never from a command-line flag.",
    )
    p.add_argument("images", nargs="+",
                   help="image URLs and/or local file paths (all sent in one message)")
    p.add_argument("-p", "--prompt", default=DEFAULT_PROMPT,
                   help=f"user prompt (default: {DEFAULT_PROMPT!r})")
    p.add_argument("--system", help="optional system message")
    p.add_argument("-m", "--model", default=os.environ.get("FEATHERLESS_MODEL"),
                   help="vision model id (default: $FEATHERLESS_MODEL)")
    p.add_argument("--base-url",
                   default=os.environ.get("FEATHERLESS_BASE_URL", DEFAULT_BASE_URL),
                   help=f"API base (default: $FEATHERLESS_BASE_URL or {DEFAULT_BASE_URL})")
    p.add_argument("--api-key-file",
                   help="read the key from this file instead of the environment")
    p.add_argument("--max-tokens", type=int, help="cap on generated tokens")
    p.add_argument("--temperature", type=float, help="sampling temperature")
    p.add_argument("--mime", help="force the mime type of local files "
                                  "(default: sniffed from content)")
    p.add_argument("--max-image-bytes", type=int, default=DEFAULT_MAX_IMAGE_BYTES,
                   help=f"per-file size limit (default: {DEFAULT_MAX_IMAGE_BYTES})")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                   help=f"attempts on 429/5xx/transport errors (default: {DEFAULT_RETRIES})")
    p.add_argument("--json", action="store_true",
                   help="emit {model, content, finish_reason, usage} instead of bare text")
    p.add_argument("--dry-run", action="store_true",
                   help="print the request body (data URIs elided) and exit; sends nothing")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="report retries on stderr")
    args = p.parse_args()

    if not args.model:
        die("no model: pass --model or set FEATHERLESS_MODEL")
    if args.retries < 1:
        die("--retries must be at least 1")
    if args.max_image_bytes < 1:
        die("--max-image-bytes must be positive")
    if args.mime and not args.mime.startswith("image/"):
        die(f"--mime must be an image/* type, got {args.mime!r}")

    scheme = urllib.parse.urlparse(args.base_url).scheme
    if scheme != "https":
        if scheme != "http":
            die(f"--base-url must be http(s), got {args.base_url!r}")
        print("featherless_image: warning: sending the API key over plaintext "
              "http", file=sys.stderr)

    payload = build_payload(args, [load_image(spec, args.max_image_bytes, args.mime)
                                   for spec in args.images])

    if args.dry_run:
        json.dump(redacted(payload), sys.stdout, indent=2)
        print()
        return 0

    api_key = read_api_key(args.api_key_file)
    endpoint = args.base_url.rstrip("/") + "/chat/completions"
    raw = call_api(endpoint, payload, api_key, args.timeout, args.retries,
                   args.verbose)

    try:
        data = json.loads(raw)
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        die(f"unexpected response shape ({e}): "
            f"{raw[:400].decode('utf-8', 'replace')}", 4)

    if content is None:
        die("model returned no content (check the model supports images)", 4)

    if args.json:
        json.dump({
            "model": data.get("model", args.model),
            "content": content,
            "finish_reason": choice.get("finish_reason"),
            "usage": data.get("usage"),
        }, sys.stdout, indent=2)
        print()
    else:
        print(content)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
