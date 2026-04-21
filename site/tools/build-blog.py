#!/usr/bin/env python3
"""
Cerberix blog generator.

Reads site/posts/*.md (markdown + YAML-lite frontmatter), emits:
  - site/blog/index.html         (post list)
  - site/blog/<slug>/index.html  (individual post)
  - site/feed.xml                (RSS, all posts)

Usage:
  python3 site/tools/build-blog.py

Frontmatter:
  ---
  title: My post title
  date: 2026-04-18
  description: Short summary for listings and RSS
  ---
"""
import html
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import markdown

SITE_DIR = Path(__file__).resolve().parent.parent
POSTS_DIR = SITE_DIR / "posts"
BLOG_DIR = SITE_DIR / "blog"
FEED_FILE = SITE_DIR / "feed.xml"
SITE_URL = "https://cerberix.org"
SITE_TITLE = "Cerberix Linux"
SITE_DESC = "Release notes, security advisories, and project updates for Cerberix Linux."
TZ_OFFSET = timedelta(hours=-4)


def parse_frontmatter(text):
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError("missing frontmatter")
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip('"\'')
    return meta, m.group(2)


def load_posts():
    posts = []
    for path in sorted(POSTS_DIR.glob("*.md")):
        try:
            meta, body = parse_frontmatter(path.read_text())
        except ValueError as e:
            print(f"SKIP {path.name}: {e}", file=sys.stderr)
            continue
        slug = path.stem
        if not {"title", "date"}.issubset(meta):
            print(f"SKIP {path.name}: missing title or date", file=sys.stderr)
            continue
        try:
            dt = datetime.strptime(meta["date"], "%Y-%m-%d").replace(
                hour=9, tzinfo=timezone(TZ_OFFSET)
            )
        except ValueError:
            print(f"SKIP {path.name}: bad date {meta['date']!r}", file=sys.stderr)
            continue
        posts.append(
            {
                "slug": slug,
                "title": meta["title"],
                "date": meta["date"],
                "dt": dt,
                "description": meta.get("description", ""),
                "body_html": markdown.markdown(
                    body, extensions=["fenced_code", "tables", "sane_lists"]
                ),
            }
        )
    posts.sort(key=lambda p: p["dt"], reverse=True)
    return posts


PAGE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>__PAGE_TITLE__</title>
  <meta name="description" content="__PAGE_DESC__" />
  <meta name="theme-color" content="#222436" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="alternate" type="application/rss+xml" title="Cerberix Linux updates" href="/feed.xml" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Cormorant+Garamond:wght@500;600;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/style.css" />
  <style>
    .prose { max-width: 760px; margin: 0 auto; padding: 80px 32px 120px; }
    .prose h1 { margin-bottom: 10px; }
    .prose h2 { margin: 2em 0 0.4em; font-size: 1.5rem; }
    .prose h3 { margin: 1.8em 0 0.4em; font-size: 1.15rem; color: var(--fg); }
    .prose p { color: var(--fg); line-height: 1.75; margin-bottom: 1em; }
    .prose ul, .prose ol { color: var(--fg-dim); padding-left: 22px; margin-bottom: 1.2em; }
    .prose li { margin-bottom: 6px; }
    .prose li strong { color: var(--fg); font-weight: 600; }
    .prose code { background: var(--bg-darker); padding: 2px 8px; border-radius: 4px; color: var(--green); font-size: 0.88em; }
    .prose pre { background: var(--bg-darker); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 18px 22px; overflow-x: auto; line-height: 1.6; }
    .prose pre code { background: transparent; padding: 0; color: var(--fg); font-size: 0.88em; }
    .prose a { text-decoration: underline; text-decoration-color: rgba(130, 170, 255, 0.4); }
    .prose blockquote { border-left: 3px solid var(--purple); padding: 8px 18px; color: var(--fg-dim); margin: 20px 0; background: var(--bg-darker); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
    .post-meta { font-family: var(--font-mono); font-size: 0.88rem; color: var(--fg-dim); margin-bottom: 36px; display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
    .post-meta .dot { width: 3px; height: 3px; background: var(--fg-faint); border-radius: 50%; display: inline-block; }
    .back-link { display: inline-flex; align-items: center; gap: 8px; color: var(--fg-dim); font-size: 0.92rem; margin-bottom: 28px; }
    .back-link:hover { color: var(--fg); }
    .post-list { list-style: none; padding: 0; margin: 0; }
    .post-item { padding: 28px 0; border-bottom: 1px solid var(--border); }
    .post-item:last-child { border-bottom: none; }
    .post-item h2 { margin: 0 0 6px; font-size: 1.4rem; }
    .post-item h2 a { color: var(--fg); text-decoration: none; }
    .post-item h2 a:hover { color: var(--blue); }
    .post-item .post-date { font-family: var(--font-mono); font-size: 0.82rem; color: var(--fg-faint); }
    .post-item .post-desc { color: var(--fg-dim); margin: 10px 0 0; }
  </style>
</head>
<body>
  <div class="bg-grid"></div>

  <header class="nav">
    <a class="brand" href="/">
      <svg class="brand-mark" viewBox="0 0 48 48" aria-hidden="true">
        <defs>
          <linearGradient id="shieldGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#82aaff" />
            <stop offset="100%" stop-color="#c099ff" />
          </linearGradient>
        </defs>
        <path d="M24 3 L42 10 V24 C42 34 34 42 24 45 C14 42 6 34 6 24 V10 Z"
              fill="none" stroke="url(#shieldGrad)" stroke-width="2.5" stroke-linejoin="round" />
        <circle cx="17" cy="22" r="2.2" fill="#c3e88d" />
        <circle cx="24" cy="20" r="2.2" fill="#c3e88d" />
        <circle cx="31" cy="22" r="2.2" fill="#c3e88d" />
        <path d="M14 30 Q24 38 34 30" fill="none" stroke="#82aaff" stroke-width="2" stroke-linecap="round" />
      </svg>
      <span class="brand-name">Cerberix</span>
    </a>
    <nav class="nav-links">
      <a href="/#features">Features</a>
      <a href="/blog/">Blog</a>
      <a href="/#download">Download</a>
      <a href="/feed.xml">RSS</a>
      <a class="nav-cta" href="/#download">Get it</a>
    </nav>
  </header>
"""

PAGE_FOOT = """
  <footer class="footer">
    <div class="foot-row">
      <div class="foot-brand">
        <svg class="brand-mark sm" viewBox="0 0 48 48" aria-hidden="true">
          <path d="M24 3 L42 10 V24 C42 34 34 42 24 45 C14 42 6 34 6 24 V10 Z"
                fill="none" stroke="#82aaff" stroke-width="2.5" stroke-linejoin="round" />
          <circle cx="17" cy="22" r="2.2" fill="#c3e88d" />
          <circle cx="24" cy="20" r="2.2" fill="#c3e88d" />
          <circle cx="31" cy="22" r="2.2" fill="#c3e88d" />
        </svg>
        <span>Cerberix Linux</span>
      </div>
      <div class="foot-links">
        <a href="/">Home</a>
        <a href="/blog/">Blog</a>
        <a href="/feed.xml">RSS</a>
        <a href="https://github.com/yodabytz/cerberix-linux">Source</a>
        <a href="https://matrix.to/#/#cerberix:matrix.quantumbytz.com">Matrix</a>
        <a href="mailto:hello@cerberix.org">Contact</a>
      </div>
    </div>
    <div class="foot-sub">
      © 2026 Cerberix &middot; Released under the MIT License &middot; Built on Arch
    </div>
  </footer>
</body>
</html>
"""


def page_head(title, desc):
    return (
        PAGE_HEAD
        .replace("__PAGE_TITLE__", html.escape(title))
        .replace("__PAGE_DESC__", html.escape(desc))
    )


def render_post(post):
    return (
        page_head(
            f"{post['title']} — Cerberix Linux",
            post["description"] or post["title"],
        )
        + f"""
  <main class="prose">
    <a class="back-link" href="/blog/">&larr; All posts</a>
    <h1>{html.escape(post['title'])}</h1>
    <div class="post-meta">
      <span>{post['date']}</span>
      <span class="dot"></span>
      <span>Cerberix Linux</span>
    </div>
    {post['body_html']}
  </main>
"""
        + PAGE_FOOT
    )


def render_index(posts):
    items = "\n".join(
        f"""      <li class="post-item">
        <span class="post-date">{p['date']}</span>
        <h2><a href="/blog/{p['slug']}/">{html.escape(p['title'])}</a></h2>
        <p class="post-desc">{html.escape(p['description'])}</p>
      </li>"""
        for p in posts
    )
    body = f"""
  <main class="prose">
    <a class="back-link" href="/">&larr; Back to home</a>
    <h1>Blog</h1>
    <p style="color: var(--fg-dim); margin-bottom: 48px;">
      Updates, release notes, and security advisories for Cerberix Linux.
      Subscribe via <a href="/feed.xml">RSS</a>.
    </p>
    <ul class="post-list">
{items}
    </ul>
  </main>
"""
    return page_head(f"Blog — {SITE_TITLE}", SITE_DESC) + body + PAGE_FOOT


def rfc822(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S %z")


def render_feed(posts):
    build_date = rfc822(max((p["dt"] for p in posts), default=datetime.now(timezone(TZ_OFFSET))))
    items_xml = []
    for p in posts:
        body = p["body_html"]
        desc_escaped = html.escape(p["description"]) if p["description"] else ""
        items_xml.append(
            f"""    <item>
      <title>{html.escape(p['title'])}</title>
      <link>{SITE_URL}/blog/{p['slug']}/</link>
      <guid isPermaLink="true">{SITE_URL}/blog/{p['slug']}/</guid>
      <pubDate>{rfc822(p['dt'])}</pubDate>
      <description>{desc_escaped}</description>
      <content:encoded><![CDATA[{body}]]></content:encoded>
    </item>"""
        )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>{SITE_TITLE}</title>
    <link>{SITE_URL}/</link>
    <atom:link href="{SITE_URL}/feed.xml" rel="self" type="application/rss+xml" />
    <description>{SITE_DESC}</description>
    <language>en-us</language>
    <lastBuildDate>{build_date}</lastBuildDate>
    <generator>Cerberix blog generator</generator>
    <image>
      <url>{SITE_URL}/favicon.svg</url>
      <title>{SITE_TITLE}</title>
      <link>{SITE_URL}/</link>
    </image>

{chr(10).join(items_xml)}
  </channel>
</rss>
"""


def main():
    POSTS_DIR.mkdir(exist_ok=True)
    posts = load_posts()
    if not posts:
        print("no posts found in", POSTS_DIR, file=sys.stderr)
        return 1

    BLOG_DIR.mkdir(exist_ok=True)
    for post in posts:
        d = BLOG_DIR / post["slug"]
        d.mkdir(exist_ok=True)
        (d / "index.html").write_text(render_post(post))
        print(f"wrote blog/{post['slug']}/")

    (BLOG_DIR / "index.html").write_text(render_index(posts))
    print("wrote blog/index.html")

    FEED_FILE.write_text(render_feed(posts))
    print("wrote feed.xml")

    print(f"\n{len(posts)} post(s) generated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
