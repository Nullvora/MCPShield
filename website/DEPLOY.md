# Nullvora launch site — deployment

This directory is the static production website for `nullvora.com`.

## Cloudflare Pages configuration

- Production branch: `main`
- Root directory: `website`
- Framework preset: None
- Build command: leave empty
- Build output directory: `.`

Cloudflare Pages should publish the files in this directory directly.

## Verification after deployment

- https://nullvora.com/
- https://nullvora.com/assets/hero-bg.jpg
- https://nullvora.com/sitemap.xml
- GitHub links point to https://github.com/Nullvora/MCPShield

## Launch notes

- MCPShield v1.1.1rc1 is intentionally described as a source beta.
- The runtime guard is defense in depth, not an OS sandbox.
- PyPI/container registry availability is not advertised until publishing is enabled.
