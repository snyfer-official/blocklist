# Snyfer Blocklist

[![Update status](https://github.com/snyfer-official/blocklist/actions/workflows/update.yml/badge.svg)](https://github.com/snyfer-official/blocklist/actions/workflows/update.yml)
[![Data: CC BY 4.0](https://img.shields.io/badge/data-CC_BY_4.0-blue)](LICENSE)

A public domain risk list maintained by [Snyfer](https://snyfer.com), available for DNS filters, browser content blockers and custom integrations.

**[Latest domain count and source date](stats.json)** · **[Report a false positive or missing domain](https://github.com/snyfer-official/blocklist/issues/new/choose)**

## Download

| Format | Download | Use |
| --- | --- | --- |
| Plain text | [domains.txt](https://raw.githubusercontent.com/snyfer-official/blocklist/main/domains.txt) | One domain per line, without headers |
| JSON array | [domains.json](https://raw.githubusercontent.com/snyfer-official/blocklist/main/domains.json) | Scripts and applications |
| Hosts | [hosts.txt](https://raw.githubusercontent.com/snyfer-official/blocklist/main/hosts.txt) | Pi-hole, AdGuard Home and hosts-compatible tools |
| AdBlock | [adblock.txt](https://raw.githubusercontent.com/snyfer-official/blocklist/main/adblock.txt) | uBlock Origin and AdGuard |
| Signed snapshot | [signed.json](https://raw.githubusercontent.com/snyfer-official/blocklist/main/signed.json) | Version, source date, domains and Ed25519 signature |

Paste the **Hosts** URL into your DNS blocklist settings, or the **AdBlock** URL into your browser blocker's custom filter lists.

Optional CDN mirror: replace `https://raw.githubusercontent.com/snyfer-official/blocklist/main/` with `https://cdn.jsdelivr.net/gh/snyfer-official/blocklist@main/`. Mirrors may update later than GitHub; check the source date when freshness matters.

## What is listed?

This repository mirrors Snyfer's published domain risk list. Membership can result from a low trust score, a regulatory warning, a blacklist signal or a dangerous verdict. **An entry is a risk classification, not a claim that every listed domain is confirmed phishing.**

All formats use the same sorted, deduplicated domain set. Domains use ASCII/punycode. The AdBlock format covers a listed domain and its subdomains; the Hosts format names only the listed hosts, and subdomain handling depends on your resolver. This is domain-level protection, not URL-path filtering.

False positives and missed threats are possible. A domain absent from the list is not necessarily safe. Inclusion does not mean a domain currently resolves or serves malicious content; this feed does not claim to be a live DNS/content-verified list.

## Updates and integrity

GitHub Actions checks the [public signed source](https://snyfer.com/blocklist/domains.json) every hour, at minute 17. Snyfer normally rebuilds that source daily. Scheduled runs can be delayed; [stats.json](stats.json) records the actual source publication time and SHA-256 checksums for every downloadable format.

The updater verifies the publisher's Ed25519 signature before generating files. It rejects malformed or empty lists, sources older than 48 hours, future dates, version rollbacks and suspicious mass removals. Failed updates leave the previous GitHub snapshot available, so consumers should monitor its date. Files are published together in one commit, and unchanged snapshots do not generate new commits.

For a consistent snapshot across formats, use the same Git commit in every download URL instead of `main`. The signature authenticates the publisher and list contents; it does not guarantee the accuracy of a domain classification. Checksums detect file changes but are not a replacement for signature verification.

Verification uses this public key (not a credential):

```text
YVW2zsIyjP805yuyAXLct/s/SX7o57iGxcqYd4QTTLg=
```

This repository contains public data and the small mirror/conversion tool. The Snyfer backend, scoring engine, extension code and private signing key are not included. Synchronization needs no Snyfer API key or server access.

## Corrections

[Open a domain report](https://github.com/snyfer-official/blocklist/issues/new/choose) with the domain, your explanation and public evidence. For private information, contact [security@snyfer.com](mailto:security@snyfer.com) instead. Reports are reviewed before changes reach the source list and its next published snapshot. Do not edit the generated lists directly: the next synchronization would overwrite those edits.

## License and attribution

The domain datasets, metadata and this documentation are copyright 2026 Snyfer and licensed under [Creative Commons Attribution 4.0 International](LICENSE). Commercial reuse is permitted with attribution, a license link and an indication of modifications. The data is provided without warranties.

Suggested attribution: **Snyfer Blocklist — https://snyfer.com — CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/**. If you modify the data, say so. The synchronization scripts, tests and workflow code use the [MIT license](scripts/LICENSE).

## Maintain the mirror

Node.js 24 or later is sufficient; no package installation is needed.

```sh
node --test test/*.test.mjs
node scripts/sync.mjs --check
node scripts/sync.mjs
```

`--check` verifies the committed signature and that all generated files match it, without accessing the network. Synchronization additionally enforces freshness and rollback checks. Changes to the generator should include tests; generated files should always come from the verified source.
