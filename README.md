# Snyfer Blocklist

Domains flagged by [Snyfer](https://snyfer.com). [Count, source date and checksums](stats.json).

## Files

| File | Format / use |
| --- | --- |
| [domains.txt](domains.txt) | One domain per line |
| [domains.json](domains.json) | JSON array |
| [hosts.txt](hosts.txt) | Hosts format for Pi-hole and AdGuard Home |
| [adblock.txt](adblock.txt) | Filters for uBlock Origin and AdGuard; includes subdomains |
| [signed.json](signed.json) | Source snapshot with Ed25519 signature |

This repository is currently private. Downloads require repository access.

## Inclusion criteria

A domain is included when its latest completed Snyfer scan meets at least one condition:

- Trust score below **40/100**.
- Regulatory warning.
- Positive blacklist detection.
- Verdict: `dangerous`.

Domains are normalized, deduplicated and sorted. Inclusion is automatic; manual approval and a published site report are not required. Old scans and inactive domains are not automatically excluded. False positives are possible.

## Updates

The workflow checks the [signed source](https://snyfer.com/blocklist/domains.json) hourly; the source normally rebuilds daily. It verifies the signature and rejects stale or invalid updates. Failed updates retain the previous snapshot; check its date in [stats.json](stats.json).

## Corrections

[Request a domain review on Snyfer](https://snyfer.com/dispute?utm_source=github&utm_medium=referral&utm_campaign=blocklist&utm_content=readme) to dispute a blocked domain, correct a report or report a dangerous site. Requests are private. Direct edits to generated files are overwritten.

## License

Data and documentation: [CC BY 4.0](LICENSE). Commercial reuse is allowed with attribution to Snyfer, a license link and notice of modifications.

Scripts, tests and workflow: [MIT](scripts/LICENSE).

## Maintenance

Node.js 24+. No dependencies.

```sh
node --test test/*.test.mjs
node scripts/sync.mjs --check
node scripts/sync.mjs
```
