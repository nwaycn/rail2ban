# rail2ban

Rust reimplementation of [fail2ban](https://github.com/fail2ban/fail2ban), aiming for behavioral
parity with fail2ban 1.1.x while delivering a single, fast, memory-safe binary.

## Status

Work in progress. See `docs/SPEC.md` for the full technical specification.

## Binaries

- `rail2ban-server` — long-running daemon (jails, filtering, banning, actions)
- `rail2ban-client` — Unix-socket client compatible with `fail2ban-client` commands
- `rail2ban-regex` — offline regex testing tool

## License

GPL-2.0-or-later.
