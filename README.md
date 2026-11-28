# Jailer

**Jailer** is a small, single-binary reimplementation of the core idea behind [fail2ban](https://github.com/fail2ban/fail2ban): it watches log files for repeated failures (or any pattern you define) and bans the offending IP address with `iptables` until the ban expires.

The goal is to keep fail2ban's behaviour while dropping its weight — no Python runtime, no plugin system, no configuration sprawl. Jailer is one trimmed, self-contained .NET 8 binary that runs as a systemd service on Linux and depends on nothing but `iptables`.

## How it works

- **Jails** are defined in a single JSON file (`jails.json`). Each jail names a log file, a pattern to match, how many attempts trigger a ban, and for how long.
- Patterns may be plain .NET regular expressions *or* fail2ban filter syntax: `<HOST>`, `%(__prefix_line)s` and other `%(...)s` variables are translated into equivalent .NET regexes at startup (see `Services/Fail2BanFilter.cs`). Multi-line filters work the same way as in fail2ban — each line is an independent alternative.
- Log files are tailed from the end; matched lines have their IPv4/IPv6 address extracted, and per-IP attempt counts accumulate within a 24-hour window (a slow drip of one bad attempt a day never adds up to a ban).
- When an IP reaches its threshold it is jailed **immediately**: an `iptables -I INPUT -s <ip> --comment jailer:<ip> DROP` rule is inserted. Rules are tagged with the `jailer:` comment so Jailer only ever removes its own entries.
- Bans expire automatically — a cleanup loop releases them (at most 30 s after expiry) and prints the current state of every jail.

## Configuration

`jails.json` lives next to the executable:

```json
{
    "jails": [
        {
            "name": "sshd",
            "logFile": "/var/log/auth.log",
            "regex": "^%(__prefix_line)sFailed \\S+ for .*? from <HOST>(?: port \\d*)?(?: ssh\\d*)?\\s*$",
            "attempts": 3,
            "banTime": 360
        }
    ]
}
```

| Field      | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `name`     | Jail name (used in logs and the state summary)                 |
| `logFile`  | Path of the log file to tail                                   |
| `regex`    | .NET regex or fail2ban filter syntax                           |
| `attempts` | Number of matching lines from one IP that trigger a ban        |
| `banTime`  | Ban duration in **minutes**                                    |

## Build & deploy

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
# Run locally (any OS, for development)
dotnet run --project Jailer.csproj

# Publish a trimmed single-file binary for Linux x64
dotnet publish Jailer.csproj -c Release -r linux-x64 \
    --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
```

Deploy to the target host (the service file expects `/opt/Jailer`):

```bash
sudo cp bin/Release/net8.0/publish/linux-x64/Jailer /opt/Jailer
sudo chmod +x /opt/Jailer
# put your jails.json next to it, then:
sudo cp jailer.service /etc/systemd/system/jailer.service
sudo systemctl daemon-reload
sudo systemctl enable --now jailer
journalctl -u jailer -f
```

Jailer needs permission to run `iptables` (root, or the appropriate capabilities). On startup it removes any leftover rules tagged `jailer:` so a restart never leaves stale bans behind.

## Example output

```text
<Program>: Starting Jailer application...
<Program>: Loading jail rules from /opt/jails.json
<HostService>: Starting up...
<LogMonitorService>: Starting monitoring for jail: sshd on file: /var/log/auth.log
<LogMonitorService>: Starting monitoring for jail: test on file: ./fakelogfile.log
<HostService>: Finished Start up
<IptablesService>: Cleaning up all Jailer-marked rules...
<IptablesService>: Cleanup complete. Removed 0 rules.

# ... after the third failed login from 203.0.113.7 ...

<LogMonitorService>: Violation detected for IP: 203.0.113.7 in jail sshd
<HostService>: Jailing IP: 203.0.113.7 due to log violation.
<IptablesService>: Jailed 203.0.113.7 in chain INPUT (target DROP).
<LogMonitorService>: IP 203.0.113.7 has been marked as jailed in 'sshd' until ...

# state summary, printed whenever the jail state changes:

sshd
  203.0.113.7  59 mins
test
  empty

# ... after the ban expires ...

<HostService>: Unjailing IP: 203.0.113.7 - expiration reached.
<IptablesService>: Unjailed 203.0.113.7.
sshd
  empty
test
  empty
```

## Limitations

- **iptables only.** No nftables or firewalld integration; the chain, target and executable are fixed to `INPUT` / `DROP`.
- **No persistent state.** Bans live in memory plus iptables rules. On restart Jailer removes its own leftover rules — a ban does not survive a reboot unless your firewall persists them independently.
- **Tail-only log reading.** Files are read from the end; if a file is rotated or truncated while running, monitoring of that jail stops until Jailer is restarted. Log rotation (e.g. `logrotate` with `copytruncate`) should be configured accordingly.
- **One process per host.** There is no clustering, web UI, or remote management — it is deliberately just the ban loop.
- **Attempt window is fixed** at 24 hours and not configurable per jail.

## Testing

A self-contained test harness lives in `Tester/` (no external test framework):

```bash
dotnet run --project Tester
# ALL CHECKS PASSED
```

It covers IP extraction, the fail2ban filter translation (`<HOST>`, `%(__prefix_line)s`, multi-line filters), end-to-end log monitoring with a fake log file, immediate violation callbacks, jail-state grouping/rendering, and attempt-window expiry.

## AI Assistant Config
this solution uses .github/copilot-instructions.md to hold its rules for AI agents and code assistance tools.

## License

[MIT](LICENSE) — see the [LICENSE](LICENSE) file. Copyright (c) 2026 Edward Collins.

---

*Built with qwen3.8.*
