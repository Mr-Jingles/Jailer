# Jailer — Copilot Instructions

## What this project is

A small, single-binary .NET 8 reimplementation of fail2ban's core idea: tail log files for repeated failures and ban the offending IPv4 address with `iptables` until the ban expires. One trimmed, self-contained binary that runs as a systemd service on Linux and depends only on `iptables`. No Python runtime, no plugin system, no configuration sprawl — keep it that way.

## Architecture (from README)

- **Jails** are defined in a single JSON file (`jails.json`) next to the executable: each jail has `name`, `logFile`, `regex` (.NET regex or fail2ban filter syntax), `attempts`, and `banTime` (in **minutes**).
- **Fail2BanFilter** (`Services/Fail2BanFilter.cs`) translates fail2ban filter syntax — `<HOST>`, `%(__prefix_line)s` and other `%(...)s` variables, multi-line filters (each line an independent alternative) — into equivalent .NET regexes at startup.
- **LogMonitorService** tails log files from the end, extracts IPv4 addresses from matched lines, and accumulates per-IP attempt counts within a fixed 24-hour window.
- On threshold breach the IP is jailed immediately: `iptables -I INPUT -s <ip> --comment jailer:<ip> DROP`. Rules are tagged with the `jailer:` comment so Jailer only ever removes its own entries; on startup it cleans up leftover `jailer:` rules.
- A cleanup loop releases bans at most 30 s after expiry and prints a per-jail state summary whenever state changes.

## Hard constraints — do not change without explicit request

- **No dependency injection** other than to bootstrap between `Program.cs` and `HostService.cs`. Wire services manually; don't introduce DI containers or constructor-injected service graphs beyond that one hop.
- **iptables only**, fixed to chain `INPUT`, target `DROP`. No nftables, no firewalld.
- **No persistent state.** Bans live in memory plus iptables rules; a restart removes Jailer's own leftover rules by design.
- **Tail-only log reading.** Don't add full-file scanning or rotation handling beyond what exists.
- **24-hour attempt window is fixed** and not configurable per jail.

## Not yet implemented (open for work, not design constraints)

- **IPv6 / `ip6tables` support.** Currently IPv4 only — this is a missing feature, not a forbidden direction; implementing it is fair game when asked.

## Conventions

- Log output uses the `<ComponentName>: message` prefix style (e.g. `<HostService>:`, `<IptablesService>:`). Follow it for new components.
- The logger takes a format string with **numbered tokens** — `{0}`, `{1}`, `{2}`, … — one per parameter passed, in order (i.e. `string.Format` style). Do not use named placeholders, arbitrary placeholder strings, or C# string interpolation (`$"..."`) to build log messages; pass the values as separate arguments instead.
- Child loggers are instantiated **per class** via Log's context API — declare a field and assign it in the constructor:

  ```csharp
  private readonly ILogger _logger;

  // in the constructor:
  _logger = Log.ForContext<HostService>();
  ```

  Do not inject `ILogger` through DI or share one global logger instance across classes — each class gets its own contextual child logger.
- Keep the binary self-contained: no new external dependencies, no plugin systems, no web UI or remote management. It is deliberately just the ban loop.

## Build & test

```bash
# Run locally (any OS)
dotnet run --project Jailer.csproj

# Publish trimmed single-file Linux x64 binary
dotnet publish Jailer.csproj -c Release -r linux-x64 \
    --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true

# Self-contained test harness (no external test framework) — must print "ALL CHECKS PASSED"
dotnet run --project Tester
```

The `Tester/` project is the only test setup; add new checks there rather than introducing a test framework.
