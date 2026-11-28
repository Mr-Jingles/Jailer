# Jailer — Copilot Instructions

## What this project is

A small, single-binary .NET 8 reimplementation of fail2ban's core idea: tail log files for repeated failures and ban the offending IPv4 address with `iptables` until the ban expires. One trimmed, self-contained binary that runs as a systemd service on Linux and depends only on `iptables`. No Python runtime, no plugin system, no configuration sprawl — keep it that way.

## Architecture

- **Jails** are defined in a single JSON file (`jails.json`) next to the executable: each jail has `name`, `logFile`, `regex` (.NET regex or fail2ban filter syntax), `attempts`, and `banTime` (in **minutes**).
- **Program.cs** loads `jails.json` from `AppContext.BaseDirectory` using a source-generated JSON serializer (`JailerJsonContext`) — reflection-based configuration binding is deliberately avoided because the trimmer silently breaks it.
- **Fail2BanFilter** (`Services/Fail2BanFilter.cs`) translates fail2ban filter syntax — `<HOST>`, `%(__prefix_line)s` and other `%(...)s` variables, multi-line filters (each line an independent alternative) — into equivalent .NET regexes at startup. Plain .NET patterns pass through unchanged.
- **LogMonitorService** tails log files from the end, extracts IPv4 addresses from matched lines (`ExtractIp` prefers a parenthesised address — fail2ban's `<HOST>` convention for lines like `refused connect from X (Y)`), and accumulates per-IP attempt counts within a fixed 24-hour window.
- **HostService** wires its collaborators manually in the constructor (`ProcessCommandRunner` → `IptablesService`, plus `LogMonitorService`) and runs two independent `PeriodicTimer` loops: a 1-minute log check (safety net) and a 30-second expiry cleanup.
- On threshold breach the IP is jailed **immediately** via the `ViolationDetected` callback, which HostService handles in a detached `Task.Run` so iptables failures never block the log-reading loop. The rule: `iptables -I INPUT -s <ip> --comment jailer:<ip> DROP`. Rules are tagged with the `jailer:` comment so Jailer only ever removes its own entries; on startup it cleans up leftover `jailer:` rules.
- A cleanup loop releases bans at most 30 s after expiry and prints a per-jail state summary whenever state changes.

## Hard constraints — do not change without explicit request

- **No dependency injection** other than to bootstrap between `Program.cs` and `HostService.cs`. Wire services manually; don't introduce DI containers or constructor-injected service graphs beyond that one hop.
- **iptables only**, fixed to chain `INPUT`, target `DROP`. No nftables, no firewalld.
- **No persistent state.** Bans live in memory plus iptables rules; a restart removes Jailer's own leftover rules by design.
- **24-hour attempt window is fixed** and not configurable per jail.

## Not yet implemented (open for work, not design constraints)

- **Configurable iptables chain/target/executable.** `IptablesService` has an `IptablesOptions` class (defaults: `iptables` / `INPUT` / `DROP`) but the constructor hardcodes `_options = new IptablesOptions()` — nothing reads it from config yet. Note there is also a near-duplicate `IptablesSettings` in `Models/JailerOptions.cs`; consolidate if you touch this area.
- **Tail-only log reading.** Adding file rotation handling is fair game provided it can be done without making the program too much larger or slower.

## Conventions

- The logging types (`Log`, `Logger`, `ILogger`) are the project's **own minimal logger** in `Logger.cs` (namespace `Jailer`) — it is *not* NLog and there is no logging package reference. Levels are `Debug` / `Information` / `Warning` / `Error`; `Error` writes to stderr, the rest to stdout.
- Log output uses the `<ComponentName>: message` prefix style (e.g. `<HostService>:`, `<IptablesService>:`), produced by the logger's context. Follow it for new components.
- The logger takes a format string with **numbered tokens** — `{0}`, `{1}`, `{2}`, … — one per parameter passed, in order (i.e. `string.Format` style). Do not use named placeholders, arbitrary placeholder strings, or C# string interpolation (`$"..."`) to build log messages; pass the values as separate arguments instead.
- Child loggers are instantiated **per class** via the project's `Log.ForContext<T>()` — declare a field and assign it in the constructor:

  ```csharp
  private readonly ILogger _logger;

  // in the constructor:
  _logger = Log.ForContext<HostService>();
  ```

  Do not inject `ILogger` through DI or share one global logger instance across classes — each class gets its own contextual child logger.
- Tests can redirect all log output by setting the static **`Log.DefaultSink`** (`Action<string>`) to capture lines instead of writing to the console; `Tester/Program.cs` uses this both for quiet runs and to assert on logged messages.
- **Trim safety matters.** The publish pipeline trims aggressively; keep JSON deserialization on the source-generated `JailerJsonContext` and avoid APIs that rely on reflection over types the trimmer can't see (the code comments call this out — respect them).
- External process execution goes through the **`ICommandRunner`** abstraction (`ProcessCommandRunner` is the real implementation) so tests can substitute a fake runner. New shell-outs should go through it, not raw `Process`.
- A `PeriodicTimer` allows only one outstanding `WaitForNextTickAsync` at a time: use **one timer per loop**, never await the same timer instance concurrently (this caused an `InvalidOperationException`; Tester Part B guards against regressions).
- `LogMonitorService` derives from `BackgroundService` but is started manually via `StartMonitoringAsync()` by HostService — do **not** also register it as an `IHostedService`, or monitoring would start twice.
- Keep the binary self-contained: the only external package reference is `Microsoft.Extensions.Hosting`. No new dependencies, no plugin systems, no web UI or remote management. It is deliberately just the ban loop.

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

The `Tester/` project is the only test setup (it references `Jailer.csproj` directly); add new checks there rather than introducing a test framework. Follow its existing structure:

- Labeled sections (`Part A`, `Part B`, …) with a header comment describing what each covers; append new parts at the end.
- Assertions go through the local `Check(name, bool)` helper, which prints `PASS`/`FAIL  <name>` and counts failures.
- The final line must be exactly `ALL CHECKS PASSED` (or `N CHECK(S) FAILED`), and the process exit code is the failure count — keep both.
- Use the static test hooks instead of long real-time waits where possible: `Log.DefaultSink` to capture/assert log lines, and `LogMonitorService.AttemptWindow` (restore the original value afterwards).
- Scratch files go in a unique directory under `Path.GetTempPath()` (`jailer-tester-<guid>`) and are deleted when done.
