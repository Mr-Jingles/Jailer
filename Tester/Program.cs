using System.Text.RegularExpressions;
using Jailer;
using Jailer.Models;
using Jailer.Services;
using Microsoft.Extensions.Options;

// Route service log output into a list instead of the console (also lets us assert on it).
var capturedLogs = new List<string>();
var logLock = new object();
Log.DefaultSink = line => { lock (logLock) { capturedLogs.Add(line); } };

string? LastLogContaining(string fragment)
{
    lock (logLock)
    {
        for (var i = capturedLogs.Count - 1; i >= 0; i--)
        {
            if (capturedLogs[i].Contains(fragment, StringComparison.Ordinal)) return capturedLogs[i];
        }
    }
    return null;
}

var failures = 0;

void Check(string name, bool condition)
{
    Console.WriteLine($"{(condition ? "PASS" : "FAIL")}  {name}");
    if (!condition) failures++;
}

// ---------------------------------------------------------------------------
// Part A: IP extraction — the same regex LogMonitorService uses.
// ---------------------------------------------------------------------------
var ipRe = new Regex(
    @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    RegexOptions.Compiled);

string? Extract(string line) => ipRe.Match(line).Success ? ipRe.Match(line).Value : null;

Check("extracts IP from 'Test log 10.20.30.40'", Extract("Test log 10.20.30.40") == "10.20.30.40");
Check("extracts IP from sshd failed-password line",
    Extract("Jan 15 10:23:45 host sshd[123]: Failed password for root from 192.168.1.5 port 22 ssh2") == "192.168.1.5");
Check("extracts IP from preauth line",
    Extract("Connection closed by authenticating user baduser 203.0.113.7 port 4242 [preauth]") == "203.0.113.7");
Check("no false positive on text without an IP", Extract("no ip here at all") is null);
Check("rejects invalid octet 999.1.2.3", Extract("bad 999.1.2.3 line") is null);
Check("first of two IPs wins", Extract("two ips 8.8.8.8 and 1.1.1.1") == "8.8.8.8");

// ---------------------------------------------------------------------------
// Part B: PeriodicTimer pattern — the fixed HostService shape (one outstanding
// wait per timer) must not throw InvalidOperationException over many ticks.
// ---------------------------------------------------------------------------
var timerOk = true;
try
{
    using var t1 = new PeriodicTimer(TimeSpan.FromMilliseconds(20));
    using var t2 = new PeriodicTimer(TimeSpan.FromMilliseconds(35));

    var cts = new CancellationTokenSource();
    var loopA = Task.Run(async () => { while (await t1.WaitForNextTickAsync(cts.Token)) { } });
    var loopB = Task.Run(async () => { while (await t2.WaitForNextTickAsync(cts.Token)) { } });

    await Task.Delay(300);
    cts.Cancel();
    await Task.WhenAll(loopA, loopB).ContinueWith(_ => { });
}
catch (Exception ex)
{
    timerOk = false;
    Console.WriteLine($"        timer exception: {ex.GetType().Name}: {ex.Message}");
}
Check("two independent PeriodicTimer loops run without InvalidOperationException", timerOk);

// ---------------------------------------------------------------------------
// Part C: LogMonitorService end-to-end — feed a fake log file and confirm the
// violated IP is extracted cleanly (no 'Test log ...' garbage).
// ---------------------------------------------------------------------------
var dir = Path.Combine(Path.GetTempPath(), "jailer-tester-" + Guid.NewGuid().ToString("n"));
Directory.CreateDirectory(dir);
var logFile = Path.Combine(dir, "fakelogfile.log");

// Create the file up front so the monitor (which seeks to end) starts reading immediately.
File.WriteAllText(logFile, string.Empty);

var options = Options.Create(new JailerOptions
{
    Jails = new List<JailRule>
    {
        new() { Name = "test", LogFile = logFile, Regex = @"Test.*", Attempts = 2, BanTime = 1 }
    }
});

using var monitorCts = new CancellationTokenSource();
var monitor = new LogMonitorService(options);
var monitorTask = monitor.StartMonitoringAsync(monitorCts.Token);

await Task.Delay(500); // let the monitoring loop start reading

File.AppendAllText(logFile, "Test log 10.20.30.40\n");
await Task.Delay(800);
File.AppendAllText(logFile, "Test log 10.20.30.40\n");
await Task.Delay(800);

var violated = monitor.GetViolatedIps().ToList();
Check("violation detected", violated.Count == 1);
Check($"violated IP is clean (got: [{string.Join(", ", violated)}])", violated.Contains("10.20.30.40"));

// A line matching the rule but with no valid IP must not produce a violation entry.
File.AppendAllText(logFile, "Test log without any address\n");
await Task.Delay(800);
var after = monitor.GetViolatedIps().ToList();
Check("line without an IP does not create a violated entry", after.Count == 0);

monitorCts.Cancel();
try { await monitorTask; } catch (OperationCanceledException) { }

Directory.Delete(dir, recursive: true);

// ---------------------------------------------------------------------------
// Part D: fail2ban filter translation (<HOST>, %(...)s variables, multi-line).
// ---------------------------------------------------------------------------
var sshdLine = "Jan 15 10:23:45 myhost sshd[123]: Failed password for invalid user admin from 192.168.1.5 port 22 ssh2";

Check("<HOST> matches an IPv4 address",
    Fail2BanFilter.Compile(@"^.*Failed \S+ for .*? from <HOST>(?: port \d*)?(?: ssh\d*)?\s*$").IsMatch(sshdLine));
Check("<HOST> rejects a line without an IPv4 address",
    !Fail2BanFilter.Compile(@"^.*from <HOST>\s*$").IsMatch("Jan 15 10:23:45 myhost sshd[1]: Failed password for root from ::1 port 22"));
Check("%(__prefix_line)s matches a syslog prefix",
    Fail2BanFilter.Compile(@"%(__prefix_line)s sshd\[1\]: message").IsMatch("Jan 15 10:23:45 myhost sshd[1]: message"));
Check("unknown %(...)s variables become wildcards",
    Fail2BanFilter.Compile(@"^.*%(md5hex)s from .*$").IsMatch(sshdLine));

// The real multi-line sshd filter from jails.json must compile and match typical auth.log lines.
var sshdFilter = "^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error) for .*? from <HOST>( via \\S+)?(?: port \\d*)?(?: ssh\\d*)?\\s*$\n^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\\s*$\n^%(__prefix_line)sFailed \\S+ for .*? from <HOST>(?: port \\d*)?(?: ssh\\d*)?(: (ruser .*|(\\S+ ID \\S+ \\(serial \\d+\\) CA )?\\S+ %(__md5hex)s(, client user \".*\", client host \".*\")?))?\\s*$\n^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>(?:\\s+\\S+)?\\s*$\n^%(__prefix_line)s[iI\n](?:llegal|nvalid) user .* from <HOST>(?: port \\d*)?\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because not listed in AllowUsers\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because listed in DenyUsers\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because not in any group\\s*$\n^%(__prefix_line)srefused connect from \\S+ \\(<HOST>\\)\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because a group is listed in DenyGroups\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because none of user's groups are listed in AllowGroups\\s*$";
var compiledSshd = Fail2BanFilter.Compile(sshdFilter); // throws if invalid
Check("multi-line sshd filter compiles", compiledSshd is not null);
var sshdRegex = compiledSshd!;
//remove this console writeline once tester is working again
Console.WriteLine("sshdRegex is " + sshdRegex);
Check("sshd filter matches 'Failed password' line", sshdRegex.IsMatch(sshdLine));
Check("sshd filter matches 'Invalid user' line (bracket class spans two lines)",
    sshdRegex.IsMatch("Jan 15 10:24:01 myhost sshd[99]: Invalid user bob from 203.0.113.7 port 443"));
Check("sshd filter rejects unrelated lines", !sshdRegex.IsMatch("Jan 15 10:25:00 myhost CRON[5]: pam_unix(cron:session): session opened for user root"));

// A plain .NET pattern must pass through unchanged.
Check("plain .NET patterns are unaffected", Fail2BanFilter.Compile(@"Test.*").IsMatch("Test log 10.20.30.40"));

// ---------------------------------------------------------------------------
// Part E: violation callback fires immediately (no periodic-tick wait).
// ---------------------------------------------------------------------------
var dirE = Path.Combine(Path.GetTempPath(), "jailer-tester-" + Guid.NewGuid().ToString("n"));
Directory.CreateDirectory(dirE);
var logFileE = Path.Combine(dirE, "fakelogfile.log");
File.WriteAllText(logFileE, string.Empty);

var ruleE = new JailRule { Name = "test", LogFile = logFileE, Regex = @"Test.*", Attempts = 2, BanTime = 1 };
using var monitorCtsE = new CancellationTokenSource();
var monitorE = new LogMonitorService(Options.Create(new JailerOptions { Jails = new List<JailRule> { ruleE } }));

var callbackHits = new List<(string Ip, string Jail)>();
var cbLock = new object();
var cbTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
monitorE.ViolationDetected = (ip, rule) =>
{
    lock (cbLock) { callbackHits.Add((ip, rule.Name)); }
    cbTcs.TrySetResult();
};

var monitorTaskE = monitorE.StartMonitoringAsync(monitorCtsE.Token);
await Task.Delay(500);

File.AppendAllText(logFileE, "Test log 10.20.30.40\n");
await Task.Delay(800);
var firedAfterFirst = false; lock (cbLock) { firedAfterFirst = callbackHits.Count > 0; }
Check("no callback before threshold reached", !firedAfterFirst);

File.AppendAllText(logFileE, "Test log 10.20.30.40\n");
var fired = await Task.WhenAny(cbTcs.Task, Task.Delay(3000)) == cbTcs.Task;
Check("ViolationDetected fires immediately on threshold (no tick wait)", fired);

string? hitIp = null; string? hitJail = null;
lock (cbLock) { if (callbackHits.Count > 0) { hitIp = callbackHits[0].Ip; hitJail = callbackHits[0].Jail; } }
Check($"callback carries IP and jail (got: [{hitIp}] in [{hitJail}])", hitIp == "10.20.30.40" && hitJail == "test");

monitorCtsE.Cancel();
try { await monitorTaskE; } catch (OperationCanceledException) { }
Directory.Delete(dirE, recursive: true);

// ---------------------------------------------------------------------------
// Part F: jail state is grouped per jail and renders in the required shape.
// ---------------------------------------------------------------------------
var ruleF1 = new JailRule { Name = "sshd", LogFile = "/var/log/auth.log", Regex = @"Failed.*", Attempts = 3, BanTime = 60 };
var ruleF2 = new JailRule { Name = "test", LogFile = "./fakelogfile.log", Regex = @"Test.*", Attempts = 2, BanTime = 1 };
var monitorF = new LogMonitorService(Options.Create(new JailerOptions { Jails = new List<JailRule> { ruleF1, ruleF2 } }));

monitorF.MarkAsJailed("10.20.30.40", ruleF1);
monitorF.MarkAsJailed("198.51.100.7", ruleF2);
monitorF.MarkAsJailed("203.0.113.9", ruleF2);

var state = monitorF.GetJailState();
Check("state grouped by jail name", state.ContainsKey("sshd") && state.ContainsKey("test"));
Check("sshd holds exactly its own IP", state["sshd"].Count == 1 && state["sshd"][0].Ip == "10.20.30.40");
Check("test holds both of its IPs", state["test"].Count == 2);

// Render the exact shape required by testResults.md and verify it line by line.
var now = DateTime.UtcNow;
var rendered = new List<string>();
foreach (var jail in new[] { ruleF1, ruleF2 })
{
    rendered.Add(jail.Name);
    if (state.TryGetValue(jail.Name, out var entries) && entries.Count > 0)
    {
        foreach (var (ip, expiresUtc) in entries.OrderBy(e => e.Ip, StringComparer.OrdinalIgnoreCase))
        {
            var minutes = Math.Max(1, (int)Math.Ceiling((expiresUtc - now).TotalMinutes));
            rendered.Add($"  {ip}  {minutes} mins");
        }
    }
    else
    {
        rendered.Add("  empty");
    }
}

var expected = new List<string>
{
    "sshd",
    $"  10.20.30.40  {(int)Math.Ceiling((state["sshd"][0].ExpiresUtc - now).TotalMinutes)} mins",
    "test",
    $"  198.51.100.7  {(int)Math.Ceiling((now.AddMinutes(1) - now).TotalMinutes)} mins",
    $"  203.0.113.9  {(int)Math.Ceiling((now.AddMinutes(1) - now).TotalMinutes)} mins",
};
Check("rendered state matches the required format", rendered.SequenceEqual(expected));

// A jail with no entries renders as 'empty'.
var monitorF2 = new LogMonitorService(Options.Create(new JailerOptions { Jails = new List<JailRule> { ruleF1 } }));
var emptyState = monitorF2.GetJailState();
Check("unjailed jail has no entries (renders 'empty')", !emptyState.ContainsKey("sshd") || emptyState["sshd"].Count == 0);

// ---------------------------------------------------------------------------
// Part G: attempt counts older than the window are dropped.
// ---------------------------------------------------------------------------
var originalWindow = LogMonitorService.AttemptWindow;
LogMonitorService.AttemptWindow = TimeSpan.FromSeconds(1);

var dirG = Path.Combine(Path.GetTempPath(), "jailer-tester-" + Guid.NewGuid().ToString("n"));
Directory.CreateDirectory(dirG);
var logFileG = Path.Combine(dirG, "fakelogfile.log");
File.WriteAllText(logFileG, string.Empty);

using var monitorCtsG = new CancellationTokenSource();
var monitorG = new LogMonitorService(Options.Create(new JailerOptions
{
    Jails = new List<JailRule> { new() { Name = "window", LogFile = logFileG, Regex = @"Test.*", Attempts = 3, BanTime = 1 } }
}));

var monitorTaskG = monitorG.StartMonitoringAsync(monitorCtsG.Token);
await Task.Delay(500);

File.AppendAllText(logFileG, "Test log 10.20.30.40\n");
await Task.Delay(800);
Check("first attempt counted as 1/3", LastLogContaining("Count: 1/3") != null);

// Let the window expire so the next attempt must start a fresh count.
await Task.Delay(1500);
File.AppendAllText(logFileG, "Test log 10.20.30.40\n");
await Task.Delay(800);
var lastCount = LastLogContaining("matched pattern in jail window. Count:");
Check($"stale count was dropped (last line: {lastCount?.Trim() ?? "none"})",
    lastCount != null && lastCount.Contains("1/3", StringComparison.Ordinal) && !lastCount.Contains("2/3", StringComparison.Ordinal));

monitorCtsG.Cancel();
try { await monitorTaskG; } catch (OperationCanceledException) { }
Directory.Delete(dirG, recursive: true);
LogMonitorService.AttemptWindow = originalWindow;

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CHECKS PASSED" : $"{failures} CHECK(S) FAILED");
return failures;
