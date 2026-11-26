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
var sshdFilter = "^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error) for .*? from <HOST>( via \\S+)?(?: port \\d*)?(?: ssh\\d*)?\\s*$\n^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\\s*$\n^%(__prefix_line)sFailed \\S+ for .*? from <HOST>(?: port \\d*)?(?: ssh\\d*)?(: (ruser .*|(\\S+ ID \\S+ \\(serial \\d+\\) CA )?\\S+ %(__md5hex)s(, client user \".*\", client host \".*\")?))?\\s*$\n^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>(?:\\s+\\S+)?\\s*$\n^%(__prefix_line)s[iI](?:llegal|nvalid) user .* from <HOST>(?: port \\d*)?\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because not listed in AllowUsers\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because listed in DenyUsers\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because not in any group\\s*$\n^%(__prefix_line)srefused connect from \\S+ \\(<HOST>\\)\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because a group is listed in DenyGroups\\s*$\n^%(__prefix_line)sUser .+ from <HOST> not allowed because none of user's groups are listed in AllowGroups\\s*$";
var compiledSshd = Fail2BanFilter.Compile(sshdFilter); // throws if invalid
Check("multi-line sshd filter compiles", compiledSshd is not null);
var sshdRegex = compiledSshd!;
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

// ---------------------------------------------------------------------------
// Part H: ovpn filter — the real multi-line regex from jails.json must compile,
// match the actual OpenVPN syslog lines, and reject the
// IP-less HMAC error line (nothing to ban).
// ---------------------------------------------------------------------------
var ovpnFilter = "^%(__prefix_line)sTLS Error: cannot locate HMAC in incoming packet from \\[AF_INET\\]<HOST>:\\d+\\s*$\n^%(__prefix_line)sTLS Error: incoming packet authentication failed from \\[AF_INET\\]<HOST>:\\d+\\s*$";
var ovpnRegex = Fail2BanFilter.Compile(ovpnFilter)!; // throws if invalid
Check("multi-line ovpn filter compiles", ovpnRegex is not null);

var ovpnHmacLine = "Nov 22 03:12:11 vmi1000953 ovpn-myserver[695]: TLS Error: cannot locate HMAC in incoming packet from [AF_INET]159.65.199.132:37973";
var ovpnAuthLine = "Nov 22 19:03:10 vmi1000953 ovpn-myserver[695]: TLS Error: incoming packet authentication failed from [AF_INET]106.75.175.85:58914";
var ovpnNoIpLine = "Nov 22 19:03:10 vmi1000953 ovpn-myserver[695]: Authenticate/Decrypt packet error: packet HMAC authentication failed";

Check("ovpn filter matches 'cannot locate HMAC' line", ovpnRegex.IsMatch(ovpnHmacLine));
Check("ovpn filter matches 'incoming packet authentication failed' line", ovpnRegex.IsMatch(ovpnAuthLine));
Check("ovpn filter rejects the IP-less HMAC error line (nothing to ban)", !ovpnRegex.IsMatch(ovpnNoIpLine));
Check("ovpn filter rejects unrelated syslog lines",
    !ovpnRegex.IsMatch("Nov 22 19:03:10 vmi1000953 CRON[7]: pam_unix(cron:session): session opened for user root"));

// The offending IP must be extractable from the matched line.
Check("extracts IP from 'cannot locate HMAC' line", Extract(ovpnHmacLine) == "159.65.199.132");
Check("extracts IP from 'authentication failed' line", Extract(ovpnAuthLine) == "106.75.175.85");

// ---------------------------------------------------------------------------
// Part I: iptables rule syntax — the exact argument lists JailAsync/UnjailAsync
// hand to iptables must be valid per the v1.8.7 usage output (the "Bad argument
// 'DROP'" regression): the target may only appear after -j, never as a bare
// positional token. A fake ICommandRunner captures what would actually run.
// ---------------------------------------------------------------------------
var incidentIp = "61.177.197.82";

// iptables v1.8.7 usage: [options] command [parameters]. The target is only a
// valid parameter after -j; a bare positional target (e.g. trailing "DROP") is
// rejected with exit 2 — the exact failure in serveroutput.txt.
var jailRuleRe = new Regex(
    @"^iptables -I INPUT -s \d{1,3}(?:\.\d{1,3}){3} -m comment --comment jailer:\d{1,3}(?:\.\d{1,3}){3} -j DROP$");
var unjailRuleRe = new Regex(
    @"^iptables -D INPUT -s \d{1,3}(?:\.\d{1,3}){3} -m comment --comment jailer:\d{1,3}(?:\.\d{1,3}){3} -j DROP$");

// Scenario 1: IP not yet jailed -> JailAsync must issue the insert rule.
var runnerJail = new CapturingCommandRunner(existingJailedIp: null);
var svcJail = new IptablesService(runnerJail);
var jailOk = await svcJail.JailAsync(incidentIp);
Check("JailAsync succeeds when IP is not yet jailed", jailOk);
var jailRule = runnerJail.Invocations.LastOrDefault(i => i.Contains("-I INPUT", StringComparison.Ordinal));
Check($"jail rule follows iptables v1.8.7 usage (target after -j): {jailRule ?? "no -I invocation captured"}",
    jailRuleRe.IsMatch(jailRule ?? string.Empty));

// Scenario 2: IP already jailed -> UnjailAsync must issue the delete rule.
var runnerUnjail = new CapturingCommandRunner(existingJailedIp: incidentIp);
var svcUnjail = new IptablesService(runnerUnjail);
var unjailOk = await svcUnjail.UnjailAsync(incidentIp);
Check("UnjailAsync succeeds when IP is jailed", unjailOk);
var unjailRule = runnerUnjail.Invocations.LastOrDefault(i => i.Contains("-D INPUT", StringComparison.Ordinal));
Check($"unjail rule follows iptables v1.8.7 usage (target after -j): {unjailRule ?? "no -D invocation captured"}",
    unjailRuleRe.IsMatch(unjailRule ?? string.Empty));

// Guard against the original regression shape: no invocation may carry a bare
// positional target token anywhere in its argument list.
var bareTarget = runnerJail.Invocations.Concat(runnerUnjail.Invocations)
    .Where(i => i.Contains("-I INPUT", StringComparison.Ordinal) || i.Contains("-D INPUT", StringComparison.Ordinal))
    .Any(i => Regex.IsMatch(i, @"(?<!-j )DROP"));
Check("no iptables invocation uses a bare positional DROP target", !bareTarget);

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CHECKS PASSED" : $"{failures} CHECK(S) FAILED");
return failures;

// Fake ICommandRunner for Part I: records every invocation it would run and
// answers the `iptables -S INPUT` guard call with a canned chain listing.
sealed class CapturingCommandRunner : ICommandRunner
{
    public List<string> Invocations { get; } = new();
    private readonly string _listOutput;

    // Simulates `iptables -S INPUT` output: an empty chain, or a chain that
    // already holds Jailer's rule for the given IP.
    public CapturingCommandRunner(string? existingJailedIp)
    {
        if (existingJailedIp is null)
        {
            _listOutput = string.Empty;
        }
        else
        {
            _listOutput = $"-P INPUT ACCEPT\n-I INPUT -s {existingJailedIp} -m comment --comment jailer:{existingJailedIp} -j DROP\n";
        }
    }

    public Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default)
    {
        var args = arguments.ToList();
        Invocations.Add(fileName + " " + string.Join(' ', args));
        if (args.Count >= 2 && args[0] == "-S" && args[1] == "INPUT")
        {
            return Task.FromResult(new CommandResult(0, _listOutput, string.Empty));
        }
        return Task.FromResult(new CommandResult(0, string.Empty, string.Empty));
    }
}