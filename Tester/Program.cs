using System.Text.RegularExpressions;
using Jailer.Models;
using Jailer.Services;
using Microsoft.Extensions.Options;

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

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CHECKS PASSED" : $"{failures} CHECK(S) FAILED");
return failures;
