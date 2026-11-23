## The todo list

1. Define configuration model — log file path(s), regex pattern, match threshold, jail duration, iptables chain/table settings
1. Build Linux command runner helper — execute iptables (and log commands) via System.Diagnostics.Process, capture output/errors
1. Implement log matching + IP extraction — read new log lines and apply the configured regex to extract the offending IP
1. Add per-IP match counting/threshold logic — count matches per IP over a window; trigger when threshold is reached
1. Build iptables jail/unjail with rule marker — insert DROP/REJECT rules tagged with a unique comment/marker so Jailer can identify its own entries
1. Track active jails and expiry state — in-memory registry of jailed IPs with their expiry timestamps
1. Schedule automatic unjailing on expiry — background timer that removes each rule when its period elapses
1. Implement shutdown cleanup — on service stop, remove all Jailer-marked iptables entries regardless of remaining time
1. Wire up Program.cs entry point + DI — Microsoft.Extensions.Hosting generic host with the services registered
1. Build and validate end-to-end behavior — compile and verify the flow works

## jail format

5 properties jail name, jail regex (defines an error log from a normal log), no of attempts (before jailing), time to jail for (in minutes), location of log file (to run the regex across)