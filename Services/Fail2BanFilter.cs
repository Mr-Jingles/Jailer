using System.Text.RegularExpressions;

namespace Jailer.Services
{
    /// <summary>
    /// Translates fail2ban filter syntax into a .NET regular expression.
    ///
    /// Supported constructs (mirroring fail2ban's default definitions):
    ///   &lt;HOST&gt;             -> an IPv4 address pattern (same octet logic as the IP extractor)
    ///   %(__prefix_line)s   -> "month day time" plus any host/tag tokens that follow, e.g.
    ///                          "Jan 15 10:23:45 myhost sshd[123]: " (the lazy token run stops as
    ///                          soon as the rest of the filter can match)
    ///   %(varname)s         -> .*?                    (any other fail2ban variable becomes a wildcard)
    ///
    /// Multi-line filters follow fail2ban semantics: each line is an independent alternative,
    /// so the lines are joined with '|' into one big alternation. Lines are only split when the
    /// square/parenthesis brackets are balanced, which keeps constructs such as "[iI\n]" (a
    /// character class spanning two physical lines) intact.
    /// </summary>
    public static class Fail2BanFilter
    {
        private const string HostPattern =
            @"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)";

        // fail2ban's __prefix_line is "month day time host" — but real syslog lines carry the
        // program tag after the hostname ("Jan 15 10:23:45 myhost sshd[123]: Failed ..."), so we
        // match the timestamp and then let a lazy run of 'token' consume whatever host/tag tokens
        // precede the message. Each token is followed by its trailing whitespace (consumed, so
        // filters that start with their own literal space still work); the ':' after a tag such as
        // "sshd[123]:" is part of the token itself (\S). The laziness guarantees we stop as early
        // as the filter allows. Each iteration consumes at least one non-space character, so the
        // repetition cannot backtrack exponentially.
        private const string PrefixLinePattern =
            @"(?:\S+\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+)(?:\S+:?\s+|\S+$)*?";

        private static readonly Regex VariableRegex = new(@"%\((?<name>[A-Za-z_][A-Za-z0-9_]*)\)s", RegexOptions.Compiled);
        private static readonly Regex HostPlaceholderRegex = new(@"<HOST>", RegexOptions.Compiled);

        /// <summary>Translates a fail2ban-style filter into an equivalent .NET regex pattern.</summary>
        public static string Translate(string filter)
        {
            if (string.IsNullOrWhiteSpace(filter))
            {
                return string.Empty;
            }

            var lines = SplitAlternatives(filter);
            var translated = lines.Select(TranslateLine).Where(l => l.Length > 0).ToList();
            return string.Join("|", translated);
        }

        /// <summary>Compiles a fail2ban-style filter for matching. Throws on invalid patterns.</summary>
        public static Regex Compile(string filter) => new(Translate(filter), RegexOptions.Multiline | RegexOptions.Compiled);

        private static string TranslateLine(string line)
        {
            var translated = VariableRegex.Replace(line, match =>
            {
                var name = match.Groups["name"].Value;
                return name == "__prefix_line" ? PrefixLinePattern : ".*?";
            });

            return HostPlaceholderRegex.Replace(translated, HostPattern);
        }

        /// <summary>
        /// Splits a filter into its per-line alternatives. A newline only starts a new
        /// alternative when the brackets seen so far are balanced; otherwise it is part of
        /// the current line (e.g. inside a character class).
        /// </summary>
        private static IEnumerable<string> SplitAlternatives(string filter)
        {
            var current = new System.Text.StringBuilder();
            var depth = 0;
            var escaped = false;

            foreach (var ch in filter)
            {
                if (ch == '\r')
                {
                    continue; // normalize CRLF to LF before deciding on a split
                }

                if (ch == '\n')
                {
                    if (depth <= 0)
                    {
                        yield return current.ToString().Trim();
                        current.Clear();
                    }
                    else
                    {
                        current.Append(ch); // keep the newline inside the open bracket expression
                    }

                    escaped = false;
                    continue;
                }

                if (escaped)
                {
                    current.Append(ch);
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    current.Append(ch);
                    escaped = true;
                    continue;
                }

                switch (ch)
                {
                    case '[': depth++; break;
                    case ']': if (depth > 0) depth--; break;
                }

                current.Append(ch);
            }

            yield return current.ToString().Trim();
        }
    }
}
