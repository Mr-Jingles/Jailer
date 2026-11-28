using System.Text;

namespace Jailer
{
    public static class Log
    {
        /// <summary>When set, all log output is routed here instead of the console (used by tests).</summary>
        public static Action<string>? DefaultSink { get; set; }

        public static Logger ForContext<T>()
        {
            var logger = new Logger(typeof(T).Name);
            return logger;
        }
    }

    public interface ILogger
    {
        public void Debug(string message, params object[] data);

        public void Information(string message, params object[] data);

        public void Warning(string message, params object[] data);

        public void Error(string message, params object[] data);
    }


    public class Logger : ILogger
    {
        private readonly string? _context;

        public Logger(string? context)
        {
            _context = context;
        }

        private static void Write(string output, bool isError = false)
        {
            if (Log.DefaultSink != null)
            {
                Log.DefaultSink(output);
                return;
            }

            if (isError)
            {
                Console.Error.WriteLine(output);
            }
            else
            {
                Console.WriteLine(output);
            }
        }

        public void Debug(string message, params object[] data) => Write(processMessage(message, data));

        public void Information(string message, params object[] data) => Write(processMessage(message, data));

        public void Warning(string message, params object[] data) => Write(processMessage(message, data));

        public void Error(string message, params object[] data) => Write(processMessage(message, data), isError: true);

        private string processMessage(string message, params object[] data)
        {
            var sb = new StringBuilder();

            if (_context != null)
            {
                sb.Append(" <");
                sb.Append(_context);
                sb.Append(">: ");
            }

            sb.Append(message);

            var output = sb.ToString();
            output = String.Format(output, data);

            return output;
        }
    }
}
