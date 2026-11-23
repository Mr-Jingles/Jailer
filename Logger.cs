using System.Text;

namespace Jailer
{
    public static class Log
    {
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

        public void Debug(string message, params object[] data)
        {
            Console.WriteLine(processMessage(message, data));
        }

        public void Information(string message, params object[] data)
        {
            Console.WriteLine(processMessage(message));
        }

        public void Warning(string message, params object[] data)
        {
            Console.WriteLine(processMessage(message));
        }

        public void Error(string message, params object[] data)
        {
            Console.Error.WriteLine(processMessage(message));
        }

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
            string.Format(output, data);

            return output;
        }
    }
}
