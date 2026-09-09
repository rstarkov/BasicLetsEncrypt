using System;
using System.IO;

namespace BasicLetsEncrypt;

class CmdLine
{
    /// <summary>Full path to the config file describing the certificate.</summary>
    public string ConfigPath;

    /// <summary>
    ///     Parses the command line. Returns null after writing usage information (and the error, if any) to the console if
    ///     the arguments are invalid or help was requested.</summary>
    public static CmdLine Parse(string[] args)
    {
        if (args.Length == 1 && (args[0] == "-?" || args[0] == "--help" || args[0] == "/?"))
        {
            PrintUsage();
            return null;
        }

        string error = null;
        if (args.Length == 0)
            error = "The parameter <ConfigPath> is mandatory and must be specified.";
        else if (args[0].StartsWith("-"))
            error = $"The specified command or option, {args[0]}, is not recognized.";
        else if (args.Length > 1)
            error = $"Unexpected parameter: {args[1]}";

        if (error != null)
        {
            PrintUsage();
            Console.WriteLine();
            Console.WriteLine($"Error: {error}");
            return null;
        }

        return new CmdLine { ConfigPath = Path.GetFullPath(args[0]) };
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: BasicLetsEncrypt <ConfigPath>");
        Console.WriteLine();
        Console.WriteLine("Obtains or renews an SSL certificate via LetsEncrypt using manual DNS validation.");
        Console.WriteLine();
        Console.WriteLine("Required parameters:");
        Console.WriteLine();
        Console.WriteLine("   <ConfigPath>   Path to the config file describing the certificate.");
        Console.WriteLine("                  Output files are created in the same directory and with the same file name as the config file");
        Console.WriteLine("                  (varying extensions). If this config file does not exist, a template file is created and the");
        Console.WriteLine("                  program exits with an error.");
    }
}
