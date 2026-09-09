using System;
using System.IO;

namespace BasicLetsEncrypt;

enum ChallengeMode
{
    /// <summary>DNS-01 challenge; the user creates the TXT record manually.</summary>
    Dns,
    /// <summary>HTTP-01 challenge; the user places the challenge file on the web server manually.</summary>
    Http,
    /// <summary>HTTP-01 challenge served by this program on port 80.</summary>
    HttpAuto,
}

class CmdLine
{
    /// <summary>Full path to the config file describing the certificate.</summary>
    public string ConfigPath;

    /// <summary>How the domain is to be validated. Defaults to <see cref="ChallengeMode.Dns"/>.</summary>
    public ChallengeMode Mode = ChallengeMode.Dns;

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

        var cmd = new CmdLine();
        var modeSpecified = false;
        string error = null;
        foreach (var arg in args)
        {
            if (arg == "--dns" || arg == "--http" || arg == "--http-auto")
            {
                if (modeSpecified)
                {
                    error = "Only one of --dns, --http and --http-auto may be specified.";
                    break;
                }
                modeSpecified = true;
                cmd.Mode = arg == "--dns" ? ChallengeMode.Dns : arg == "--http" ? ChallengeMode.Http : ChallengeMode.HttpAuto;
            }
            else if (arg.StartsWith("-"))
            {
                error = $"The specified command or option, {arg}, is not recognized.";
                break;
            }
            else if (cmd.ConfigPath != null)
            {
                error = $"Unexpected parameter: {arg}";
                break;
            }
            else
                cmd.ConfigPath = Path.GetFullPath(arg);
        }
        if (error == null && cmd.ConfigPath == null)
            error = "The parameter <ConfigPath> is mandatory and must be specified.";

        if (error != null)
        {
            PrintUsage();
            Console.WriteLine();
            Console.WriteLine($"Error: {error}");
            return null;
        }

        return cmd;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: BasicLetsEncrypt <ConfigPath> [--dns|--http|--http-auto]");
        Console.WriteLine();
        Console.WriteLine("Obtains or renews an SSL certificate via LetsEncrypt using DNS or HTTP validation.");
        Console.WriteLine();
        Console.WriteLine("Required parameters:");
        Console.WriteLine();
        Console.WriteLine("   <ConfigPath>   Path to the config file describing the certificate.");
        Console.WriteLine("                  Output files are created in the same directory and with the same file name as the config file");
        Console.WriteLine("                  (varying extensions). If this config file does not exist, a template file is created and the");
        Console.WriteLine("                  program exits with an error.");
        Console.WriteLine();
        Console.WriteLine("Optional parameters:");
        Console.WriteLine();
        Console.WriteLine("   --dns          Validate via a DNS TXT record which you create manually. This is the default, and the only");
        Console.WriteLine("                  option for wildcard certificates.");
        Console.WriteLine("   --http         Validate via an HTTP challenge file which you place on the web server manually.");
        Console.WriteLine("   --http-auto    Validate via an HTTP challenge served by this program on port 80. Assumes that the domain");
        Console.WriteLine("                  resolves to this machine and that port 80 is open and available.");
    }
}
