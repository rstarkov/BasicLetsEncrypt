using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Newtonsoft.Json;
using RT.CommandLine;
using RT.Util;
using RT.Util.Consoles;

namespace BasicLetsEncrypt;

[Documentation("Obtains or renews an SSL certificate via LetsEncrypt using manual DNS validation.")]
class CmdLine : ICommandLineValidatable
{
    [DocumentationRhoML("{h}Path to the config file describing the certificate.{}\r\nOutput files are created in the same directory and with the same file name as the config file (varying extensions). If this config file does not exist, a template file is created and the program exits with an error.")]
    [IsPositional, IsMandatory]
    public string ConfigPath;

    public Config Config;

    public ConsoleColoredString Validate()
    {
        ConfigPath = Path.GetFullPath(ConfigPath);
        if (!File.Exists(ConfigPath))
        {
            var cfg = new Config { Domain = "example.com", NotifyEmail = "me@example.com", PfxPassword = "asdf", CountryName = "GB", Locality = "London", State = "London" };
            File.WriteAllText(ConfigPath, JsonConvert.SerializeObject(cfg, Formatting.Indented));
            return CommandLineParser.Colorize(RhoML.Parse($"Config file not found: {{h}}{ConfigPath}{{}}\r\n\r\nA template file has been created at the above path."));
        }

        try { Config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigPath)); }
        catch { return CommandLineParser.Colorize(RhoML.Parse($"Could not parse config file: {{h}}{ConfigPath}{{}}")); }

        return null;
    }
}

class Config
{
    public string Domain { get; set; }
    public string NotifyEmail { get; set; }
    public string PfxPassword { get; set; }

    public string CountryName { get; set; }
    public string State { get; set; }
    public string Locality { get; set; }
}

class Program
{
    static CmdLine Args;

    static async Task<int> Main(string[] args)
    {
        Args = CommandLineParser.ParseOrWriteUsageToConsole<CmdLine>(args);
        if (Args == null)
            return 1;

        var outputPath = Path.GetDirectoryName(Args.ConfigPath);
        var identifier = Path.GetFileNameWithoutExtension(Args.ConfigPath);
        var cfg = Args.Config;

        Console.WriteLine($"This will create/renew a LetsEncrypt certificate for {cfg.Domain}");
        PressYToContinue();

        // https://community.letsencrypt.org/t/what-are-accounts-do-i-need-to-backup-them/21318/2
        // We won't try to preserve the account key, and will simply create a new one every time.
        var acme = new AcmeContext(WellKnownServers.LetsEncryptV2);
        await acme.NewAccount(cfg.NotifyEmail, true);

        var commonName = cfg.Domain;
        var order = await acme.NewOrder(new[] { commonName });
        var authz = (await order.Authorizations()).First();
        var challenge = await authz.Dns();
        Console.WriteLine();
        Console.WriteLine("DNS challenge required:");
        Console.WriteLine($"    update TXT record for _acme-challenge.{cfg.Domain.Replace("*.", "")}");
        Console.WriteLine($"    {acme.AccountKey.DnsTxt(challenge.Token)}");
        Console.WriteLine();
        PressYToContinue();
        await challenge.Validate();
        Thread.Sleep(10000);
        Console.WriteLine("Validation complete");

        var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var cert = await order.Generate(new CsrInfo
        {
            CountryName = cfg.CountryName,
            State = cfg.State,
            Locality = cfg.Locality,
            Organization = cfg.Domain.Replace("*.", ""),
            OrganizationUnit = "IT",
            CommonName = commonName,
        }, privateKey);

        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.ca-bundle"), string.Join("\r\n", cert.Issuers.Select(s => s.ToPem())));
        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.crt"), cert.Certificate.ToPem());
        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.private.key"), privateKey.ToPem());
        if (cfg.PfxPassword != null)
        {
            var pfxBuilder = cert.ToPfx(privateKey);
            var pfx = pfxBuilder.Build(identifier, cfg.PfxPassword);
            File.WriteAllBytes(Path.Combine(outputPath, $"{identifier}.pfx"), pfx);
        }

        Console.WriteLine($"Certificate files saved to: {outputPath}\\{identifier}.*");

        return 0;
    }

    private static void PressYToContinue()
    {
        do { Console.WriteLine("Press Y to continue..."); }
        while (Console.ReadKey(true).Key != ConsoleKey.Y);
        Console.WriteLine("Please wait...");
    }
}
