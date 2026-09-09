using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace BasicLetsEncrypt;

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
    static async Task<int> Main(string[] args)
    {
        var cmd = CmdLine.Parse(args);
        if (cmd == null)
            return 1;
        var cfg = LoadConfig(cmd.ConfigPath);
        if (cfg == null)
            return 1;

        var outputPath = Path.GetDirectoryName(cmd.ConfigPath);
        var identifier = Path.GetFileNameWithoutExtension(cmd.ConfigPath);

        Console.WriteLine($"This will create/renew a LetsEncrypt certificate for {cfg.Domain}");
        PressYToContinue();

        // https://community.letsencrypt.org/t/what-are-accounts-do-i-need-to-backup-them/21318/2
        // We won't try to preserve the account key, and will simply create a new one every time.
        var acme = new AcmeClient(AcmeClient.LetsEncryptV2);
        await acme.NewAccount(cfg.NotifyEmail);

        var commonName = cfg.Domain;
        var order = await acme.NewOrder(commonName);
        var challenge = await acme.GetDnsChallenge(order.Authorizations.First());
        Console.WriteLine();
        Console.WriteLine("DNS challenge required:");
        Console.WriteLine($"    update TXT record for _acme-challenge.{cfg.Domain.Replace("*.", "")}");
        Console.WriteLine($"    {acme.DnsTxt(challenge.Token)}");
        Console.WriteLine();
        PressYToContinue();
        await acme.Validate(challenge.Url);
        order = await acme.WaitWhileOrderIs(order.Url, "pending");
        Console.WriteLine("Validation complete");

        var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = Pki.CreateCsr(new CsrInfo
        {
            CountryName = cfg.CountryName,
            State = cfg.State,
            Locality = cfg.Locality,
            Organization = cfg.Domain.Replace("*.", ""),
            OrganizationUnit = "IT",
            CommonName = commonName,
        }, privateKey);
        await acme.Finalize(order.Finalize, csr);
        order = await acme.WaitWhileOrderIs(order.Url, "processing");
        var chain = await acme.DownloadCertificate(order.Certificate);

        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.ca-bundle"), string.Join("\r\n", chain.Skip(1).Select(c => c.ExportCertificatePem())));
        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.crt"), chain[0].ExportCertificatePem());
        File.WriteAllText(Path.Combine(outputPath, $"{identifier}.private.key"), privateKey.ExportECPrivateKeyPem());
        if (cfg.PfxPassword != null)
            File.WriteAllBytes(Path.Combine(outputPath, $"{identifier}.pfx"), Pki.ToPfx(chain, privateKey, identifier, cfg.PfxPassword));

        Console.WriteLine($"Certificate files saved to: {outputPath}\\{identifier}.*");

        return 0;
    }

    /// <summary>
    ///     Loads the config file. If it doesn't exist, creates a template in its place; if it can't be parsed, reports the
    ///     error. Returns null in either case.</summary>
    private static Config LoadConfig(string path)
    {
        if (!File.Exists(path))
        {
            var template = new Config { Domain = "example.com", NotifyEmail = "me@example.com", PfxPassword = "asdf", CountryName = "GB", Locality = "London", State = "London" };
            File.WriteAllText(path, JsonSerializer.Serialize(template, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"Config file not found: {path}");
            Console.WriteLine();
            Console.WriteLine("A template file has been created at the above path.");
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<Config>(File.ReadAllText(path), new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        }
        catch
        {
            Console.WriteLine($"Could not parse config file: {path}");
            return null;
        }
    }

    private static void PressYToContinue()
    {
        do { Console.WriteLine("Press Y to continue..."); }
        while (Console.ReadKey(true).Key != ConsoleKey.Y);
        Console.WriteLine("Please wait...");
    }
}
