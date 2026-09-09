using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BasicLetsEncrypt;

/// <summary>
///     Serves a single HTTP-01 challenge response on port 80. Binds only to http://{domain}/.well-known/acme-challenge/, so
///     HTTP.sys never delivers requests for other hosts or paths to us, and other HTTP.sys-based servers such as IIS can keep
///     serving everything else. Within that subtree, only a GET for the exact challenge path gets the response; everything
///     else gets an empty 404.</summary>
class HttpChallengeServer : IDisposable
{
    private HttpListener _listener;
    private readonly string _path;
    private readonly byte[] _response;

    /// <summary>
    ///     Starts listening on port 80. If the port is not available, retries every 5 seconds for up to 120 seconds before
    ///     giving up.</summary>
    public HttpChallengeServer(string domain, string path, string keyAuthorization)
    {
        _path = path;
        _response = Encoding.ASCII.GetBytes(keyAuthorization);
        var deadline = DateTime.UtcNow.AddSeconds(120);
        var waited = false;
        while (true)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://{domain}:80/.well-known/acme-challenge/");
            try
            {
                _listener.Start();
                break;
            }
            catch (HttpListenerException e) when (e.ErrorCode != 5) // 5 = access denied: waiting won't help
            {
                _listener.Close();
                if (DateTime.UtcNow >= deadline)
                    throw new Exception($"Port 80 did not become available within 120 seconds: {e.Message}");
                if (!waited)
                    Console.WriteLine($"Port 80 is not available: {e.Message} Retrying every 5 seconds for up to 120 seconds...");
                waited = true;
                Thread.Sleep(5000);
            }
        }
        if (waited)
            Console.WriteLine("Port 80 is now available.");
        _ = Task.Run(Serve);
    }

    private async Task Serve()
    {
        while (true)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync(); }
            catch (Exception) { return; } // the listener has been stopped
            var request = context.Request;
            var host = request.UserHostName;
            var isMatch = request.HttpMethod == "GET" && request.RawUrl == _path;
            // The request becomes inaccessible once the response is closed, so log first.
            Console.WriteLine($"    {request.RemoteEndPoint.Address}: {request.HttpMethod} {host}{request.RawUrl} -> {(isMatch ? 200 : 404)}");
            try
            {
                if (isMatch)
                {
                    context.Response.ContentLength64 = _response.Length;
                    await context.Response.OutputStream.WriteAsync(_response);
                }
                else
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentLength64 = 0;
                }
                context.Response.Close();
            }
            catch (Exception) { } // the client went away
        }
    }

    public void Dispose()
    {
        _listener.Close();
    }
}
