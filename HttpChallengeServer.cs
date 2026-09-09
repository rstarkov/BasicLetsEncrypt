using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace BasicLetsEncrypt;

/// <summary>
///     Serves a single HTTP-01 challenge response on port 80. Only a GET for the expected path with the expected Host header
///     gets the response; everything else gets an empty 404.</summary>
class HttpChallengeServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly string _domain;
    private readonly string _path;
    private readonly byte[] _response;

    public HttpChallengeServer(string domain, string path, string keyAuthorization)
    {
        _domain = domain;
        _path = path;
        _response = Encoding.ASCII.GetBytes(keyAuthorization);
        _listener.Prefixes.Add("http://+:80/");
        _listener.Start();
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
            var isMatch = request.HttpMethod == "GET" && request.RawUrl == _path
                && (string.Equals(host, _domain, StringComparison.OrdinalIgnoreCase) || string.Equals(host, _domain + ":80", StringComparison.OrdinalIgnoreCase));
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
