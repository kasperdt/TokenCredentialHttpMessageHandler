using Azure.Core;
using System.Net.Http.Headers;

namespace TokenCredentialHttpMessageHandler;

public sealed class TokenCredentialHttpMessageHandler : DelegatingHandler
{
    readonly TokenCredential _credential;
    string[]? _scopes;
    AccessToken _token;

    public TokenCredentialHttpMessageHandler(TokenCredential credential, IEnumerable<string>? scopes = null, HttpMessageHandler? innerHandler = null)
        : base(innerHandler ?? new SocketsHttpHandler() { PooledConnectionLifetime = TimeSpan.FromSeconds(90) })
    {
        _credential = credential;
        _scopes = scopes?.ToArray();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_scopes is not { Length: > 0 }) _scopes = [$"{request.RequestUri!.GetLeftPart(UriPartial.Authority)}/.default"];
        if (_token.ExpiresOn <= DateTimeOffset.Now)
            _token = await _credential.GetTokenAsync(new TokenRequestContext(_scopes), cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue(_token.TokenType, _token.Token);
        return await base.SendAsync(request, cancellationToken);
    }
}
