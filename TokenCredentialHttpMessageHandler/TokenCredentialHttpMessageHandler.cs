using Azure;
using Azure.Core;
using System.ClientModel;
using System.ClientModel.Primitives;
using System.Net.Http.Headers;

namespace HttpMessageHandlers;

public sealed class TokenCredentialHttpMessageHandler : DelegatingHandler
{
    AuthenticationToken? _token;
    Func<HttpRequestMessage, AuthenticationToken?, CancellationToken, ValueTask<AuthenticationToken>> _tokenHandler;

    public TokenCredentialHttpMessageHandler(AuthenticationTokenProvider credential, IEnumerable<string>? scopes = null, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(credential, (a, r) => Map(a, new(scopes?.ToArray() ?? [$"{r.RequestUri!.GetLeftPart(UriPartial.Authority)}/.default"])), innerHandler: innerHandler) { }

    public TokenCredentialHttpMessageHandler(AuthenticationTokenProvider credential, TokenRequestContext requestContext, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(credential, (a, r) => requestContext, tokenReuseCriteria, innerHandler) { }

    public TokenCredentialHttpMessageHandler(AuthenticationTokenProvider credential, GetTokenOptions properties, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(credential, (a, r) => properties, tokenReuseCriteria, innerHandler) { }

    public TokenCredentialHttpMessageHandler(AuthenticationTokenProvider credential, Func<AuthenticationTokenProvider, HttpRequestMessage, TokenRequestContext> requestResolver, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(async (r, ct) => await credential.GetTokenAsync(Map(credential, requestResolver(credential, r)), ct), tokenReuseCriteria, innerHandler) { }

    public TokenCredentialHttpMessageHandler(AuthenticationTokenProvider credential, Func<AuthenticationTokenProvider, HttpRequestMessage, GetTokenOptions> requestResolver, Func<HttpRequestMessage, AuthenticationToken?, bool>?  tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(async (r, ct) => await credential.GetTokenAsync(requestResolver(credential, r), ct), tokenReuseCriteria, innerHandler) { }

    public TokenCredentialHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, ValueTask<AuthenticationToken>> tokenFetcher, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null, HttpMessageHandler? innerHandler = null)
        : this(CreateTokenFetcher(tokenFetcher, tokenReuseCriteria), innerHandler) { }

    public TokenCredentialHttpMessageHandler(Func<HttpRequestMessage, AuthenticationToken?, CancellationToken, ValueTask<AuthenticationToken>> tokenHandler, HttpMessageHandler? innerHandler = null)
        : base(innerHandler ?? new SocketsHttpHandler() { PooledConnectionLifetime = TimeSpan.FromSeconds(90) })
    {
        _tokenHandler = tokenHandler;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _token = await _tokenHandler(request, _token, cancellationToken);
        if (_token != null)
            request.Headers.Authorization = new AuthenticationHeaderValue(_token.TokenType, _token.TokenValue);
        return await base.SendAsync(request, cancellationToken);
    }

    static Func<HttpRequestMessage, AuthenticationToken?, CancellationToken, ValueTask<AuthenticationToken>> CreateTokenFetcher(Func<HttpRequestMessage, CancellationToken, ValueTask<AuthenticationToken>> tokenFetcher, Func<HttpRequestMessage, AuthenticationToken?, bool>? tokenReuseCriteria = null)
    {
        tokenReuseCriteria ??= ((r, t) => t is not null && t.ExpiresOn >= DateTimeOffset.UtcNow.AddSeconds(3));
        return async (r, t, ct) => tokenReuseCriteria(r, t) ? t! : await tokenFetcher(r, ct);
    }

    static GetTokenOptions Map(AuthenticationTokenProvider provider, TokenRequestContext context)
        => provider.CreateTokenOptions(new Dictionary<string, object?>
        {
            { GetTokenOptions.ScopesPropertyName, context.Scopes },
            { "parentRequestId", context.ParentRequestId },
            { "clains", context.Claims },
            { "tenantId", context.TenantId  },
            { "isCaeEnabled", context.IsCaeEnabled },
            { "isProofOfPossessionEnabled", context.IsProofOfPossessionEnabled },
            { "proofOfPossessionNonce", context.ProofOfPossessionNonce },
            { "requestUri", context.ResourceRequestUri },
            { "requestMethod", context.ResourceRequestMethod },
        }.Where(x => x.Value is not null).ToDictionary()!) ?? throw new Exception("GetTokenOptions cannot be null.");
}
