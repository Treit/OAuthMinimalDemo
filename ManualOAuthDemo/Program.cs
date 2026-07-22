using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;

// Discord permits redirects only to URIs registered for the application. This must exactly match
// both the URI configured in Discord's developer portal and the HTTPS launch profile's port.
const string redirectUri = "https://localhost:7176/auth/callback";

var builder = WebApplication.CreateBuilder(args);

// User secrets are a development-only configuration store outside the repository. The client ID
// identifies this application; the client secret proves the server owns that application at token exchange.
var discordClientId = builder.Configuration["Discord:ClientId"];
var discordClientSecret = builder.Configuration["Discord:ClientSecret"];

// Keep shared markup out of the OAuth code so the protocol steps remain easy to follow.
var pageTemplate = File.ReadAllText(Path.Combine(builder.Environment.ContentRootPath, "PageTemplate.html"));

// IHttpClientFactory creates HttpClient instances for Discord's token and user-info HTTP requests.
builder.Services.AddHttpClient();

// The callback stores a profile result here only long enough to redirect away from the URL containing the code.
builder.Services.AddMemoryCache();

var app = builder.Build();

// OAuth transfers credentials and authorization codes. Always redirect HTTP requests to HTTPS.
app.UseHttpsRedirection();

app.MapGet("/", () =>
    Html(
        "Manual Discord OAuth demo",
        "<p>This version implements the OAuth authorization-code flow itself. It does not use ASP.NET Core authentication or OAuth middleware.</p><p><a class=\"button\" href=\"/login\">Sign in with Discord</a></p>"));

app.MapGet("/login", (HttpContext context) =>
{
    // A missing client secret would cause a confusing failure at Discord's token endpoint.
    if (string.IsNullOrWhiteSpace(discordClientId) || string.IsNullOrWhiteSpace(discordClientSecret))
    {
        return Html("Configuration required", "<p>Set Discord:ClientId and Discord:ClientSecret with dotnet user-secrets first.</p>", 400);
    }

    // State is a high-entropy value that binds the callback to this browser's login attempt. Without it,
    // an attacker could try to cause the browser to accept an authorization response they initiated.
    var state = RandomValue();

    // PKCE, short for Proof Key for Code Exchange, binds the authorization code to this login attempt.
    // We retain the secret verifier and send only its SHA-256-derived challenge to Discord. A stolen code
    // cannot be exchanged without the verifier, which is available only in this browser's secure cookie.
    var codeVerifier = RandomValue();
    var codeChallenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    var cookieOptions = new CookieOptions
    {
        // JavaScript cannot read these protocol secrets, reducing damage from a script-injection bug.
        HttpOnly = true,

        // These cookies are required for the user-requested OAuth operation, not optional tracking cookies.
        IsEssential = true,

        // Lax sends cookies on Discord's top-level GET redirect back to this site but not with cross-site
        // subrequests. That lets the callback work while providing useful cross-site request protection.
        SameSite = SameSiteMode.Lax,

        // Never send state or the verifier over unencrypted HTTP.
        Secure = true,

        // OAuth callbacks should finish quickly. Expire abandoned state and PKCE material after 15 minutes.
        MaxAge = TimeSpan.FromMinutes(15),
        Path = "/"
    };

    // The callback reads these values from the same browser that initiated the redirect.
    context.Response.Cookies.Append("discord-oauth-state", state, cookieOptions);
    context.Response.Cookies.Append("discord-oauth-verifier", codeVerifier, cookieOptions);

    var authorizationUrl = QueryHelpers.AddQueryString(
        "https://discord.com/api/oauth2/authorize",
        new Dictionary<string, string?>
        {
            // Discord uses this public identifier to find the registered application and redirect URI list.
            ["client_id"] = discordClientId,

            // "code" requests the authorization-code flow rather than returning a token in the browser.
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,

            // The identify scope permits the small profile request made after token exchange.
            ["scope"] = "identify",
            // Discord returns this unchanged. We compare it to the state cookie in the callback.
            ["state"] = state,

            // PKCE parameters tell Discord to require the original verifier during code exchange.
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        });

    return Results.Redirect(authorizationUrl);
});

// This local endpoint represents the cloud-hosted backend callback in a production client application.
// Discord redirects the browser here, but this server, not browser JavaScript, validates the response,
// uses the client secret, exchanges the code for tokens, and calls Discord's API.
app.MapGet("/auth/callback", async (HttpContext context, IHttpClientFactory clientFactory, IMemoryCache callbackResults) =>
{
    // The provider can return an OAuth error instead of a code when sign-in is denied or malformed.
    var providerError = context.Request.Query["error"].FirstOrDefault();
    if (providerError is not null)
    {
        // An error ends this login attempt too, so remove its state and verifier rather than retaining them.
        ClearOAuthCookies(context);
        return Html("OAuth callback failed", $"<p>Discord returned: {WebUtility.HtmlEncode(providerError)}</p>", 400);
    }

    // A code is short-lived and single-use. It is safe to receive in this HTTPS request, but never log it.
    var code = context.Request.Query["code"].FirstOrDefault();
    var state = context.Request.Query["state"].FirstOrDefault();
    var expectedState = context.Request.Cookies["discord-oauth-state"];
    var codeVerifier = context.Request.Cookies["discord-oauth-verifier"];

    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state))
    {
        return Html("OAuth callback failed", "<p>Discord did not return an authorization code and state.</p>", 400);
    }

    if (string.IsNullOrWhiteSpace(expectedState) || string.IsNullOrWhiteSpace(codeVerifier) || !FixedTimeEquals(state, expectedState))
    {
        return Html("OAuth callback failed", "<p>The callback state did not match the state stored before the redirect.</p>", 400);
    }

    // A valid callback consumes both values so an authorization response cannot be replayed.
    ClearOAuthCookies(context);

    // The browser never sees the client secret or access token. This server-to-server POST trades the
    // authorization code plus the PKCE verifier for tokens issued by Discord.
    using var tokenResponse = await clientFactory.CreateClient().PostAsync(
        "https://discord.com/api/oauth2/token",
        new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["client_id"] = discordClientId!,
                ["client_secret"] = discordClientSecret!,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier
            }),
        context.RequestAborted);

    if (!tokenResponse.IsSuccessStatusCode)
    {
        return Html("Token exchange failed", "<p>Discord rejected the authorization code. Check the client secret and redirect URI.</p>", 502);
    }

    // Read only the access token needed for the next request. Do not put it in the HTML response or logs.
    await using var tokenStream = await tokenResponse.Content.ReadAsStreamAsync(context.RequestAborted);
    using var token = await JsonDocument.ParseAsync(tokenStream, cancellationToken: context.RequestAborted);
    var accessToken = token.RootElement.GetProperty("access_token").GetString();

    // The bearer token authorizes this request for the exact scope granted by the user.
    using var userRequest = new HttpRequestMessage(HttpMethod.Get, "https://discord.com/api/users/@me");
    userRequest.Headers.Authorization = new("Bearer", accessToken);
    using var userResponse = await clientFactory.CreateClient().SendAsync(userRequest, context.RequestAborted);
    userResponse.EnsureSuccessStatusCode();

    await using var userStream = await userResponse.Content.ReadAsStreamAsync(context.RequestAborted);
    using var user = await JsonDocument.ParseAsync(userStream, cancellationToken: context.RequestAborted);

    // Store the non-sensitive display result under a random, one-time key. Redirecting to a separate endpoint
    // removes the authorization code and state from the browser address bar, history, and future referrers.
    var resultId = RandomValue();
    callbackResults.Set(
        resultId,
        new OAuthResult(
            user.RootElement.GetProperty("id").GetString() ?? string.Empty,
            user.RootElement.GetProperty("username").GetString() ?? string.Empty),
        TimeSpan.FromMinutes(1));

    return Results.Redirect(QueryHelpers.AddQueryString("/callback-complete", "result", resultId));
});

app.MapGet("/callback-complete", (HttpContext context, IMemoryCache callbackResults) =>
{
    var resultId = context.Request.Query["result"].FirstOrDefault();
    if (string.IsNullOrWhiteSpace(resultId) ||
        !callbackResults.TryGetValue<OAuthResult>(resultId, out var result) ||
        result is null)
    {
        return Html("OAuth callback result unavailable", "<p>The one-time callback result expired. Start sign-in again.</p>", 400);
    }

    // Display this value once, then remove it. This manual demo deliberately does not create a sign-in session.
    callbackResults.Remove(resultId);
    var userId = WebUtility.HtmlEncode(result.UserId);
    var username = WebUtility.HtmlEncode(result.Username);
    return Html(
        "OAuth callback completed",
        $"<p>The explicit <code>/auth/callback</code> endpoint validated state, exchanged the code, and fetched Discord's profile.</p><table><tr><th>Discord ID</th><td>{userId}</td></tr><tr><th>Username</th><td>{username}</td></tr></table><p>This manual demo does not create a local sign-in cookie.</p><p><a href=\"/\">Home</a></p>");
});

app.Run();

IResult Html(string title, string body, int statusCode = 200) =>
    Results.Content(
        pageTemplate
            .Replace("{{title}}", WebUtility.HtmlEncode(title))
            .Replace("{{body}}", body),
        "text/html",
        statusCode: statusCode);

// Generate 256 bits from the operating system's cryptographic random-number generator, then Base64URL
// encode them so the values are safe in cookies and query strings without additional escaping.
static string RandomValue() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

// A normal string comparison can stop at the first different character, exposing timing differences to
// an attacker making many measurements. FixedTimeEquals compares every byte before returning a result.
static bool FixedTimeEquals(string left, string right) =>
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));

static void ClearOAuthCookies(HttpContext context)
{
    var options = new CookieOptions { Path = "/" };
    context.Response.Cookies.Delete("discord-oauth-state", options);
    context.Response.Cookies.Delete("discord-oauth-verifier", options);
}

sealed record OAuthResult(string UserId, string Username);
