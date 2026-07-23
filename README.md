# OAuth Minimal Demo Using Discord

Two minimal ASP.NET Core apps run Discord's real OAuth 2.0 authorization-code flow.

If you are learning OAuth, watch [this video](https://youtu.be/996OiexHze0), then use these code examples to trace the flow step by step, preferably in a debugger.

`ManualOAuthDemo` implements the redirects, `state` validation, PKCE, token exchange, and Discord profile request directly. It has a normal `MapGet("/auth/callback")` endpoint where every step is visible.

`MiddlewareOAuthDemo` uses ASP.NET Core's OAuth handler to perform those steps and creates a local authentication cookie. Its middleware intercepts `/auth/callback`, so use its `OnCreatingTicket`, `OnTicketReceived`, and `OnRemoteFailure` events for breakpoints.

In both samples, the local callback represents the client application's backend service. In production, that endpoint normally runs in a cloud-hosted service controlled by the client application, not in the browser. Discord redirects the browser to it, but that service validates the response, keeps the client secret, exchanges the code for tokens, and calls Discord APIs.

## OAuth flow in plain language

1. The user selects **Sign in with Discord**. The client application creates a temporary `state` value and PKCE values, then redirects the browser to Discord with its client ID, requested scope, and callback URI.
2. Discord signs in the user and asks whether the application may use the requested scope.
3. Discord redirects the browser to the client application's callback URI with a short-lived, one-time authorization code and the original `state` value.
4. The client application's backend checks that `state` matches the browser's original login attempt. It then sends the code, its client secret, and the PKCE verifier directly to Discord. The browser never receives the client secret or token.
5. Discord returns tokens to the backend. The backend uses the access token to request the user's Discord profile.
6. The manual demo displays that one-time result and does not create a session. The middleware demo maps the profile to claims and creates its own local authentication cookie, so later requests recognize the user without repeating the Discord redirect.

## Setup

1. Create a Discord application at <https://discord.com/developers/applications>. On **OAuth2**, add both redirect URIs exactly:

   ```text
   https://localhost:7176/auth/callback
   https://localhost:7175/auth/callback
   ```

2. Store its client ID and client secret once. Both projects intentionally share this local user-secrets store:

   ```powershell
   dotnet user-secrets --project .\MiddlewareOAuthDemo set "Discord:ClientId" "your-client-id"
   dotnet user-secrets --project .\MiddlewareOAuthDemo set "Discord:ClientSecret" "your-client-secret"
   ```

3. Trust the local certificate once:

   ```powershell
   dotnet dev-certs https --trust
   ```

4. Run either project, then select **Sign in with Discord**:

   ```powershell
   dotnet run --project .\ManualOAuthDemo
   dotnet run --project .\MiddlewareOAuthDemo
   ```

Open <https://localhost:7176> for the manual demo or <https://localhost:7175> for the middleware demo. Approve Discord's `identify` scope.

The client secret remains outside source control. Clear the shared local values afterward with `dotnet user-secrets --project .\MiddlewareOAuthDemo clear`.

## Production notes

Register the exact public HTTPS callback URI, not a localhost URI. Store secrets in the deployment platform's secret store. If a reverse proxy terminates TLS for `MiddlewareOAuthDemo`, configure trusted forwarded headers and set `ReverseProxy:UseForwardedHeaders` to `true` so ASP.NET Core creates the public callback URI. Replace `AllowedHosts: localhost` with the application's public host.

The manual demo uses short-lived `SameSite=Lax` cookies because Discord returns the browser with a top-level GET request. The middleware handler instead uses its own protected correlation cookie and a 15-minute remote-authentication timeout.

### Data Protection in the middleware demo

`ManualOAuthDemo` does not use ASP.NET Core Data Protection. It reads its `state` and PKCE verifier directly from the secure, HTTP-only cookies it creates.

`MiddlewareOAuthDemo` does use Data Protection, but no application code calls `Decrypt`. `.AddOAuth("Discord", ...)` internally protects OAuth state and correlation data before the browser redirects to Discord. When `app.UseAuthentication()` receives `/auth/callback`, the handler internally unprotects and validates that data before any `OAuthEvents` run. `.AddCookie()` similarly protects the local authentication cookie and `UseAuthentication()` unprotects it on later requests.

With multiple cloud instances, instance A can start sign-in while instance B receives the callback. If they use different temporary Data Protection keys, B cannot validate A's OAuth state and sign-in fails. The same issue can invalidate a local authentication cookie when a later request reaches another instance. Persist and share the Data Protection key ring in protected storage that all instances can access, such as a secured shared volume, Azure Blob Storage, or Redis. Protect those stored keys at rest and use the same Data Protection application name on every instance.
