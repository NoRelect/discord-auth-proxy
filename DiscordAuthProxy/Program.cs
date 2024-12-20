using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Claims;
using AspNet.Security.OAuth.Discord;
using AspNetCore.Proxy;
using DiscordAuthProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

var clientId = builder.Configuration.GetValue<string>("Discord:ClientId") ??
    throw new InvalidOperationException("Discord:ClientId is required.");
var clientSecret = builder.Configuration.GetValue<string>("Discord:ClientSecret") ??
    throw new InvalidOperationException("Discord:ClientSecret is required.");
var proxyUrl = builder.Configuration.GetValue<string>("ProxyUrl") ??
    throw new InvalidOperationException("ProxyUrl is required.");
var allowedGuildIds = builder.Configuration.GetRequiredSection("AllowedGuildIds").Get<string[]>() ??
    throw new InvalidOperationException("AllowedGuildIds is required.");
var allowedGuildIdsHashSet = new HashSet<string>(allowedGuildIds);
Console.WriteLine($"Configured proxy to: {proxyUrl}");
Console.WriteLine($"Allowed guild ids: {string.Join(", ", allowedGuildIdsHashSet)}");

builder.Services.AddProxies();
builder.Services.AddAuthentication(options => {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = DiscordAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "AuthProxySession";
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.HttpOnly = true;

        options.Events.OnRedirectToAccessDenied = async context => {
            context.Response.ContentType = MediaTypeNames.Text.Plain;
            context.Response.StatusCode = 403;
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Denied request for user {User} that is in the following guilds: {Guilds}",
                context.HttpContext.User, context.HttpContext.User.FindAll("guilds"));
            await context.Response.WriteAsync("Access denied");
        };
    })
    .AddDiscord(options =>
    {
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.CallbackPath = "/callback-discord";
        options.CorrelationCookie.Name = "AuthProxyCorrelation";
        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.Scope.Add("identify");
        options.Scope.Add("guilds");

        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "username");

        options.Events.OnCreatingTicket = async context => {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://discord.com/api/users/@me/guilds");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException("Failed to get guilds");
            }
            var guilds = await response.Content.ReadFromJsonAsync<List<DiscordPartialGuildResponse>>() ??
                throw new InvalidOperationException("Failed to parse response");
            
            // Only add guild ids to claim that are in the allowlist
            foreach (var guild in guilds.Where(guild => allowedGuildIdsHashSet.Contains(guild.Id)))
            {
                context.Identity?.AddClaim(new Claim("guilds", guild.Id));
            }
        };
        options.Events.OnRemoteFailure = async context => {
            context.Response.ContentType = MediaTypeNames.Text.Plain;
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("Remote authentication failed");
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddAuthorization(options => {
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireAssertion(context =>
        {
            if (string.IsNullOrEmpty(context.User.FindFirstValue(ClaimTypes.NameIdentifier)) ||
                string.IsNullOrEmpty(context.User.FindFirstValue(ClaimTypes.Name)))
                return false;

            var guildClaims = context.User.FindAll("guilds");
            if (!guildClaims.Any(c => allowedGuildIdsHashSet.Contains(c.Value)))
                return false;

            return true;
        }).Build();
    options.DefaultPolicy = policy;
    options.FallbackPolicy = policy;
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.RunProxy(proxy => proxy.UseHttp(proxyUrl));
app.Run();
