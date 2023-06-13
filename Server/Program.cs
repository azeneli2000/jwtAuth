using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var rsaKey = RSA.Create();
rsaKey.ImportRSAPrivateKey(File.ReadAllBytes("key"), out _);


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("jwt").AddJwtBearer("jwt", o =>
{
    o.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false
    };
    o.Events = new JwtBearerEvents()
    {
        OnMessageReceived = (ctx) =>
        {
            if (ctx.Request.Query.ContainsKey("t"))
            {
                ctx.Token = ctx.Request.Query["t"];
            }
            return Task.CompletedTask;
        }
    };
    o.Configuration = new OpenIdConnectConfiguration()
    {
        SigningKeys = {new RsaSecurityKey(rsaKey)}
    };
    o.MapInboundClaims = false;
});

var app = builder.Build();

app.MapGet("/", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "Empty");
app.MapGet("/jwt", () =>
{
    var handler = new JsonWebTokenHandler(); //create and validate
    var key = new RsaSecurityKey(rsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://localhost:5004",
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("name", "Andi")
        }),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
    });
    return token;
});

app.Run();