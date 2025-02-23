using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("token", (Authentication auth, IConfiguration config) =>
{
    if (auth is { username: "admin", password: "admin" })
        return TokenJwt.Create(config, role: "Admin");
    
    return Results.Unauthorized();
});


app.UseHttpsRedirection();
app.Run();

record Authentication(string username, string password);

public static class TokenJwt
{
    public static object Create(IConfiguration configuration, string role)
    {
        var key = Encoding.ASCII.GetBytes(configuration["JWT:Key"]);

        var tokenConfig = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, role),
            }),
            Expires = DateTime.UtcNow.AddHours(3),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), algorithm: SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenConfig);
        var tokenString = tokenHandler.WriteToken(token);
        
        return new
        {
            token = tokenString,
        };
    }
}


