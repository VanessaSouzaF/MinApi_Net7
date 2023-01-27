using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    //o.SwaggerDoc("v1", info);
    o.AddSecurityDefinition("Bearer", securityScheme);
    o.AddSecurityRequirement(securityReq);
});

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("/security/getToken", [AllowAnonymous] (UserDto user) =>
{

    if (user.Email == "ferreira@gmail.com" && user.Password == "P@ssword")
    {
        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", "1"),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),

            Expires = DateTime.UtcNow.AddHours(48),
            Audience = audience,
            Issuer = issuer,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);

        var jwtToken = jwtTokenHandler.WriteToken(token);

        return Results.Ok(jwtToken);
    }
    else
    {
        return Results.Unauthorized();
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("filters", [Authorize](string chaveSecreta) =>
{
    return "Usando filtro em Minimal em Minimal Apis";
})
.AddEndpointFilter(async (context, next) =>
{
    if (!context.HttpContext.Request
    .QueryString.Value.Contains("numsey"))
    {
        return Results.BadRequest();
    }
    return await next(context);
});

app.MapGet("/curto-circuito", [Authorize] () => "Nunca será executado...")
    .AddEndpointFilter<ShortCircuit>();

app.MapPost("/upload", async (IFormFile arquivo) =>
{
    await arquivo.CopyToAsync(File.OpenWrite($@"{DateTime.Now.Ticks}.txt"));
});

app.MapPost("/uploadArquivo", [Authorize] async (IFormFile arquivo) =>
{
    string arquivoTemp = CriaCaminhoArquivoTemp();
    using var stream = File.OpenWrite(arquivoTemp);
    await arquivo.CopyToAsync(stream);
    return Results.Ok("Arquivo enviado com sucesso");
});

app.MapPost("/uploadArquivos", [Authorize] async (IFormFileCollection arquivos) =>
{
    foreach (var arquivo in arquivos)
    {
        string arquivoTemp = CriaCaminhoArquivoTemp();
        using var stream = File.OpenWrite(arquivoTemp);
        await arquivo.CopyToAsync(stream);
    }
    return Results.Ok("Arquivos enviados com sucesso");
});

app.MapGet("/procurar", [Authorize] (string[] nomes) =>
{
    var result = $"Nomes : {nomes[0]}, {nomes[1]}, {nomes[2]}";
    return Results.Ok(result);
});


app.MapGet("/buscar", [Authorize] ([AsParameters] Livro info) =>
{
    return $"Livro: {info.Titulo}, {info.Autor}, {info.Ano}";
});

app.UseHttpsRedirection();

app.Run();

static string CriaCaminhoArquivoTemp()
{
    var nomeArquivo = $@"{DateTime.Now.Ticks}.tmp";
    var directoryPath = Path.Combine("temp", "uploads");

    if (!Directory.Exists(directoryPath))
        Directory.CreateDirectory(directoryPath);

    return Path.Combine(directoryPath, nomeArquivo);
}

public class ShortCircuit : IEndpointFilter 
{
    public ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        return new ValueTask<object?>
            (Results.Json(new { Curto = "Circuito" }));
    }
}

public class Livro
{
    public string? Autor { get; set; }
    public string? Titulo { get; set; }
    public int Ano { get; set; }
}
record UserDto(string Email, string Password);
