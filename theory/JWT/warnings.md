If you are following along from .NET 7, you will notice that in the next video you have a warning that I don't have right after you create your SymmetricSecurityKey for your JWT.

The code snippet below will get rid of that warning.

string? tokenKeyString = _config.GetSection("AppSettings:Token").Value;
 
SymmetricSecurityKey tokenKey = new SymmetricSecurityKey(
    Encoding.UTF8.GetBytes(
        tokenKeyString != null ? tokenKeyString : ""
    )
);

In order to verify that the signature of the token our user passes back to us matches the signature of the token we issued, we need to provide the same SymmetricSecurityKey to our TokenValidationParameters.



string? tokenKeyString = builder.Configuration.GetSection("AppSettings:Token").Value;
 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters() 
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                tokenKeyString != null ? tokenKeyString : ""
            )),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });


This code snippet will use the same logic from to ensure that the string returned by GetSection() is not null.