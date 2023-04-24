creamos unas políticas de CORS  para los environment de desarrollo y producción
en Program.cs antes de var app = builder.Build()

builder.Services.AddCors((options)=>{
    options.AddPolicy("DevCors",(corsBuilder)=>
        {
            corsBuilder.WithOrigins("http://localhost:4200","http://locahost:3000","http://localhost:8000")
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        });
    options.AddPolicy("ProdCors",(corsBuilder)=>
        {
            corsBuilder.WithOrigins("https://myProductionSite.com")
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        });
});

y añadimos la política que sea en el momento de arrancar

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseCors("DevCors");
    app.UseSwagger();
    app.UseSwaggerUI();
}
else 
{
    app.UseCors("ProdCors");
    app.UseHttpsRedirection();
}