después de instalar todas las librerías de mysql , configuramos dentro de un directorio Data en la raíz
un archivo DataContextDapper.cs

using System.Data;
using Microsoft.Data.SqlClient;
using Dapper;
using Microsoft.Extensions.Configuration;

namespace HelloWorld.Data
{
    public class DataContextDapper
    {

        private readonly IConfiguration _config;

        public DataContextDapper(IConfiguration config)
        {
            _config = config;
        }

        public IEnumerable<T> LoadData<T>(string sql)
        {
            IDbConnection dbConnection = new SqlConnection(_config.GetConnectionString("DefaultConnection"));
            return dbConnection.Query<T>(sql);
        }

        public T LoadDataSingle<T>(string sql)
        {
            IDbConnection dbConnection = new SqlConnection(_config.GetConnectionString("DefaultConnection"));
            return dbConnection.QuerySingle<T>(sql);
        }
    }
}

y el controlador de usuario de la siguiente manera



using System;
using HelloWorld.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;


[ApiController]
[Route("[controller]")]//el endPoint de la url es el nombre que pongamos antes de Controller
// public class ClienteController , el endpoint será /Cliente
public class UserController : ControllerBase
{
    DataContextDapper _dapper;
    public UserController(IConfiguration config)
    {
        _dapper = new DataContextDapper(config);
    }

    [HttpGet("TestConection")]
    
    public DateTime TestConnection()
    {
        return _dapper.LoadDataSingle<DateTime>("SELECT GETDATE()");
    }

    [HttpGet("GetUsers/{testValue}")] // de esta manera el endpoint será /User/GetUsers/{testValue}
    //retornamos un IEnumerable del modelo que creemos
    public string[] GetUsers(string testValue)
    {

        return new string[] {"user1","user2" , testValue};

        /* return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray(); */
    }
}


con esto en swagger podremos probar la conexión