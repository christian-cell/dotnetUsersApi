using DotnetAPI.Data;
using DotnetAPI.Models;
using DotnetAPI.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using System;
// using Internal; usando internal no puedo acceder a la Clase Console para debuggear

namespace DotnetAPI.Controllers;

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
    {   //_dapper va a ser la instancia de la clase . el método y la configuración
        return _dapper.LoadDataSingle<DateTime>("SELECT GETDATE()");
    }

    [HttpGet("GetUsers")] // de esta manera el endpoint será /User/GetUsers/{testValue}
    //retornamos un IEnumerable del modelo que creemos
    public IEnumerable<User> GetUsers()
    {
        //hay un máximo de 4000 caracteres que le podemos pasar a Dapper en una query
        string sql = @"
            SELECT 
                [UserId],
                [FirstName],
                [LastName],
                [Email],
                [Gender],
                [Active] 
            FROM TutorialAppSchema.Users
        ";
        //le passamos a dapper la query
        IEnumerable<User> users = _dapper.LoadData<User>(sql);
        return users;
        //return new string[] {"user1","user2" , testValue};

        /* return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray(); */
    }

    [HttpGet("GetSingleUser/{userId}")] 
    //en c# al declarar un método primero es la visibilidad , tipo del valor a retornar y nombre
    // osea en te caso public , tipo modelo Users y el nombre
    public User GetSingleUser(int userId)
    {
        string sql = @"
        SELECT 
            [UserId],
            [FirstName],
            [LastName],
            [Email],
            [Gender],
            [Active] 
        FROM TutorialAppSchema.Users
        WHERE UserId = " + userId.ToString(); //al llegar el userId como int lo convertimos a str

        //le passamos a dapper la query
        User user = _dapper.LoadDataSingle<User>(sql);
        return user;
        
    }

    [HttpPut("EditUser")/* /{userId} */]
    
    public IActionResult EditUser(User user)  //IActionResult es una interface que retorna una respusta http success or error
    {
        // tenemos que hacer un populate del string de la query con los valores que vienen por el param user
        // podemos en vez de pasar el parámetro del elemento a modificar , enviar el userId en el cuerpo
        // encontrará este userId y lo modificará
        string sql = @"
        UPDATE TutorialAppSchema.Users
        SET  
            [FirstName] = '" + user.FirstName + 
            "', [LastName] = '" + user.FirstName +  
            "', [Email] = '" + user.Email +  
            "', [Gender] = '" + user.Gender +  
            "', [Active] = '" + user.Active +  
        "' WHERE UserId = " + user.UserId;

        Console.WriteLine(sql);

        if(_dapper.ExecuteSql(sql))
        {
            return Ok();
        }

        throw new Exception("Filed to update user");
    }

    /* [HttpPost("AddUser")]
    public IActionResult AddUser(User user)
    {

        string sql = @"
           INSERT TutorialAppSchema.Users
            (
                [FirstName],
                [LastName],
                [Email],
                [Gender],
                [Active]
            )VALUES('" + user.FirstName + 
            "', '" + user.FirstName +  
            "', '" + user.Email +  
            "', '" + user.Gender +  
            "', '" + user.Active +
        "')";

        Console.WriteLine(sql);

        if(_dapper.ExecuteSql(sql))
        {
            return Ok();
        }

        throw new Exception("Filed to add user");
    } */

    /* con dto , cuando creamos un post no necesitamos el id */
    [HttpPost("AddUser")]
    public IActionResult AddUser(UserToAddDto user)
    {

        string sql = @"
           INSERT TutorialAppSchema.Users
            (
                [FirstName],
                [LastName],
                [Email],
                [Gender],
                [Active]
            )VALUES('" + user.FirstName + 
            "', '" + user.FirstName +  
            "', '" + user.Email +  
            "', '" + user.Gender +  
            "', '" + user.Active +
        "')";

        Console.WriteLine(sql);

        if(_dapper.ExecuteSql(sql))
        {
            return Ok();
        }

        throw new Exception("Filed to add user");
    }

    [HttpDelete("GetSingleUser/{userId}")]
    public string /* IAsyncResult */ DeleteUser(int userId)
    {
        string sql = @"
            DELETE FROM TutorialAppSchema.Users 
            WHERE UserId = 
        " + userId.ToString();

        Console.WriteLine(sql);

        if(_dapper.ExecuteSql(sql))
        {
            return "cliente eliminado";
            /* return Ok(); */
        }

        throw new Exception("Filed to delete user");
    }

    /****************************** SALARY ************************************/

    [HttpGet("UserSalary/{userId}")]
    public IEnumerable<UserSalary> GetUserSalary(int userId)
    {
        return _dapper.LoadData<UserSalary>(@"
            SELECT UserSalary.UserId
                    , UserSalary.Salary
                    , UserSalary.AvgSalary
            FROM  TutorialAppSchema.UserSalary
                WHERE UserId = " + userId.ToString());
    }

    [HttpPost("UserSalary")]
    public IActionResult PostUserSalary(UserSalary userSalaryForInsert)
    {
        string sql = @"
            INSERT INTO TutorialAppSchema.UserSalary (
                UserId,
                Salary
            ) VALUES (" + userSalaryForInsert.UserId.ToString()
                + ", " + userSalaryForInsert.Salary
                + ")";

        if (_dapper.ExecuteSqlWithRowCount(sql) > 0)
        {
            return Ok(userSalaryForInsert);
        }
        throw new Exception("Adding User Salary failed on save");
    }

    [HttpPut("UserSalary")]
    public IActionResult PutUserSalary(UserSalary userSalaryForUpdate)
    {
        string sql = "UPDATE TutorialAppSchema.UserSalary SET Salary=" 
            + userSalaryForUpdate.Salary
            + " WHERE UserId=" + userSalaryForUpdate.UserId.ToString();

        if (_dapper.ExecuteSql(sql))
        {
            return Ok(userSalaryForUpdate);
        }
        throw new Exception("Updating User Salary failed on save");
    }

    [HttpDelete("UserSalary/{userId}")]
    public IActionResult DeleteUserSalary(int userId)
    {
        string sql = "DELETE FROM TutorialAppSchema.UserSalary WHERE UserId=" + userId.ToString();

        if (_dapper.ExecuteSql(sql))
        {
            return Ok();
        }
        throw new Exception("Deleting User Salary failed on save");
    }

    [HttpGet("UserJobInfo/{userId}")]
    public IEnumerable<UserJobInfo> GetUserJobInfo(int userId)
    {
        return _dapper.LoadData<UserJobInfo>(@"
            SELECT  UserJobInfo.UserId
                    , UserJobInfo.JobTitle
                    , UserJobInfo.Department
            FROM  TutorialAppSchema.UserJobInfo
                WHERE UserId = " + userId.ToString());
    }

    [HttpPost("UserJobInfo")]
    public IActionResult PostUserJobInfo(UserJobInfo userJobInfoForInsert)
    {
        string sql = @"
            INSERT INTO TutorialAppSchema.UserJobInfo (
                UserId,
                Department,
                JobTitle
            ) VALUES (" + userJobInfoForInsert.UserId
                + ", '" + userJobInfoForInsert.Department
                + "', '" + userJobInfoForInsert.JobTitle
                + "')";

        if (_dapper.ExecuteSql(sql))
        {
            return Ok(userJobInfoForInsert);
        }
        throw new Exception("Adding User Job Info failed on save");
    }

    [HttpPut("UserJobInfo")]
    public IActionResult PutUserJobInfo(UserJobInfo userJobInfoForUpdate)
    {
        string sql = "UPDATE TutorialAppSchema.UserJobInfo SET Department='" 
            + userJobInfoForUpdate.Department
            + "', JobTitle='"
            + userJobInfoForUpdate.JobTitle
            + "' WHERE UserId=" + userJobInfoForUpdate.UserId.ToString();

        if (_dapper.ExecuteSql(sql))
        {
            return Ok(userJobInfoForUpdate);
        }
        throw new Exception("Updating User Job Info failed on save");
    }

    [HttpDelete("UserJobInfo/{userId}")]
    public IActionResult DeleteUserJobInfo(int userId)
    {
        string sql = @"
            DELETE FROM TutorialAppSchema.UserJobInfo 
                WHERE UserId = " + userId.ToString();
        
        Console.WriteLine(sql);

        if (_dapper.ExecuteSql(sql))
        {
            return Ok();
        } 

        throw new Exception("Failed to Delete User");
    }
}
