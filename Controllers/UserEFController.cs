using AutoMapper;
using DotnetAPI.Data;
using DotnetAPI.Models;
using DotnetAPI.Dtos;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class UserEFController : ControllerBase
{
    DataContextEF _entityFramework;
    IUserRepository _userRepository;
    IMapper _mapper;
    
    public UserEFController(IConfiguration config , IUserRepository userRepository)
    {
        _entityFramework = new DataContextEF(config); 
        _userRepository = userRepository;
        _mapper = new Mapper(new MapperConfiguration(cfg => {
            cfg.CreateMap<UserToAddDto , User>();
        }));
    }

    [HttpGet("GetUsers")] 
    public IEnumerable<User> GetUsers()
    {
        IEnumerable<User> users = _userRepository.GetUsers();
        return users;
    }

    [HttpGet("GetSingelUser/{userId}")] 
    public User GetSingleUser(int userId)
    {
        return _userRepository.GetSingleUser(userId);
    }

    [HttpPut("EditUser")]
    
    public IActionResult EditUser(User user) 
    {
        User? userDb = _userRepository.GetSingleUser(user.UserId);

        if(userDb != null)
        {
            userDb.Active = user.Active;
            userDb.FirstName = user.FirstName;
            userDb.LastName = user.LastName;
            userDb.Email = user.Email;
            userDb.Gender = user.Gender;

            if( _userRepository.SaveChanges() /* _userRepository.SaveChanges() */)
            {
                return Ok();
            }
        }

        throw new Exception("Error al actualizar usuario");
    }

    [HttpPost("AddUser")]
    public IActionResult AddUser(UserToAddDto user)
    {
        User userDb = _mapper.Map<User>(user);

        _userRepository.AddEntity<User>(userDb);
        if(_userRepository.SaveChanges())
        {
            return Ok();
        }
        throw new Exception("Error al añadir usuario");
    }

    [HttpDelete("GetSingelUser/{userId}")]
    public IActionResult  DeleteUser(int userId)
    {
        User? userDb = _entityFramework.Users
            .Where(u => u.UserId == userId)
            .FirstOrDefault<User>();

        if(userDb != null)
        {
            /* _entityFramework.Users.Remove */_userRepository.RemoveEntity<User>(userDb);
            if(_userRepository.SaveChanges())
            {
                return Ok();
            }
        }

        throw new Exception("Error al borrar usuario");
    }

    /********************* SALARY ***************************/

    [HttpGet("UserSalary/{userId}")]
    public IEnumerable<UserSalary> GetUserSalaryEF(int userId)
    {
        return _entityFramework.UserSalary
            .Where(u => u.UserId == userId)
            .ToList();
    }

    [HttpPost("UserSalary")]
    public IActionResult PostUserSalaryEf(UserSalary userForInsert)
    {
        _userRepository.AddEntity<UserSalary>(userForInsert);
        if (_userRepository.SaveChanges())
        {
            return Ok();
        }
        throw new Exception("Adding UserSalary failed on save");
    }


    [HttpPut("UserSalary")]
    public IActionResult PutUserSalaryEf(UserSalary userForUpdate)
    {
        UserSalary? userToUpdate = _entityFramework.UserSalary
            .Where(u => u.UserId == userForUpdate.UserId)
            .FirstOrDefault();

        if (userToUpdate != null)
        {
            _mapper.Map(userToUpdate, userForUpdate);
            if (_userRepository.SaveChanges())
            {
                return Ok();
            }
            throw new Exception("Updating UserSalary failed on save");
        }
        throw new Exception("Failed to find UserSalary to Update");
    }


    [HttpDelete("UserSalary/{userId}")]
    public IActionResult DeleteUserSalaryEf(int userId)
    {
        UserSalary? userToDelete = _entityFramework.UserSalary
            .Where(u => u.UserId == userId)
            .FirstOrDefault();

        if (userToDelete != null)
        {
            _userRepository.RemoveEntity<UserSalary>(userToDelete);
            if (_userRepository.SaveChanges())
            {
                return Ok();
            }
            throw new Exception("Deleting UserSalary failed on save");
        }
        throw new Exception("Failed to find UserSalary to delete");
    }

    /*************************** JOB INFO *******************************/
    [HttpGet("UserJobInfo/{userId}")]
    public IEnumerable<UserJobInfo> GetUserJobInfoEF(int userId)
    {
        return _entityFramework.UserJobInfo
            .Where(u => u.UserId == userId)
            .ToList();
    }

    [HttpPost("UserJobInfo")]
    public IActionResult PostUserJobInfoEf(UserJobInfo userForInsert)
    {
        _userRepository.AddEntity<UserJobInfo>(userForInsert);
        if (_userRepository.SaveChanges())
        {
            return Ok();
        }
        throw new Exception("Adding UserJobInfo failed on save");
    }


    [HttpPut("UserJobInfo")]
    public IActionResult PutUserJobInfoEf(UserJobInfo userForUpdate)
    {
        UserJobInfo? userToUpdate = _entityFramework.UserJobInfo
            .Where(u => u.UserId == userForUpdate.UserId)
            .FirstOrDefault();

        if (userToUpdate != null)
        {
            _mapper.Map(userToUpdate, userForUpdate);
            if (_userRepository.SaveChanges())
            {
                return Ok();
            }
            throw new Exception("Updating UserJobInfo failed on save");
        }
        throw new Exception("Failed to find UserJobInfo to Update");
    }


    [HttpDelete("UserJobInfo/{userId}")]
    public IActionResult DeleteUserJobInfoEf(int userId)
    {
        UserJobInfo? userToDelete = _entityFramework.UserJobInfo
            .Where(u => u.UserId == userId)
            .FirstOrDefault();

        if (userToDelete != null)
        {
            _userRepository.RemoveEntity<UserJobInfo>(userToDelete);
            if (_userRepository.SaveChanges())
            {
                return Ok();
            }
            throw new Exception("Deleting UserJobInfo failed on save");
        }
        throw new Exception("Failed to find UserJobInfo to delete");
    }
}


