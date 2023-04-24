using DotnetAPI.Models;

namespace DotnetAPI.Data
{
    // a partir de ahora solo podemos acceder a esta clase a través de esta interface
    // CHECKEA LA NUEVA LINEA QUE SE AÑADE EN PROGRAM.CS
    public class UserRepository : IUserRepository
    {
        DataContextEF _entityFramework;
    
        public UserRepository(IConfiguration config)
        {
            _entityFramework = new DataContextEF(config); 
        }

        public bool SaveChanges()
        {
            return _entityFramework.SaveChanges() > 0;
        }

        public void AddEntity<T>(T entityToAdd)
        {
            if (entityToAdd != null)
            {
                _entityFramework.Add(entityToAdd);
            }
        }

        /* si quisieramo retornar un booleano */
        /* public bool AddEntity<T>(T entityToAdd)
        {
            if (entityToAdd != null)
            {
                _entityFramework.Add(entityToAdd);
                return true;
            }
            return false;
        } */

        public void RemoveEntity<T>(T entityToAdd)
        {
            if (entityToAdd != null)
            {
                _entityFramework.Remove(entityToAdd);
            }
        }

        public IEnumerable<User> GetUsers()
        {
            IEnumerable<User> users = _entityFramework.Users.ToList<User>();
            return users;
        }

        public User GetSingleUser(int userId)
        {
            User? user = _entityFramework.Users
                .Where(u => u.UserId == userId)
                .FirstOrDefault<User>();

            if(user != null)
            {
                return user;
            }

            throw new Exception("No se encontró usuario con id : " + userId);
        }

        public UserSalary GetSingleUserSalary(int userId)
        {
            UserSalary? userSalary = _entityFramework.UserSalary
                .Where(u => u.UserId == userId)
                .FirstOrDefault<UserSalary>();

            if(userSalary != null)
            {
                return userSalary;
            }

            throw new Exception("No se encontró el salario de el usuario " );
        }

        public UserJobInfo GetSingleUserJobInfo(int userId)
        {
            UserJobInfo? userJobInfo = _entityFramework.UserJobInfo
                .Where(u => u.UserId == userId)
                .FirstOrDefault<UserJobInfo>();

            if(userJobInfo != null)
            {
                return userJobInfo;
            }

            throw new Exception("No se encontró la info del puesto de este usuario ");
        }
    }
}