using DotnetAPI.Data;
using DotnetAPI.Dtos;
using System.Security.Cryptography;
using System.Text;
using System.Data;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace DotnetAPI.Controllers
{
    public class AuthController : ControllerBase
    {
        private readonly DataContextDapper _dapper;
        private readonly IConfiguration _config;
        public AuthController(IConfiguration config)
        {
            _dapper = new DataContextDapper(config);
            _config = config;
        }

        [HttpPost("Register")]
        public IActionResult Register(UserForRegistrationDto userForRegistration)
        {
            if( userForRegistration.Password == userForRegistration.PasswordConfirm )
            { 
                string sqlCheckUsersExists = "SELECT Email FROM TutorialAppSchema.Auth WHERE Email = '"+ 
                    userForRegistration.Email +"'";
                
                IEnumerable<string> existingUser = _dapper.LoadData<string>(sqlCheckUsersExists);
                if(existingUser.Count() == 0)
                {
                    byte[] passwordSalt = new byte[128 / 8];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    {
                        rng.GetNonZeroBytes(passwordSalt);
                    }

                    byte[] passwordHash = GetPasswordHash(userForRegistration.Password , passwordSalt);

                    string sqlAddAuth = @"
                        INSERT INTO TutorialAppSchema.Auth (
                            [Email],
                            [PasswordHash],
                            [PasswordSalt]
                        ) VALUES ('" + userForRegistration.Email + 
                        "', @PasswordHash, @PasswordSalt)";

                    List<SqlParameter> sqlParameters = new List<SqlParameter>();

                    SqlParameter passwordSaltParameter = new SqlParameter("@PasswordSalt",SqlDbType.VarBinary);
                    passwordSaltParameter.Value = passwordSalt;
                    
                    SqlParameter passwordHashParameter = new SqlParameter("@PasswordHash",SqlDbType.VarBinary);
                    passwordHashParameter.Value = passwordHash;  

                    sqlParameters.Add(passwordSaltParameter);
                    sqlParameters.Add(passwordHashParameter);

                    if(_dapper.ExecuteSqlWithParameters(sqlAddAuth , sqlParameters))
                    {
                        return Ok();
                    }

                    throw new Exception("Failed to register user . ");
                         
                } 
                throw new Exception("User with this email already exists");
            }
            throw new Exception("Passwords do not match");
        } 

        [HttpPost("Login")]
        public IActionResult Login(UserForLoginDto userForLogin)
        {
            string sqlForHashAndSalt = @"SELECT 
                [PasswordHash],
                [PasswordSalt] FROM TutorialAppSchema.Auth WHERE Email = '" +
                userForLogin.Email + "'";

            UserForLoginConfirmationDto userForConfirmation = _dapper
                .LoadDataSingle<UserForLoginConfirmationDto>(sqlForHashAndSalt);

            byte[] passwordHash = GetPasswordHash(userForLogin.Password, userForConfirmation.PasswordSalt);

            // if (passwordHash == userForConfirmation.PasswordHash) // Won't work

            for (int index = 0; index < passwordHash.Length; index++)
            {
                if (passwordHash[index] != userForConfirmation.PasswordHash[index]){
                    return StatusCode(401, "Incorrect password!");
                }
            }

            return Ok();
        }

        private byte[] GetPasswordHash(string password, byte[] passwordSalt)
        {
            string passwordSaltPlusString = _config.GetSection("AppSettings:PasswordKey").Value +
                Convert.ToBase64String(passwordSalt);

            return KeyDerivation.Pbkdf2(
                password: password,
                salt: Encoding.ASCII.GetBytes(passwordSaltPlusString),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 1000000,
                numBytesRequested: 256 / 8
            );
        }

    }
}