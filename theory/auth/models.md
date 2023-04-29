in DTOS folder

file UserForRegistrationDto.cs

namespace DotnetAPI.Dtos
{
    partial class UserForRegistrationDto
    {
        string Email {get ; set;}
        string Password {get ; set;}
        string PasswordConfirm {get ; set;}

        public UserForRegistrationDto()
        {
            if(Email == null)
            {
                Email = "";
            }
            if(Password == null)
            {
                Password = "";
            }
            if(PasswordConfirm == null)
            {
                PasswordConfirm = "";
            }
        }
    }
}

PARA EL LOGIN , vemos que en un login no necesitamos que confirme el password

namespace DotnetAPI.Dtos
{
    partial class UserForLoginDto
    {
        string Email {get ; set;}
        string Password {get ; set;}

        public UserForLoginDto()
        {
            if(Email == null)
            {
                Email = "";
            }
            if(Password == null)
            {
                Password = "";
            }
        }
    }
}

Para la confirmación

namespace DotnetAPI.Dtos
{
    partial class UserForLoginConfirmationDto
    {
        byte[] PasswordHass {get; set;}
        byte[] PasswordSalt {get; set;}

        UserForLoginConfirmationDto()
        {
            if(PasswordHass == null)
            {
                PasswordHass = new byte[0];
            }
            if(PasswordSalt == null)
            {
                PasswordSalt = new byte[0];
            }
        }
    }
}