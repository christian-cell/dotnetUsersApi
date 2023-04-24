namespace DotnetAPI.Dtos
{//modelos deberían ser parciales
    public partial class UserToAddDto
    {
        public string FirstName {get; set;}
        public string LastName {get; set;}
        public string Email {get; set;}
        public string Gender {get; set;}
        public bool Active {get; set;}

        /* creamos un constructor para no hacer las propiedades nullables */
        public UserToAddDto()
        {
            if(FirstName == null)
            {
                FirstName = "";
            };
            if(LastName == null)
            {
                LastName = "";
            };
            if(Email == null)
            {
                Email = "";
            };
            if(Gender == null)
            {
                Gender = "";
            };
        }
    }
}