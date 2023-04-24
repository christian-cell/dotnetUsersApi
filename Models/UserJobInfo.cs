namespace DotnetAPI.Models
{//modelos deberían ser parciales
    public partial class UserJobInfo
    {
        public int UserId {get; set;}
        public string JobTitle {get; set;}
        public string Department {get; set;}

        /* creamos un constructor para no hacer las propiedades nullables */
        public UserJobInfo()
        {
            if(JobTitle == null)
            {
                JobTitle = "";
            };
            if(Department == null)
            {
                Department = "";
            }
        }
    }
}
