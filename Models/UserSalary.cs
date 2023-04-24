namespace DotnetAPI.Models
{//modelos deberían ser parciales
    public partial class UserSalary
    {
        public int UserId {get; set;}
        public decimal Salary {get; set;}
        public decimal AvgSalary {get; set;}
        
        //no necesitamos constructor porque un decimal está permitido que sea null
    }
}