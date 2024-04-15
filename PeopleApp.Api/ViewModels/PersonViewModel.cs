using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.ViewModels
{
    public class PersonViewModel
    {
        public string Firstname { get; set; }
        public string Surname { get; set; }        
        public long DepartmentId { get; set; }        
        public long LocationId { get; set; }
    }
}
