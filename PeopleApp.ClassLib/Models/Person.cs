using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PeopleApp.ClassLib.Models
{
    public class Person
    {
        public long Id { get; set; }
        public string Firstname { get; set; }
        public string Surname { get; set; }
        public Department Department { get; set; }
        public long DepartmentId { get; set; }
        public Location Location { get; set; }
        public long LocationId { get; set; }
    }
}
