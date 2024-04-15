using PeopleApp.Api.Services.Results;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.Services.Interfaces
{
    public interface IPersonService
    {
        ApiResult<Person> Get();
        ApiResult<Person> GetById(long id);
        ApiResult<Person> Add(PersonViewModel person);
        ApiResult<Person> Update(Person person);
        ApiResult<Person> DeleteById(long id);
        ApiResult<Person> Delete(Person person);
    }
}
