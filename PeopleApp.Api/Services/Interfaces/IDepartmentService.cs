using PeopleApp.Api.Services.Results;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.Services.Interfaces
{
    public interface IDepartmentService
    {
        ApiResult<Department> Get();
        ApiResult<Department> GetById(long id);
        ApiResult<Department> Add(DepartmentViewModel department);
        ApiResult<Department> Update(Department department);
        ApiResult<Department> DeleteById(long id);
        ApiResult<Department> Delete(Department department);
    }
}
