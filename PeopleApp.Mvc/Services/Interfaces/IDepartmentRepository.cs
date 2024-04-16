using PeopleApp.ClassLib.Models;
using PeopleApp.Mvc.Helpers;

namespace PeopleApp.Mvc.Services.Interfaces
{
    public interface IDepartmentRepository
    {
        Task<ApiResult<Department>> GetAsync();
        Task<ApiResult<Department>> GetByIdAsync(long id);
        Task<ApiResult<Department>> AddAsync(Department department);
    }
}
