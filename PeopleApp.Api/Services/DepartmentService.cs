using PeopleApp.Api.Data;
using PeopleApp.Api.Services.Interfaces;
using PeopleApp.Api.Services.Results;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.Services
{
    public class DepartmentService : IDepartmentService
    {
        DataContext _context;
        public DepartmentService(DataContext context)
        {
            _context = context;
        }
        public ApiResult<Department> Get()
        {
            var result = new ApiResult<Department>();
            try
            {
                result.Entities = _context.Departments;
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Department> GetById(long id)
        {
            var result = new ApiResult<Department>();
            try
            {
                result.Entities = _context.Departments.Where(x=>x.Id == id);
                result.Entity = result.Entities.FirstOrDefault();
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Department> Add(DepartmentViewModel departmentViewModel)
        {
            var result = new ApiResult<Department>();
            try
            {
                var department = new Department();
                department.Name = departmentViewModel.Name; 
                _context.Departments.Add(department);
                _context.SaveChanges();
                result.Entity = department;
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Department> DeleteById(long id)
        {
            var result = new ApiResult<Department>();
            try
            {
                var department = _context.Departments.Find(id);
                if(department!=null)
                {
                    return Delete(department);
                }
                else
                {
                    result.Failed("Department is not found!");
                }
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Department> Delete(Department department)
        {
            var result = new ApiResult<Department>();
            try
            {
                _context.Departments.Remove(department);
                _context.SaveChanges();
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }       

        public ApiResult<Department> Update(Department department)
        {
            var result = new ApiResult<Department>();
            try
            {
                _context.Departments.Update(department);
                _context.SaveChanges();
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
    }
}
