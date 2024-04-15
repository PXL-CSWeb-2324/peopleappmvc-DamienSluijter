using Microsoft.EntityFrameworkCore;
using PeopleApp.Api.Data;
using PeopleApp.Api.Services.Interfaces;
using PeopleApp.Api.Services.Results;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.Services
{
    public class PersonService : IPersonService
    {
        DataContext _context;
        public PersonService(DataContext context)
        {
            _context = context;
        }
        public ApiResult<Person> Get()
        {
            var result = new ApiResult<Person>();
            try
            {
                result.Entities = _context.People;
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Person> GetById(long id)
        {
            var result = new ApiResult<Person>();
            try
            {
                result.Entities = _context.People.Where(x => x.Id == id);
                result.Entity = result.Entities.FirstOrDefault();
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Person> Add(PersonViewModel viewModel)
        {
            var result = new ApiResult<Person>();
            try
            {
                var person = new Person();
                person.Firstname = viewModel.Firstname;
                _context.People.Add(person);
                _context.SaveChanges();
                result.Entity = person;
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Person> DeleteById(long id)
        {
            var result = new ApiResult<Person>();
            try
            {
                var person = _context.People.Find(id);
                if (person != null)
                {
                    return Delete(person);
                }
                else
                {
                    result.Failed("Person is not found!");
                }
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Person> Delete(Person person)
        {
            var result = new ApiResult<Person>();
            try
            {
                _context.People.Remove(person);
                _context.SaveChanges();
                result.Succeeded = true;
            }
            catch (Exception ex)
            {
                result.Failed(ex.Message);
            }
            return result;
        }
        public ApiResult<Person> Update(Person person)
        {
            var result = new ApiResult<Person>();
            try
            {
                _context.People.Update(person);
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
