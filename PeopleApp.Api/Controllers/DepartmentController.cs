using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PeopleApp.Api.Data;
using PeopleApp.Api.Services.Interfaces;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;

namespace PeopleApp.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DepartmentController : ControllerBase
    {
        IDepartmentService _service;
        public DepartmentController(IDepartmentService service)
        {
            _service = service;
        }
        #region Get
        [HttpGet]
        public IActionResult Get()
        {
            try
            {
                var result = _service.Get();
                if(result.Succeeded)
                {
                    return Ok(result.Entities);
                }
                return BadRequest(result.Error);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("{id}")]
        public IActionResult GetDetails(long id)
        {
            try
            {
                var result = _service.GetById(id);
                if (result.Succeeded)
                {
                    return Ok(result.Entity);
                }
                return BadRequest(result.Error);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        #endregion
        #region Post
        [HttpPost]
        public IActionResult Add(DepartmentViewModel model)
        {
            try
            {
                var result = _service.Add(model);
                if (result.Succeeded)
                {
                    return Ok(result.Entity);
                }
                return BadRequest(result.Error);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        #endregion
        #region Update
        [HttpPut]
        public IActionResult Update(Department model)
        {
            try
            {
                var result = _service.Update(model);
                if (result.Succeeded)
                {
                    return Ok(result.Entity);
                }
                return BadRequest(result.Error);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        #endregion
        #region Delete
        [HttpDelete("{id}")]
        public IActionResult Delete(long id)
        {
            try
            {
                var result = _service.DeleteById(id);
                if (result.Succeeded)
                {
                    return Ok();
                }
                return BadRequest(result.Error);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        #endregion
    }
}
