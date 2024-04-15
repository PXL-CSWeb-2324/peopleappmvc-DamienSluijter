using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PeopleApp.Api.Data;
using PeopleApp.Api.ViewModels;
using PeopleApp.ClassLib.Models;
using System;

namespace PeopleApp.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LocationController : ControllerBase
    {
        DataContext _context;
        public LocationController(DataContext context)
        {
            _context = context;
        }
        #region Get
        [HttpGet]
        public IActionResult GetLocations()
        {
            try
            {
                var locations = _context.Locations;
                return Ok(locations);
            }
            catch (Exception)
            {
                return BadRequest();
            }            
        }
        [HttpGet("{id}")]
        public IActionResult GetDetails(long id)
        {
            Location location = _context.Locations.Find(id);
            if (location == null)
            {
                return NotFound();
            }
            return Ok(location);
        }
        #endregion
        #region Post
        [HttpPost]
        public IActionResult AddLocation(LocationViewModel model)
        {
            try
            {
                Location location = new Location
                {
                    City = model.City,
                    State = model.State
                };
                _context.Locations.Add(location);
                _context.SaveChanges();                
                return Ok(location);
            }
            catch (Exception)
            {
                return BadRequest();
            }            
        }

        #endregion
        #region Update
        [HttpPut]
        public IActionResult UpdatePerson(Location model)
        {
            try
            {
                _context.Locations.Update(model);
                _context.SaveChanges();
                return Ok();
            }
            catch (Exception)
            {
                return BadRequest();
                throw;
            } 
        }
        #endregion
        #region Delete
        [HttpDelete("{id}")]
        public IActionResult DeleteLocation(long id)
        {
            Location location = _context.Locations.Find(id);
            if (location == null)
            {
                return NotFound();
            }
            _context.Locations.Remove(location);
            _context.SaveChanges();
            return Ok();
        }

        #endregion
    }
}

