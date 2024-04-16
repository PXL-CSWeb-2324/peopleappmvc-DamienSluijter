using Microsoft.AspNetCore.Mvc;
using PeopleApp.ClassLib.Models;
using PeopleApp.Mvc.Services.Interfaces;

namespace PeopleApp.Mvc.Controllers
{
    public class DepartmentController : Controller
    {
        IDepartmentRepository _repo;

        public DepartmentController(IDepartmentRepository repo)
        {
            _repo = repo;
        }

        public async Task<IActionResult> IndexAsync()
        {
            var result = await _repo.GetAsync();
            if (result.Succeeded)
            {
                return View(result.Entities);
            }
            return View(Enumerable.Empty<Department>());
        }

        [HttpPost]
        public async Task<IActionResult> CreateAsync(Department department)
        {
            if (ModelState.IsValid)
            {
                var result = await _repo.AddAsync(department);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                ModelState.AddModelError("", result.Error);
            }
            return View();
        }

        public async Task<IActionResult> DetailsAsync(long id)
        {
            var result = await _repo.GetByIdAsync(id);

            if (result.Succeeded)
            {
                return View(result.Entity);
            }

            ModelState.AddModelError("", result.Error);

            return View();
        }
    }
}
