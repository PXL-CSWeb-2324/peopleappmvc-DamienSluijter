using PeopleApp.Mvc.Helpers;
using PeopleApp.Mvc.Services;
using PeopleApp.Mvc.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<IDepartmentRepository, DepartmentRepository>();

builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient(
    ApiHelper.ClientName,
    client => { client.BaseAddress = ApiHelper.BaseAddress; });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
