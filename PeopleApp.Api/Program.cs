using Microsoft.EntityFrameworkCore;
using PeopleApp.Api.Data;
using PeopleApp.Api.Data.DefaultData;
using PeopleApp.Api.Services;
using PeopleApp.Api.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("PeopleConnection");
builder.Services.AddDbContext<DataContext>(options =>
    {
        options.UseSqlServer(connectionString);    
    });
builder.Services.AddScoped<IDepartmentService, DepartmentService>();
builder.Services.AddScoped<IPersonService, PersonService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
SeedData.SeedDatabase(app);
app.Run();
