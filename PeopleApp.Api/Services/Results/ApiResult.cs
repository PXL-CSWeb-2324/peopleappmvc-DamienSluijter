using System.ComponentModel;

namespace PeopleApp.Api.Services.Results
{
    public class ApiResult<T> : BaseResult
    {
        public IEnumerable<T>? Entities { get; set; }
        public T? Entity { get; set; }
    }
}
