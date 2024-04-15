namespace PeopleApp.Api.Services.Results
{
    abstract public class BaseResult
    {
        private string error;
        public string Error => error;
        public bool Succeeded { get; set; }
        public void Failed(string message)
        {
            error = message;
            Succeeded = false;
        }
    }
}
