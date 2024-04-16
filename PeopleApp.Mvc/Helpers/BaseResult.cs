namespace PeopleApp.Mvc.Helpers
{
    public class BaseResult
    {
        public bool Succeeded { get; set; }
        public string? Error { get; set; }
        public void Failed(string message)
        {
            Error = message;
            Succeeded = false;
        }
    }
}
