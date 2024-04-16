using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace PeopleApp.Api.Attributes
{

    [AttributeUsage(validOn: AttributeTargets.Class)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        private const string APIKEYNAME = "ApiKey";
        private ContentResult GetContentResult(int statusCode, string content)
        {
            var result = new ContentResult();
            result.StatusCode = statusCode;
            result.Content = content;
            return result;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            try
            {
                if (!context.HttpContext.Request.Headers.TryGetValue(APIKEYNAME, out var extractedApiKey))
                {
                    context.Result = GetContentResult(401, "Api Key was not provided");
                    return;
                }

                var appSettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                if (appSettings == null)
                {
                    context.Result = GetContentResult(401, "Appsettings not found");
                    return;
                }

                var ApiKey = appSettings.GetValue<string>(APIKEYNAME);
                if (ApiKey == null)
                {
                    context.Result = GetContentResult(401, "Appsettings - ApiKey - not found");
                    return;
                }

                if (!ApiKey.Equals(extractedApiKey))
                {
                    context.Result = GetContentResult(401, "ApiKey is not valid");
                    return;
                }
                await next();
            }
            catch (Exception ex)
            {
                context.Result = GetContentResult(401, ex.Message);
                return;
            }
        }
    }
}
