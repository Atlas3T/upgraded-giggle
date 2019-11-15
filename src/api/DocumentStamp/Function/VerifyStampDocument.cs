using System;
using System.IO;
using DocumentStamp.Helper;
using DocumentStamp.Http.Response;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using RestSharp;

namespace DocumentStamp.Function
{
    public class VerifyStampDocument
    {
        private readonly RestClient _restClient;
        public VerifyStampDocument(RestClient restClient)
        {
            _restClient = restClient;
        }

        [FunctionName("VerifyStampDocument")]
        public IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "VerifyStampDocument/{txId}")]
            HttpRequest req,
            string txId,
            ILogger log)
        {
            log.LogInformation("VerifyStampDocument processing a request");

            try
            {
                var stampDocumentResponse =
                    HttpHelper.GetStampDocument(_restClient, txId);
                return new OkObjectResult(new Result<StampDocumentResponse>(true, stampDocumentResponse));
            }
            catch (InvalidDataException ide)
            {
                return new BadRequestObjectResult(new Result<string>(false, ide.Message));
            }
            catch (Exception exc)
            {
                return new BadRequestObjectResult(new Result<string>(false, exc.Message));
            }
        }
    }
}