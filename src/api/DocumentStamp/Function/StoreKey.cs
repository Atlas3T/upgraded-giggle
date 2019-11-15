using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Catalyst.Core.Lib.DAO;
using DocumentStamp.Helper;
using DocumentStamp.Http.Request;
using DocumentStamp.Http.Response;
using DocumentStamp.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using RestSharp;

namespace DocumentStamp.Function
{
    //public class GetStamps
    //{
    //    [FunctionName("GetStamps2")]
    //    public async Task<IActionResult> Run(
    //        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "GetStamps/{publicKey}")]
    //        string publicKey,
    //        ILogger log)
    //    {
    //        log.LogInformation("GetStamps processing a request");

    //        try
    //        {
    //            return new OkObjectResult(new Result<IEnumerable<StampDocumentResponse>>(true, stampedDocumentList));
    //        }
    //        catch (InvalidDataException ide)
    //        {
    //            return new BadRequestObjectResult(new Result<string>(false, ide.ToString()));
    //        }
    //        catch (Exception exc)
    //        {
    //            return new BadRequestObjectResult(new Result<string>(false, exc.ToString()));
    //        }
    //    }
    //}
}