using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Catalyst.Modules.Repository.CosmosDb;
using DocumentStamp.Helper;
using DocumentStamp.Http.Response;
using DocumentStamp.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using RestSharp;

namespace DocumentStamp.Function
{
    public class GetStamps
    {
        private readonly RestClient _restClient;
        private readonly CosmosDbRepository<DocumentStampMetaData> _documentStampMetaDataRepository;
        public GetStamps(RestClient restClient, CosmosDbRepository<DocumentStampMetaData> documentStampMetaDataRepository)
        {
            _restClient = restClient;
            _documentStampMetaDataRepository = documentStampMetaDataRepository;
        }

        [FunctionName("GetStamps")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "GetStamps/{publicKey}/{page}/{count}")]
            HttpRequest req,
            ClaimsPrincipal principal,
            string publicKey,
            int page,
            int count,
            ILogger log)
        {
#if (DEBUG)
            principal = JwtDebugTokenHelper.GenerateClaimsPrincipal();
#endif
            page--;
            var userId = principal.Claims.First(x => x.Type == "sub").Value;

            publicKey = publicKey.ToLowerInvariant();
            log.LogInformation("GetStamps processing a request");

            try
            {
                var documentStamp = _documentStampMetaDataRepository.FindAll(x => x.PublicKey == publicKey && x.User == userId).Skip(page * count).Take(count).OrderByDescending(x => x.StampDocumentProof.TimeStamp);
                var stampedDocumentList = documentStamp.Select(x => new StampDocumentResponse() { FileName = x.FileName, StampDocumentProof = x.StampDocumentProof }).ToList();

                return new OkObjectResult(new Result<IEnumerable<StampDocumentResponse>>(true, stampedDocumentList));
            }
            catch (InvalidDataException ide)
            {
                return new BadRequestObjectResult(new Result<string>(false, ide.ToString()));
            }
            catch (Exception exc)
            {
                return new BadRequestObjectResult(new Result<string>(false, exc.ToString()));
            }
        }
    }
}