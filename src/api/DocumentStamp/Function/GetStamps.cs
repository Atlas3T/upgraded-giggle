using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Catalyst.Core.Lib.DAO;
using Catalyst.Modules.Repository.CosmosDb;
using DocumentStamp.Helper;
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
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "GetStamps/{publicKey}")]
            HttpRequest req,
            ClaimsPrincipal principal,
            string publicKey,
            ILogger log)
        {
#if (DEBUG)
            principal = JwtDebugTokenHelper.GenerateClaimsPrincipal();
#endif

            var userId = principal.Claims.First(x => x.Type == "sub").Value;

            publicKey = publicKey.ToLowerInvariant();
            log.LogInformation("GetStamps processing a request");

            try
            {
                var request = new RestRequest("/api/Mempool/GetTransactionsByPublickey/{publicKey}", Method.GET);
                request.AddUrlSegment("publicKey", publicKey);

                var response = _restClient.Execute<List<TransactionBroadcastDao>>(request);
                var transactionBroadcastDaoList = response.Data;
                if (transactionBroadcastDaoList == null)
                {
                    throw new InvalidDataException("Could not find stamps.");
                }

                var stampedDocumentList = new List<StampDocumentResponse>();
                foreach (var transactionBroadcastDao in transactionBroadcastDaoList)
                {
                    try
                    {
                        var smartContract = transactionBroadcastDao.ContractEntries.First();
                        var smartContractData = Encoding.UTF8.GetString(Convert.FromBase64String(smartContract.Data));
                        var userProof = JsonConvert.DeserializeObject<UserProof>(smartContractData);

                        //Verify the signature of the stamp document request
                        var verifyResult = SignatureHelper.VerifyStampDocumentRequest(userProof);
                        if (!verifyResult)
                        {
                            throw new InvalidDataException("Could not verify signature of document stamp request");
                        }

                        var documentStamp = _documentStampMetaDataRepository.FindAll(x => x.PublicKey == publicKey);
                        stampedDocumentList = documentStamp.Select(x => new StampDocumentResponse() { FileName = x.FileName, StampDocumentProof = x.StampDocumentProof }).ToList();
                    }
                    catch (Exception exc)
                    {
                        //Invalid timestamp
                    }
                }

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