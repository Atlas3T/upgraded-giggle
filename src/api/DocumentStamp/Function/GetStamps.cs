using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Catalyst.Core.Lib.DAO;
using DocumentStamp.Helper;
using DocumentStamp.Http.Response;
using DocumentStamp.Model;
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
        public GetStamps(RestClient restClient)
        {
            _restClient = restClient;
        }

        [FunctionName("GetStamps")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "GetStamps/{publicKey}")]
            string publicKey,
            ILogger log)
        {
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

                        var stampDocument = new StampDocumentResponse
                        {
                            TransactionId = transactionBroadcastDao.Id.ToUpper(),
                            TimeStamp = transactionBroadcastDao.TimeStamp,
                            UserProof = userProof,
                            NodeProof = new NodeProof
                            {
                                PublicKey = smartContract.Base.SenderPublicKey.ToUpper(),
                                Signature = transactionBroadcastDao.Signature.RawBytes.ToUpper()
                            }
                        };

                        stampedDocumentList.Add(stampDocument);
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