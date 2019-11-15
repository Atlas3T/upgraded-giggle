using System;
using System.IO;
using System.Threading.Tasks;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Core.Lib.DAO;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.IO.Messaging.Correlation;
using Catalyst.Core.Lib.P2P;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Protocol.Cryptography;
using Catalyst.Protocol.Network;
using Catalyst.Protocol.Peer;
using DocumentStamp.Helper;
using DocumentStamp.Http.Request;
using DocumentStamp.Http.Response;
using DocumentStamp.Validator;
using Google.Protobuf;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using RestSharp;
using TheDotNetLeague.MultiFormats.MultiBase;

namespace DocumentStamp.Function
{
    //https://github.com/Azure/DotNetty/issues/246 memoryleaks in dotnetty
    public class StampDocument
    {
        private readonly RestClient _restClient;
        private readonly PeerId _peerId;
        private readonly FfiWrapper _cryptoContext;
        private readonly IPrivateKey _privateKey;

        public StampDocument(RestClient restClient, PeerId peerId, FfiWrapper cryptoContext, IPrivateKey privateKey)
        {
            _restClient = restClient;
            _peerId = peerId;
            _cryptoContext = cryptoContext;
            _privateKey = privateKey;
        }

        [FunctionName("StampDocument")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
            HttpRequest req,
            Microsoft.Extensions.Logging.ILogger log)
        {
            log.LogInformation("StampDocument processing a request");

            try
            {
                //Validate the request model sent by the user or client
                var stampDocumentRequest =
                    ModelValidator.ValidateAndConvert<StampDocumentRequest>(await req.ReadAsStringAsync());

                //Verify the signature of the stamp document request
                var verifyResult = SignatureHelper.VerifyStampDocumentRequest(stampDocumentRequest);
                if (!verifyResult)
                {
                    throw new InvalidDataException("Could not verify signature of document stamp request");
                }

                var receiverPublicKey =
                    _cryptoContext.GetPublicKeyFromBytes(stampDocumentRequest.PublicKey.FromBase32());

                //Construct DocumentStamp smart contract data
                var userProofJson = JsonConvert.SerializeObject(stampDocumentRequest);
                var transaction =
                    StampTransactionHelper.GenerateStampTransaction(_cryptoContext, _privateKey, receiverPublicKey,
                        userProofJson.ToUtf8Bytes(), 1, 1);
                var protocolMessage =
                    StampTransactionHelper.ConvertToProtocolMessage(transaction, _cryptoContext, _privateKey,
                        _peerId);

                var request = new RestRequest("/api/Mempool/AddTransaction", Method.POST);
                request.AddQueryParameter("transactionBroadcastProtocolBase64", Convert.ToBase64String(protocolMessage.ToByteArray()));

                var response = _restClient.Execute<TransactionBroadcastDao>(request);
                if (response.Data == null)
                {
                    throw new InvalidDataException("DocumentStamp does not exist under txId");
                }

                var stampDocumentResponse =
                    HttpHelper.GetStampDocument(_restClient,
                        transaction.Signature.RawBytes.ToByteArray().ToBase32().ToUpperInvariant());
                return new OkObjectResult(new Result<StampDocumentResponse>(true, stampDocumentResponse));
            }
            catch (InvalidDataException ide)
            {
                return new BadRequestObjectResult(new Result<string>(false,
                    ide.ToString()));
            }
            catch (Exception exc)
            {
                return new BadRequestObjectResult(new Result<string>(false,
                    exc.ToString()));
            }
        }
    }
}