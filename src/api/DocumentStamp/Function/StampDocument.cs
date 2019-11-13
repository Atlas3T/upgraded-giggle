using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Abstractions.Rpc;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.IO.Messaging.Correlation;
using Catalyst.Core.Lib.IO.Messaging.Dto;
using Catalyst.Core.Lib.P2P;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Protocol.Peer;
using Catalyst.Protocol.Rpc.Node;
using DocumentStamp.Helper;
using DocumentStamp.Http.Request;
using DocumentStamp.Http.Response;
using DocumentStamp.Validator;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using TheDotNetLeague.MultiFormats.MultiBase;

namespace DocumentStamp.Function
{
    public class StampDocument
    {
        private readonly IRpcClient _rpcClient;
        private readonly PeerSettings _peerSettings;
        private readonly FfiWrapper _cryptoContext;
        private readonly IPrivateKey _privateKey;
        private readonly PeerId _recipientPeer;

        public StampDocument(IRpcClient rpcClient, PeerSettings peerSettings, FfiWrapper cryptoContext, IPrivateKey privateKey, PeerId recipientPeer)
        {
            _rpcClient = rpcClient;
            _peerSettings = peerSettings;
            _cryptoContext = cryptoContext;
            _privateKey = privateKey;
            _recipientPeer = recipientPeer;
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
                using var autoResetEvent = new AutoResetEvent(false);

                //Validate the request model sent by the user or client
                var stampDocumentRequest =
                    ModelValidator.ValidateAndConvert<StampDocumentRequest>(await req.ReadAsStringAsync());

                //Verify the signature of the stamp document request
                var verifyResult = SignatureHelper.VerifyStampDocumentRequest(stampDocumentRequest);
                if (!verifyResult)
                {
                    throw new InvalidDataException("Could not verify signature of document stamp request");
                }

                var receiverPublicKey = _cryptoContext.GetPublicKeyFromBytes(stampDocumentRequest.PublicKey.FromBase32());

                //Construct DocumentStamp smart contract data
                var userProofJson = JsonConvert.SerializeObject(stampDocumentRequest);
                var transaction =
                    StampTransactionHelper.GenerateStampTransaction(_privateKey, receiverPublicKey,
                        userProofJson.ToUtf8Bytes(), 1, 1);
                var protocolMessage =
                    transaction.ToProtocolMessage(_peerSettings.PeerId, CorrelationId.GenerateCorrelationId());

                //Connect to the node
                await _rpcClient.StartAsync();
                log.LogInformation($"Connected to node {_rpcClient.Channel.Active}");

                ResponseCode? responseCode = null;

                //Listen to BroadcastRawTransactionResponse responses from the node.
                using var nodeListener = _rpcClient.SubscribeToResponse<BroadcastRawTransactionResponse>(x =>
                {
                    responseCode = x.ResponseCode;
                    autoResetEvent.Set();
                });

                //Send transaction to node
                log.LogInformation($"Sending transaction to node");
                await _rpcClient.Channel.WriteAsync(new MessageDto(protocolMessage, _recipientPeer))
                    .ConfigureAwait(false);

                //Wait for node response then generate azure function response
                log.LogInformation($"Waiting for response");
                var signaled = autoResetEvent.WaitOne(TimeSpan.FromSeconds(10));
                if (!signaled)
                {
                    return new BadRequestObjectResult(new Result<string>(false,
                        "Timed out waiting for response from node."));
                }

                if (responseCode != ResponseCode.Successful)
                {
                    throw new InvalidDataException(
                        $"Stamp document returned an invalid response code: {responseCode}");
                }

                var stampDocumentResponse =
                    HttpHelper.GetStampDocument(Environment.GetEnvironmentVariable("NodeWebAddress"),
                        transaction.Transaction.Signature.RawBytes.ToByteArray().ToBase32().ToUpperInvariant());
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