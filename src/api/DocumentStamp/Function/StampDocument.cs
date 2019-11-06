using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Autofac;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Abstractions.Keystore;
using Catalyst.Abstractions.P2P;
using Catalyst.Abstractions.Rpc;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.IO.Messaging.Correlation;
using Catalyst.Core.Lib.IO.Messaging.Dto;
using Catalyst.Protocol.Peer;
using Catalyst.Protocol.Rpc.Node;
using DocumentStamp.Helper;
using DocumentStamp.Http.Request;
using DocumentStamp.Http.Response;
using DocumentStamp.Model;
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
        //private readonly AutoResetEvent _autoResetEvent;
        //private readonly Config _config;
        //private readonly IPeerSettings _peerSettings;
        //private readonly ICryptoContext _cryptoContext;
        //private readonly IPrivateKey _privateKey;
        //private readonly IRpcClient _rpcClient;
        //private readonly PeerId _recipientPeer;

        //public StampDocument(Config config, IPeerSettings peerSettings, ICryptoContext cryptoContext,
        //    IPrivateKey privateKey, IRpcClient rpcClient,
        //    PeerId recipientPeer)
        //{
        //    _autoResetEvent = new AutoResetEvent(false);
        //    _config = config;
        //    _peerSettings = peerSettings;
        //    _cryptoContext = cryptoContext;
        //    _privateKey = privateKey;
        //    _rpcClient = rpcClient;
        //    _recipientPeer = recipientPeer;
        //}

        [FunctionName("StampDocument")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("StampDocument processing a request");

            try
            {
                //var rpcClientConfig = container.Resolve<IRpcClientConfig>();
                //            builder.Services.AddSingleton(container.Resolve<Config>());
                //            builder.Services.AddSingleton(container.Resolve<IPeerSettings>());
                //            builder.Services.AddSingleton(container.Resolve<ICryptoContext>());
                //            builder.Services.AddSingleton(keyStore.KeyStoreDecrypt(KeyRegistryTypes.DefaultKey));
                //            builder.Services.AddSingleton(container.Resolve<IRpcClient>());
                //            builder.Services.AddSingleton(rpcClientConfig.PublicKey.BuildPeerIdFromBase32Key(rpcClientConfig.HostAddress, rpcClientConfig.Port));

                var autoResetEvent = new AutoResetEvent(false);
                var containerBuilder = AutoFacHelper.GenerateRpcClientContainerBuilder();
                var container = containerBuilder.Build();
                var keyStore = container.Resolve<IKeyStore>();
                var rpcClient = container.Resolve<IRpcClient>();
                var cryptoContext = container.Resolve<ICryptoContext>();
                var peerSettings = container.Resolve<IPeerSettings>();
                var config = container.Resolve<Config>();
                var rpcClientConfig = container.Resolve<IRpcClientConfig>();
                var recipientPeer = rpcClientConfig.PublicKey.BuildPeerIdFromBase32Key(rpcClientConfig.HostAddress, rpcClientConfig.Port);
                var privateKey = keyStore.KeyStoreDecrypt(KeyRegistryTypes.DefaultKey);
                var publicKey = privateKey.GetPublicKey();

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
                    cryptoContext.GetPublicKeyFromBytes(stampDocumentRequest.PublicKey.FromBase32());

                //Connect to the node
                await rpcClient.StartAsync();

                //Listen to BroadcastRawTransactionResponse responses from the node.
                rpcClient.SubscribeToResponse<BroadcastRawTransactionResponse>(x =>
                {
                    if (x.ResponseCode != ResponseCode.Successful)
                    {
                        throw new InvalidDataException(
                            $"Stamp document returned an invalid response code: {x.ResponseCode}");
                    }

                    autoResetEvent.Set();
                });

                //Construct DocumentStamp smart contract data
                var userProofJson = JsonConvert.SerializeObject(stampDocumentRequest);
                var transaction =
                    StampTransactionHelper.GenerateStampTransaction(privateKey, receiverPublicKey,
                        userProofJson.ToUtf8Bytes(), 1, 1);
                var protocolMessage =
                    transaction.ToProtocolMessage(peerSettings.PeerId, CorrelationId.GenerateCorrelationId());

                rpcClient.SendMessage(new MessageDto(protocolMessage, recipientPeer));

                //Wait for node response then generate azure function response
                autoResetEvent.WaitOne();

                var stampDocumentResponse =
                    HttpHelper.GetStampDocument(config.NodeConfig.WebAddress,
                        transaction.Transaction.Signature.RawBytes.ToByteArray().ToBase32().ToUpperInvariant());
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