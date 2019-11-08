using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Catalyst.Abstractions.IO.Observers;
using Catalyst.Abstractions.Rpc;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Lib.Cryptography;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.IO.EventLoop;
using Catalyst.Core.Lib.IO.Messaging.Correlation;
using Catalyst.Core.Lib.IO.Messaging.Dto;
using Catalyst.Core.Lib.P2P;
using Catalyst.Core.Lib.Rpc.IO.Messaging.Correlation;
using Catalyst.Core.Lib.Util;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Core.Modules.Hashing;
using Catalyst.Core.Modules.KeySigner;
using Catalyst.Core.Modules.Rpc.Client;
using Catalyst.Core.Modules.Rpc.Client.IO.Observers;
using Catalyst.Core.Modules.Rpc.Client.IO.Transport.Channels;
using Catalyst.Protocol.Rpc.Node;
using DocumentStamp.Helper;
using DocumentStamp.Http.Request;
using DocumentStamp.Http.Response;
using DocumentStamp.Keystore;
using DocumentStamp.Model;
using DocumentStamp.Validator;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Serilog;
using TheDotNetLeague.MultiFormats.MultiBase;
using TheDotNetLeague.MultiFormats.MultiHash;

namespace DocumentStamp.Function
{
    public class StampDocument
    {
        [FunctionName("StampDocument")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
            HttpRequest req,
            Microsoft.Extensions.Logging.ILogger log)
        {
            log.LogInformation("StampDocument processing a request");

            try
            {
                //Required or it will cause outofmemory exceptions on azure functions!
                Environment.SetEnvironmentVariable("io.netty.allocator.type", "unpooled");

                //Validate the request model sent by the user or client
                var stampDocumentRequest =
                    ModelValidator.ValidateAndConvert<StampDocumentRequest>(await req.ReadAsStringAsync());

                //Verify the signature of the stamp document request
                var verifyResult = SignatureHelper.VerifyStampDocumentRequest(stampDocumentRequest);
                if (!verifyResult)
                {
                    throw new InvalidDataException("Could not verify signature of document stamp request");
                }

                var local_root = Environment.GetEnvironmentVariable("AzureWebJobsScriptRoot");
                var azure_root = $"{Environment.GetEnvironmentVariable("HOME")}/site/wwwroot";
                var actual_root = local_root ?? azure_root;

                var logger = new LoggerConfiguration().WriteTo.Debug(Serilog.Events.LogEventLevel.Debug).CreateLogger();

                var cryptoContext = new FfiWrapper();

                var hashProvider = new HashProvider(HashingAlgorithm.GetAlgorithmMetadata("blake2b-256"));

                var keyStore = new InMemoryKeyStore(cryptoContext, Environment.GetEnvironmentVariable("FunctionPrivateKey"));

                var keyRegistry = new KeyRegistry();
                var keySigner = new KeySigner(keyStore, cryptoContext, keyRegistry);

                var memoryCacheOptions = new MemoryCacheOptions();
                var memoryCache = new MemoryCache(memoryCacheOptions);
                var changeTokenProvider = new TtlChangeTokenProvider(10000);
                var messageCorrelationManager = new RpcMessageCorrelationManager(memoryCache, logger, changeTokenProvider);
                var peerIdValidator = new PeerIdValidator(cryptoContext);

                var privateKey = keyRegistry.GetItemFromRegistry(KeyRegistryTypes.DefaultKey);
                var publicKey = privateKey.GetPublicKey();
                var publicKeyBase32 = publicKey.Bytes.ToBase32();

                var peerConfig = new Dictionary<string, string>
                {
                    {"CatalystNodeConfiguration:Peer:Network", "Devnet"},
                    {"CatalystNodeConfiguration:Peer:PublicKey", publicKeyBase32},
                    {"CatalystNodeConfiguration:Peer:Port", "42076"},
                    {"CatalystNodeConfiguration:Peer:PublicIpAddress", IPAddress.Loopback.ToString()},
                    {"CatalystNodeConfiguration:Peer:BindAddress", IPAddress.Loopback.ToString()}
                };

                var peerSettingsConfig = new ConfigurationBuilder().AddInMemoryCollection(peerConfig).Build();
                var peerSettings = new PeerSettings(peerSettingsConfig);

                var nodeRpcClientChannelFactory =
                    new RpcClientChannelFactory(keySigner, messageCorrelationManager, peerIdValidator, peerSettings, 0);

                var eventLoopGroupFactoryConfiguration = new EventLoopGroupFactoryConfiguration
                {
                    TcpClientHandlerWorkerThreads = 4
                };

                var tcpClientEventLoopGroupFactory = new TcpClientEventLoopGroupFactory(eventLoopGroupFactoryConfiguration);

                var handlers = new List<IRpcResponseObserver>
                {
                    new BroadcastRawTransactionResponseObserver(logger)
                };

                var rpcClientFactory = new RpcClientFactory(nodeRpcClientChannelFactory, tcpClientEventLoopGroupFactory, handlers);

                var certBytes = File.ReadAllBytes(Path.Combine(actual_root, Environment.GetEnvironmentVariable("NodePfxFileName")));
                var certificate = new X509Certificate2(certBytes, Environment.GetEnvironmentVariable("NodeSslCertPassword"), X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

                var rpcClientSettings = new RpcClientSettings
                {
                    HostAddress = IPAddress.Parse(Environment.GetEnvironmentVariable("NodeIpAddress")),
                    Port = int.Parse(Environment.GetEnvironmentVariable("NodePort")),
                    PublicKey = Environment.GetEnvironmentVariable("NodePublicKey")
                };

                var recipientPeer = rpcClientSettings.PublicKey.BuildPeerIdFromBase32Key(rpcClientSettings.HostAddress, rpcClientSettings.Port);

                var receiverPublicKey =
                    cryptoContext.GetPublicKeyFromBytes(stampDocumentRequest.PublicKey.FromBase32());

                //Construct DocumentStamp smart contract data
                var userProofJson = JsonConvert.SerializeObject(stampDocumentRequest);
                var transaction =
                    StampTransactionHelper.GenerateStampTransaction(privateKey, receiverPublicKey,
                        userProofJson.ToUtf8Bytes(), 1, 1);
                var protocolMessage =
                    transaction.ToProtocolMessage(peerSettings.PeerId, CorrelationId.GenerateCorrelationId());

                var autoResetEvent = new AutoResetEvent(false);
                ResponseCode? responseCode = null;

                var rpcClient = await rpcClientFactory.GetClient(certificate, rpcClientSettings).ConfigureAwait(false);

                //Connect to the node
                await rpcClient.StartAsync();
                log.LogInformation($"Connected to node {rpcClient.Channel.Active}");

                //Listen to BroadcastRawTransactionResponse responses from the node.
                rpcClient.SubscribeToResponse<BroadcastRawTransactionResponse>(x =>
                {
                    responseCode = x.ResponseCode;
                    autoResetEvent.Set();
                });

                //Send transaction to node
                log.LogInformation($"Sending transaction to node");
                await rpcClient.Channel.WriteAsync(new MessageDto(protocolMessage, recipientPeer)).ConfigureAwait(false);

                //Wait for node response then generate azure function response
                log.LogInformation($"Waiting for response");
                var signaled = autoResetEvent.WaitOne(TimeSpan.FromSeconds(10));
                if (!signaled)
                {
                    return new BadRequestObjectResult(new Result<string>(false, "Timed out waiting for response from node."));
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
                return new BadRequestObjectResult(new Result<string>(false, ide.ToString()));
            }
            catch (Exception exc)
            {
                return new BadRequestObjectResult(new Result<string>(false, exc.ToString()));
            }
        }
    }
}