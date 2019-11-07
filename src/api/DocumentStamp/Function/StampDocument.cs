using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Catalyst.Abstractions.IO.Observers;
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
                var local_root = Environment.GetEnvironmentVariable("AzureWebJobsScriptRoot");
                var azure_root = $"{Environment.GetEnvironmentVariable("HOME")}/site/wwwroot";
                var actual_root = local_root ?? azure_root;

                var configRoot = new ConfigurationBuilder().AddJsonFile(Path.Combine(actual_root, "config.json")).Build();
                var config = new Config(configRoot);

                var logger = new LoggerConfiguration().WriteTo.Debug(Serilog.Events.LogEventLevel.Debug).CreateLogger();

                var cryptoContext = new FfiWrapper();

                var hashProvider = new HashProvider(HashingAlgorithm.GetAlgorithmMetadata("blake2b-256"));

                var keyStore = new InMemoryKeyStore(cryptoContext);

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
                    new RpcClientChannelFactory(keySigner, messageCorrelationManager, peerIdValidator, peerSettings);

                var eventLoopGroupFactoryConfiguration = new EventLoopGroupFactoryConfiguration
                {
                    TcpServerHandlerWorkerThreads = 4,
                    TcpClientHandlerWorkerThreads = 4
                };

                var tcpClientEventLoopGroupFactory = new TcpClientEventLoopGroupFactory(eventLoopGroupFactoryConfiguration);

                var handlers = new List<IRpcResponseObserver>
                {
                    new BroadcastRawTransactionResponseObserver(logger),
                    new GetVersionResponseObserver(logger)
                };

                var rpcClientFactory = new RpcClientFactory(nodeRpcClientChannelFactory, tcpClientEventLoopGroupFactory, handlers);

                var certificate = new X509Certificate2(File.ReadAllBytes(Path.Combine(actual_root, "mycert.pfx")), config.NodeConfig.SslCertPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

                var rpcClientSettings = new RpcClientSettings
                {
                    HostAddress = config.NodeConfig.IpAddress,
                    Port = config.NodeConfig.Port,
                    PfxFileName = config.NodeConfig.PfxFileName,

                    SslCertPassword = config.NodeConfig.SslCertPassword,
                    PublicKey = config.NodeConfig.PublicKey
                };

                var recipientPeer = rpcClientSettings.PublicKey.BuildPeerIdFromBase32Key(config.NodeConfig.IpAddress, config.NodeConfig.Port);
                var rpcClient = await rpcClientFactory.GetClient(certificate, rpcClientSettings).ConfigureAwait(false);

                var autoResetEvent = new AutoResetEvent(false);

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

                log.LogInformation($"Connecting to node");
                //Connect to the node
                await rpcClient.StartAsync();
                log.LogInformation($"Connected to node {rpcClient.Channel.Active}");

                //Listen to BroadcastRawTransactionResponse responses from the node.
                ResponseCode? responseCode = null;
                rpcClient.SubscribeToResponse<BroadcastRawTransactionResponse>(x =>
                {
                    responseCode = x.ResponseCode;
                    autoResetEvent.Set();
                });

                //Construct DocumentStamp smart contract data
                var userProofJson = JsonConvert.SerializeObject(stampDocumentRequest);
                var transaction =
                    StampTransactionHelper.GenerateStampTransaction(privateKey, receiverPublicKey,
                        userProofJson.ToUtf8Bytes(), 1, 1);
                var protocolMessage =
                    transaction.ToProtocolMessage(peerSettings.PeerId, CorrelationId.GenerateCorrelationId());

                await Task.Factory.StartNew(() =>
                {
                    for (var i = 0; i < 5; i++)
                    {
                        log.LogInformation($"Sending transaction {i}");
                        rpcClient.SendMessage(new MessageDto(protocolMessage, recipientPeer));
                        Thread.Sleep(100);
                    }
                }).ConfigureAwait(false);

                log.LogInformation($"Waiting for response");
                //Wait for node response then generate azure function response
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

                //var stampDocumentResponse =
                //    HttpHelper.GetStampDocument(config.NodeConfig.WebAddress,
                //        transaction.Transaction.Signature.RawBytes.ToByteArray().ToBase32().ToUpperInvariant());
                return new OkObjectResult(new Result<object>(true, new { TxId = transaction.Transaction.Signature.RawBytes.ToByteArray().ToBase32().ToUpperInvariant() }));
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