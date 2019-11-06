using System;
using System.Diagnostics;
using System.IO;
using System.IO.Abstractions;
using System.Threading.Tasks;
using Autofac;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Abstractions.Keystore;
using Catalyst.Abstractions.P2P;
using Catalyst.Abstractions.Rpc;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Protocol.Network;
using DocumentStamp.Helper;
using DocumentStamp.Http.Response;
using DocumentStamp.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using TheDotNetLeague.MultiFormats.MultiBase;

namespace DocumentStamp.Function
{
    public class DocumentStampSettings
    {
        [FunctionName("DocumentStampSettings")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("DocumentStampSettings processing a request");

            try
            {
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

                return new OkObjectResult(new Result<object>(true,
                    new { PublicKey = publicKey.Bytes.ToBase32().ToUpper() }));
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