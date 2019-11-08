using System;
using System.Configuration;
using System.IO;
using System.Threading.Tasks;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using DocumentStamp.Http.Response;
using DocumentStamp.Keystore;
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
                var keyStore = new InMemoryKeyStore(new FfiWrapper(), Environment.GetEnvironmentVariable("FunctionPrivateKey"));
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