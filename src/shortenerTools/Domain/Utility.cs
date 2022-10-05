using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Cloud5mins.domain
{
    public static class Utility
    {
        //reshuffled for randomisation, same unique characters just jumbled up, you can replace with your own version
        private const string ConversionCode = "FjTG0s5dgWkbLf_8etOZqMzNhmp7u6lUJoXIDiQB9-wRxCKyrPcv4En3Y21aASHV";
        private static readonly int Base = ConversionCode.Length;
        //sets the length of the unique code to add to vanity
        private const int MinVanityCodeLength = 5;

        public static async Task<string> GetValidEndUrl(string vanity, StorageTableHelper stgHelper)
        {
            if (string.IsNullOrEmpty(vanity))
            {
                var newKey = await stgHelper.GetNextTableId();
                string getCode() => Encode(newKey);
                if (await stgHelper.IfShortUrlEntityExistByVanity(getCode()))
                    return await GetValidEndUrl(vanity, stgHelper);
              
                return string.Join(string.Empty, getCode());
            }
            else
            {
                return string.Join(string.Empty, vanity);
            }
        }

        public static string Encode(int i)
        {
            if (i == 0)
                return ConversionCode[0].ToString();

            return GenerateUniqueRandomToken(i);
        }

        public static string GetShortUrl(string host, string vanity)
        {
            return host + "/" + vanity;
        }

        // generates a unique, random, and alphanumeric token for the use as a url 
        //(not entirely secure but not sequential so generally not guessable)
        public static string GenerateUniqueRandomToken(int uniqueId)
        {
            using (var generator = new RNGCryptoServiceProvider())
            {
                //minimum size I would suggest is 5, longer the better but we want short URLs!
                var bytes = new byte[MinVanityCodeLength];
                generator.GetBytes(bytes);
                var chars = bytes
                    .Select(b => ConversionCode[b % ConversionCode.Length]);
                var token = new string(chars.ToArray());
                var reversedToken = string.Join(string.Empty, token.Reverse());
                return uniqueId + reversedToken;
            }
        }

        public static IActionResult CatchUnauthorizeAsync(ClaimsPrincipal principal, ILogger log, HttpRequest request)
        {

            if (principal == null)
            {
                log.LogWarning("No principal.");
                return new UnauthorizedResult();
            }

            if (principal.Identity == null)
            {
                log.LogWarning("No identity.");
                return new UnauthorizedResult();
            }

            if (!principal.Identity.IsAuthenticated)
            {
                log.LogWarning("Request was not authenticated.");
                return new UnauthorizedResult();
            }

            var givenName = Utility.GetNameInJWT(log, request);

            if (string.IsNullOrEmpty(givenName))
            {
                log.LogError("Claim not Found");
                return new BadRequestObjectResult(new
                {
                    message = "Claim not Found",
                    StatusCode = System.Net.HttpStatusCode.BadRequest
                });
            }
            return null;
        }

        public static string GetNameInJWT(ILogger log, HttpRequest request)
        {
            try
            {
                string givenName = "";
                request.Headers.TryGetValue("Authorization", out var headerValue);
                if (headerValue != "")
                {
                    var jwtEncodedString = headerValue[0].Substring(7);
                    var handler = new JwtSecurityTokenHandler();
                    var jsonToken = handler.ReadToken(jwtEncodedString);
                    var tokenS = jsonToken as JwtSecurityToken;
                    var name = tokenS.Claims.FirstOrDefault(t => t.Type == "name");
                    givenName = name.ToString().Substring(6);
                }
                return givenName;
            }
            catch (System.Exception ex)
            {
                log.LogError("Authorization in JWT not Found");
                return "";
            }
        }

        public static string GetIDPInJWT(ILogger log, HttpRequest request)
        {
            try
            {
                string idp = "";
                request.Headers.TryGetValue("Authorization", out var headerValue);
                if (headerValue != "")
                {
                    var jwtEncodedString = headerValue[0].Substring(7);
                    var handler = new JwtSecurityTokenHandler();
                    var jsonToken = handler.ReadToken(jwtEncodedString);
                    var tokenS = jsonToken as JwtSecurityToken;
                    idp = tokenS.Claims.FirstOrDefault(t => t.Type == "idp").ToString();
                }
                return idp;
            }
            catch (System.Exception ex)
            {
                log.LogError("IDP in JWT not Found");
                return "";
            }
        }
    }
}
