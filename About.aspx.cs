using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace twitter
{
    public partial class About : Page
    {
        string pinURL = string.Empty;
        static string oauth_token = string.Empty;
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnTweet_Click(object sender, EventArgs e)
        {
            string pin=txtTweetPin.Text;
            TwitterAuthenticationReturn authReturn = getTwitterAccessTokenFromAuthorizationCode(pin, oauth_token);
            tweet(txtTweet.Text, authReturn.access_token, authReturn.access_token_secret);

        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            string oauth_token = startTwitterAuthentication();
            Process.Start(pinURL);
        }
        private string startTwitterAuthentication()
        {
            // string oauthCallback = Request.Url.AbsoluteUri;
            const string oauthConsumerKey = "AuDl8wV51dOUKFkcfccvHDodU";
            const string oauthConsumerSecret = "6xWw64T2IbHJiDudgIJdSyMjvdjeeIHYOCR8Qz8dGvWZwD3y05";
            // const string oauthToken = "822906096-edkWLzVMgA1vgnQPvHqprUZbMcWp7NDb8pBvj6It";
            //const string oauthTokenSecret = "5hEycoKK0LPc39winhw8p60qvm9gounp64zx7Z1LvB4xO";
            const string oauthVersion = "1.0";
            const string oauthSignatureMethod = "HMAC-SHA1";

            var oauthNonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture)));
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var oauthTimestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString(CultureInfo.InvariantCulture);

            const string resourceUrl = "https://api.twitter.com/oauth/request_token";

            const string baseFormat = "oauth_consumer_key={0}&oauth_nonce={1}&oauth_signature_method={2}" +
                                        "&oauth_timestamp={3}&oauth_version={4}";

            var baseString = string.Format(baseFormat,
                                        oauthConsumerKey,
                                        oauthNonce,
                                        oauthSignatureMethod,
                                        oauthTimestamp,
                                        oauthVersion
                                        );

            baseString = string.Concat("POST&", Uri.EscapeDataString(resourceUrl), "&", Uri.EscapeDataString(baseString));

            var compositeKey = string.Concat(Uri.EscapeDataString(oauthConsumerSecret),
                                    "&");

            string oauthSignature;
            using (var hasher = new HMACSHA1(Encoding.ASCII.GetBytes(compositeKey)))
            {
                oauthSignature = Convert.ToBase64String(
                    hasher.ComputeHash(Encoding.ASCII.GetBytes(baseString)));
            }

            const string headerFormat =
                                        "OAuth oauth_consumer_key=\"{0}\", " +
                                        "oauth_nonce=\"{1}\", " +
                                        "oauth_signature=\"{2}\", " +
                                        "oauth_signature_method=\"{3}\", " +
                                        "oauth_timestamp=\"{4}\", " +

                                        "oauth_version=\"{5}\"";

            var authHeader = string.Format(headerFormat,
                                    Uri.EscapeDataString(oauthConsumerKey),
                                    Uri.EscapeDataString(oauthNonce),
                                    Uri.EscapeDataString(oauthSignature),
                                    Uri.EscapeDataString(oauthSignatureMethod),
                                    Uri.EscapeDataString(oauthTimestamp),

                                    Uri.EscapeDataString(oauthVersion)
                            );

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(resourceUrl);
            request.Method = "POST";
            request.Headers["Authorization"] = authHeader;

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            StreamReader reader = new StreamReader(response.GetResponseStream(), System.Text.Encoding.UTF8);
            String resultData = reader.ReadToEnd();



            int beginIndex = resultData.IndexOf('=');
            int endIndex = resultData.IndexOf('&');

            int lastIndex = resultData.LastIndexOf('&');
            pinURL = "https://api.twitter.com/oauth/authenticate?oauth_token";
            pinURL = string.Concat(pinURL + resultData.Substring(beginIndex, lastIndex - beginIndex));
            oauth_token = resultData.Substring(beginIndex + 1, (endIndex - beginIndex) - 1);
            return oauth_token;

        }
        private TwitterAuthenticationReturn getTwitterAccessTokenFromAuthorizationCode(string pin, string oauthToken)
        {
            // string oauthCallback = Request.Url.AbsoluteUri;
            const string oauthConsumerKey = "AuDl8wV51dOUKFkcfccvHDodU";
            const string oauthConsumerSecret = "6xWw64T2IbHJiDudgIJdSyMjvdjeeIHYOCR8Qz8dGvWZwD3y05";

            const string oauthVersion = "1.0";
            const string oauthSignatureMethod = "HMAC-SHA1";

            var oauthNonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture)));
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var oauthTimestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString(CultureInfo.InvariantCulture);

            const string resourceUrl = "https://api.twitter.com/oauth/access_token";

            const string baseFormat = "oauth_consumer_key={0}&oauth_nonce={1}&oauth_signature_method={2}" +
                                        "&oauth_timestamp={3}&oauth_token={4}&oauth_version={5}";

            var baseString = string.Format(baseFormat,
                                        oauthConsumerKey,
                                        oauthNonce,
                                        oauthSignatureMethod,
                                        oauthTimestamp,
                                        oauthToken,
                                        oauthVersion
                                        );

            baseString = string.Concat("POST&", Uri.EscapeDataString(resourceUrl), "&", Uri.EscapeDataString(baseString));

            var compositeKey = string.Concat(Uri.EscapeDataString(oauthConsumerSecret),
                                    "&");

            string oauthSignature;
            using (var hasher = new HMACSHA1(Encoding.ASCII.GetBytes(compositeKey)))
            {
                oauthSignature = Convert.ToBase64String(
                    hasher.ComputeHash(Encoding.ASCII.GetBytes(baseString)));
            }

            const string headerFormat =
                                        "OAuth oauth_consumer_key=\"{0}\", " +
                                        "oauth_nonce=\"{1}\", " +
                                        "oauth_signature=\"{2}\", " +
                                        "oauth_signature_method=\"{3}\", " +
                                        "oauth_timestamp=\"{4}\", " +
                                        "oauth_token=\"{5}\", " +
                                        "oauth_version=\"{6}\"";

            var authHeader = string.Format(headerFormat,
                                    Uri.EscapeDataString(oauthConsumerKey),
                                    Uri.EscapeDataString(oauthNonce),
                                    Uri.EscapeDataString(oauthSignature),
                                    Uri.EscapeDataString(oauthSignatureMethod),
                                    Uri.EscapeDataString(oauthTimestamp),
                                    Uri.EscapeDataString(oauthToken),
                                    Uri.EscapeDataString(oauthVersion)
                            );

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(resourceUrl);
            request.Method = "POST";
            request.Headers.Add("Authorization", authHeader);

            request.ContentType = "application/x-www-form-urlencoded;charset=UTF-8";
            var entity = "oauth_verifier=" + Uri.EscapeDataString(pin);


            using (Stream stream = request.GetRequestStream())
            {
                byte[] content = ASCIIEncoding.ASCII.GetBytes(entity);
                stream.Write(content, 0, content.Length);
            }
            WebResponse response = request.GetResponse();


            TwitterAuthenticationReturn twr = new TwitterAuthenticationReturn();
            StreamReader reader = new StreamReader(response.GetResponseStream(), System.Text.Encoding.UTF8);
            String resultData = reader.ReadToEnd();
            char[] delimeter = { '&' };
            string[] tokens = resultData.Split(delimeter);
            foreach (string token in tokens)
            {
                if (token.StartsWith("oauth_token="))
                    twr.access_token = token.Substring(token.IndexOf("=") + 1);
                if (token.StartsWith("oauth_token_secret="))
                    twr.access_token_secret = token.Substring(token.IndexOf("=") + 1);
                if (token.StartsWith("user_id="))
                    twr.user_id = token.Substring(token.IndexOf("=") + 1);
                if (token.StartsWith("screen_name="))
                    twr.screen_name = token.Substring(token.IndexOf("=") + 1);

            }

            return twr;
        }

        private string tweet(string tweetText, string oauthToken, string OauthTokenSecret)
        {
            // string oauthCallback = Request.Url.AbsoluteUri;
            const string oauthConsumerKey = "AuDl8wV51dOUKFkcfccvHDodU";
            const string oauthConsumerSecret = "6xWw64T2IbHJiDudgIJdSyMjvdjeeIHYOCR8Qz8dGvWZwD3y05";

            const string oauthVersion = "1.0";
            const string oauthSignatureMethod = "HMAC-SHA1";

            var oauthNonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture)));
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var oauthTimestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString(CultureInfo.InvariantCulture);

            const string resourceUrl = "https://api.twitter.com/1.1/statuses/update.json";

            const string baseFormat = "oauth_consumer_key={0}&oauth_nonce={1}&oauth_signature_method={2}" +
                                        "&oauth_timestamp={3}&oauth_token={4}&oauth_version={5}&status={6}";

            var baseString = string.Format(baseFormat,
                                        oauthConsumerKey,
                                        oauthNonce,
                                        oauthSignatureMethod,
                                        oauthTimestamp,
                                        oauthToken,
                                        oauthVersion,
                                        tweetText
                                        );

            baseString = string.Concat("POST&", Uri.EscapeDataString(resourceUrl), "&", Uri.EscapeDataString(baseString));

            var compositeKey = string.Concat(Uri.EscapeDataString(oauthConsumerSecret),
                                    "&", Uri.EscapeDataString(OauthTokenSecret));

            string oauthSignature;
            using (var hasher = new HMACSHA1(Encoding.ASCII.GetBytes(compositeKey)))
            {
                oauthSignature = Convert.ToBase64String(
                    hasher.ComputeHash(Encoding.ASCII.GetBytes(baseString)));
            }

            const string headerFormat =
                                        "OAuth oauth_consumer_key=\"{0}\", " +
                                        "oauth_nonce=\"{1}\", " +
                                        "oauth_signature=\"{2}\", " +
                                        "oauth_signature_method=\"{3}\", " +
                                        "oauth_timestamp=\"{4}\", " +
                                        "oauth_token=\"{5}\", " +
                                        "oauth_version=\"{6}\"";

            var authHeader = string.Format(headerFormat,
                                    Uri.EscapeDataString(oauthConsumerKey),
                                    Uri.EscapeDataString(oauthNonce),
                                    Uri.EscapeDataString(oauthSignature),
                                    Uri.EscapeDataString(oauthSignatureMethod),
                                    Uri.EscapeDataString(oauthTimestamp),
                                    Uri.EscapeDataString(oauthToken),
                                    Uri.EscapeDataString(oauthVersion)
                            );

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(resourceUrl);
            request.Method = "POST";
            request.Headers.Add("Authorization", authHeader);

            request.ContentType = "application/x-www-form-urlencoded;charset=UTF-8";
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            var entity = "status=" + Uri.EscapeDataString(tweetText);


            using (Stream stream = request.GetRequestStream())
            {
                byte[] content = ASCIIEncoding.ASCII.GetBytes(entity);
                stream.Write(content, 0, content.Length);
            }
            request.Headers.Add("Accept-Encoding", "gzip");
            WebResponse response = request.GetResponse();


            TwitterAuthenticationReturn twr = new TwitterAuthenticationReturn();
            StreamReader reader = new StreamReader(response.GetResponseStream(), System.Text.Encoding.UTF8);
            String resultData = reader.ReadToEnd();
            return resultData;
        }


    }
}