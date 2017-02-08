using LinqToTwitter;
using Newtonsoft.Json;
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
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Web.UI.WebControls;
using Twitterizer;

namespace twitter
{
    public partial class _Default : Page
    {
       
        string pinURL = string.Empty;
        static string oauth_token = string.Empty;
        protected void Page_Load(object sender, EventArgs e)
        {
          


            //POST 

            //if (Request["oauth_token"] == null)
            //{
            //    //pass consumer key, consumersecret and current page url
            //    OAuthTokenResponse reqToken = OAuthUtility.GetRequestToken(
            //        oAuthConsumerKey,
            //        oAuthConsumerSecret,
            //        Request.Url.AbsoluteUri);

            //    Response.Redirect(string.Format("https://twitter.com/oauth/authorize?oauth_token={0}",
            //        reqToken.Token));

            //}
            //else
            //{
            //    string requestToken = Request["oauth_token"].ToString();
            //    string pin = Request["oauth_verifier"].ToString();

            //    var tokens = OAuthUtility.GetAccessToken(
            //        oAuthConsumerKey,
            //        oAuthConsumerSecret,
            //        requestToken,
            //        pin);

            //    OAuthTokens accesstoken = new OAuthTokens()
            //    {
            //        AccessToken = tokens.Token,
            //        AccessTokenSecret = tokens.TokenSecret,
            //        ConsumerKey = oAuthConsumerKey,
            //        ConsumerSecret = oAuthConsumerSecret
            //    };

            //    //TwitterResponse<TwitterStatus> response = TwitterStatus.Update(
            //    //    accesstoken,
            //    //    "Testing!! It works (hopefully).");
            //    OptionalProperties op = new OptionalProperties();
            //    op.UseSSL = true;
            //    op.APIBaseAddress = "http://api.twitter.com/1.1/";
            //    TwitterResponse<TwitterStatus> response = TwitterStatus.Retweet(accesstoken, Convert.ToDecimal(tweetid), op);

            //   // TwitterResponse<TwitterStatus> response = TwitterStatus.Update(accesstoken, "Testing again!! ", new StatusUpdateOptions() { UseSSL = true, APIBaseAddress = "http://api.twitter.com/1.1/" });

            //    if (response.Result == RequestResult.Success)
            //    {
            //        Response.Write("we did it!");
            //    }
            //    else
            //    {
            //        Response.Write("it's all bad.");
            //    }
            //}
            //POST 
            //TEST


            //tEST


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

        public string reTweets(string id, string access_token, string access_token_secret)
        {
            const string oauthConsumerKey = "AuDl8wV51dOUKFkcfccvHDodU";
            const string oauthConsumerSecret = "6xWw64T2IbHJiDudgIJdSyMjvdjeeIHYOCR8Qz8dGvWZwD3y05";
            string oauthToken = access_token;
            string oauthTokenSecret = access_token_secret;
            const string oauthVersion = "1.0";
            const string oauthSignatureMethod = "HMAC-SHA1";

            var oauthNonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture)));
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var oauthTimestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString(CultureInfo.InvariantCulture);

            string resourceUrl = "https://api.twitter.com/1.1/statuses/retweet/" + id + ".json";

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
                                    "&",Uri.EscapeDataString(oauthTokenSecret));

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

            

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            StreamReader reader = new StreamReader(response.GetResponseStream(), System.Text.Encoding.UTF8);
            String resultData = reader.ReadToEnd();
            if(resultData!=null)
            {
                lblresponse.Visible = true;
                txtHashtag.Text = "";
                txtHandler.Text = "";
                txtPin.Text = "";
                lblresponse.InnerText = "Latest Retweet of specified Handler and Hashtag has been done on your Account.";
            }
            return authHeader;

        }
        public string searchTweets(string q, string access_token, string access_token_secret)
        {
            var oAuthConsumerKey = "AuDl8wV51dOUKFkcfccvHDodU";
            var oAuthConsumerSecret = "6xWw64T2IbHJiDudgIJdSyMjvdjeeIHYOCR8Qz8dGvWZwD3y05";
            var oAuthUrl = "https://api.twitter.com/oauth2/token";
            var screenname = "swati39434173";

            // Do the Authenticate
            var authHeaderFormat = "Basic {0}";

            var authHeader = string.Format(authHeaderFormat,
                Convert.ToBase64String(Encoding.UTF8.GetBytes(Uri.EscapeDataString(oAuthConsumerKey) + ":" +
                Uri.EscapeDataString((oAuthConsumerSecret)))
            ));

            var postBody = "grant_type=client_credentials";

            HttpWebRequest authRequest = (HttpWebRequest)WebRequest.Create(oAuthUrl);
            authRequest.Headers.Add("Authorization", authHeader);
            authRequest.Method = "POST";
            authRequest.ContentType = "application/x-www-form-urlencoded;charset=UTF-8";
            authRequest.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

            using (Stream stream = authRequest.GetRequestStream())
            {
                byte[] content = ASCIIEncoding.ASCII.GetBytes(postBody);
                stream.Write(content, 0, content.Length);
            }

            authRequest.Headers.Add("Accept-Encoding", "gzip");

            WebResponse authResponse = authRequest.GetResponse();
            // deserialize into an object
            TwitAuthenticateResponse twitAuthResponse;
            using (authResponse)
            {
                using (var reader = new StreamReader(authResponse.GetResponseStream()))
                {
                    JavaScriptSerializer js = new JavaScriptSerializer();
                    var objectText = reader.ReadToEnd();
                    twitAuthResponse = JsonConvert.DeserializeObject<TwitAuthenticateResponse>(objectText);
                }
            }

            // Do the timeline
            //   var timelineFormat = "https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name={0}&include_rts=1&exclude_replies=1&count=1";
            
            var timelineFormat = "https://api.twitter.com/1.1/search/tweets.json?q="+q+"&count=1";//%23INDVENG%20from%3Avirendersehwag&count=1";

            var timelineUrl = string.Format(timelineFormat, screenname);
            HttpWebRequest timeLineRequest = (HttpWebRequest)WebRequest.Create(timelineUrl);
            var timelineHeaderFormat = "{0} {1}";
            timeLineRequest.Headers.Add("Authorization", string.Format(timelineHeaderFormat, twitAuthResponse.token_type, twitAuthResponse.access_token));
            timeLineRequest.Method = "Get";
            WebResponse timeLineResponse = timeLineRequest.GetResponse();
            var timeLineJson = string.Empty;
            var tweetid = string.Empty;
            using (timeLineResponse)
            {
                using (var reader = new StreamReader(timeLineResponse.GetResponseStream()))
                {
                    timeLineJson = reader.ReadToEnd();
                    var js = new JavaScriptSerializer();
                    var d = js.Deserialize<dynamic>(timeLineJson);
                    tweetid = Convert.ToString(d["statuses"][0]["id"]);
                    Console.WriteLine(Convert.ToString(d["statuses"][0]["id"]));
                }
            }
            return tweetid;

        }
      

        protected void Button1_Click(object sender, EventArgs e)
        {

            string oauth_token = startTwitterAuthentication();
            Process.Start(pinURL);
           
        }
       

        protected void Button2_Click(object sender, EventArgs e)
        {
            string pin = txtPin.Text;
            //Response.Redirect(pinURL);
            TwitterAuthenticationReturn authReturn = getTwitterAccessTokenFromAuthorizationCode(pin, oauth_token);
            string hashtag = txtHashtag.Text;
            string handler = txtHandler.Text; //"swati39434173";
            
            var query = hashtag + " from:" + handler;
            query = Uri.EscapeDataString(query);
            string tweetid= searchTweets(query, authReturn.access_token, authReturn.access_token_secret);
            string response=reTweets(tweetid, authReturn.access_token, authReturn.access_token_secret);
        }

        protected void btnTweet_Click(object sender, EventArgs e)
        {

        }
    }
    public class TwitAuthenticateResponse
    {
        public string token_type { get; set; }
        public string access_token { get; set; }
    }
    class TwitterAuthenticationReturn
    {
        public String access_token = "";
        public String access_token_secret = "";
        public String user_id = "";
        public String screen_name = "";
    }







}