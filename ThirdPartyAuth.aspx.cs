/*
 * The code blow is written as a proof-of concept and sample only. It is not intended
 * for production use.
 * 
 *  *** Use at your own risk. ***
 * 
 * In addition, there are certainly things that could be done more efficiently and
 * more securely. For example, the Twitter code could be optimized through the use
 * of one of several Twitter libraries available through nuget.
 * 
 * If you plan to use Twitter for any segmentation or other data collection about
 * the given user through their profile or feed, then you will need to store
 * the oauth token, which I do not do as that is beyond the purpose of this sample.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Net;
using System.Security.Cryptography;
using Ektron.Cms;
using Ektron.Cms.Framework.User;

public partial class webforms_ThirdPartyAuth : System.Web.UI.Page
{
    /*
     * Arbitrary value selected by the developer to represent Twitter within Ektron. 
     * 
     * This value should be the same for all accounts created through Twitter Sign-in.
     */
    private long TwitterAuthenticationId = 6000;

    /*
     * Running in Admin mode so I can create a user when needed. You should not run 
     * admin mode for any tasks which can be performed by the logged in user.
     * 
     * The way this is written, it won't initialize the UserManager until it's called.
     */
    private UserManager _userCRUD = null;
    private UserManager UserCRUD { get { return _userCRUD ?? (_userCRUD = new UserManager(Ektron.Cms.Framework.ApiAccessMode.Admin)); } }

    /*
     * The Page_Load logic here handles
     */
    protected void Page_Load(object sender, EventArgs e)
    {

        /*
         * Detect if the user is logged in. This is the most efficient way to go about
         * it as it employs a static option. You could call upon the UserManager defined
         * above, but that may cause it to initialize unnecessarily.
         */
        if (Ektron.Cms.Framework.Context.UserContextService.Current.IsLoggedIn)
        {
            uxAuthenticationViews.SetActiveView(uxLogoutView);
        }
        else
        {
            /*
             * Ensure the login view is set. It should by default, but it's best to specify
             * it explicitly in case of inadvertent postbacks.
             */
            uxAuthenticationViews.SetActiveView(uxLoginView);

            /*
             * I'm not going to perform checks against the querystring until I know it has values.
             */
            if (Request.QueryString.Count > 1)
            {
                /*
                 * Try to get the values from the querystring.
                 * 
                 * These are the values that are returned by Twitter when the user has successfully 
                 * authenticated. Not to worry, we're not going to assume these values are valid
                 * for authentication without some double-checking.
                 */
                string oAuthToken = Request.QueryString["oauth_token"];
                string oAuthVerifier = Request.QueryString["oauth_verifier"];

                /*
                 * Make sure the parameters have values. :)
                 */
                if (!string.IsNullOrEmpty(oAuthToken) && !string.IsNullOrEmpty(oAuthVerifier))
                {
                    /*
                     * Get the original request token values out of the Session.
                     */
                    TwitterRequestTokenResponse originalResponse = (TwitterRequestTokenResponse)Session["TwitterAuthValues"];

                    /*
                     * Compare the token recieved in the querystring with the Request Token API.
                     * 
                     * If they're the same, then you can trust that the visitor is just arrived 
                     * from your authentication request.
                     */
                    if (oAuthToken == originalResponse.OAuthToken)
                    {
                        /*
                         * Authentication successful!
                         * 
                         * Now you need to use this information to get some information about the visitor
                         * who just authenticated to your site. In everything we've done so far, we still 
                         * don't know the visitor's screen name or Twitter ID, for example. 
                         * 
                         * In addition, we can't make any requests on behalf of that user. The app that I've
                         * registered for this sample application is read-only. What I can do with that is 
                         * read the profile and tweets of this user. I may be able to use that for some 
                         * personalization. For example, I may want to know whether this visitor has mentioned
                         * my company by name or used any of the hashtags we're interested in.
                         * 
                         * In order to request that information, I need another token, which I will also get
                         * in the following request. As mentioned above, I'm only making use of the visitor's
                         * screen name and user id below, not the token. And as such, this code does not
                         * show you how to store that token or use it in Twitter's APIs.
                         */

                        /*
                         * To kick things off, I'll create a new access token request. This is a custom class
                         * defined below which will hold data and make calculations specifically for this request.
                         * 
                         * The request will make use of the newly received token and verifier that we got out
                         * of the querystring. I'm passing them to the new object as it's initialized.
                         */
                        var AccessRequest = new TwitterAccessTokenRequest(oAuthToken, oAuthVerifier);

                        /*
                         * Make the request. The workings of this method are described within its parent class
                         * below. It returns a response which contains an access token (to get read-only data),
                         * secret, as well as the visitor's Twitter Screen Name and User ID.
                         */
                        var AccessResponse = AccessRequest.ExecuteAccessTokenRequest();

                        /*
                         * Make sure it didn't incur any errors. If so, respond accordingly.
                         */
                        if (!string.IsNullOrEmpty(AccessResponse.ErrorMessage))
                        {
                            uxLoginError.InnerText = string.Format("We were unable to get an authentication token from Twitter. Error: {0}", AccessResponse.ErrorMessage);
                            uxLoginError.Visible = true;
                        }
                        else
                        {
                            /*
                             * At this point, all has gone well. The user has granted permissions and we were able 
                             * to verify their identity using Twitter's APIs. First, we attempt to login the user 
                             * with the Authentication ID (defined as a private global above) and their Twitter 
                             * User ID.
                             * 
                             * The User ID is used here rather than their Screen Name because a Twitter user can 
                             * alter their screen name at any time, but not their ID. As long as you use their ID
                             * then the visitor can alter their screen name at any time, yet still be albe to login
                             * to your site.
                             */

                            /*
                             * Establish initial user object. Set to null for now. If login is successful, then the
                             * object will be given a value.
                             */
                            UserData loggedInUser = null;
                            try
                            {
                                /*
                                 * Using the Authentication Type ID and Authentication User ID is the only method for
                                 * logging a user in without having a password. Hence, any 3rd party authentication
                                 * system used in your application should have a unique Type ID.
                                 * 
                                 * I arbitrarily chose 6000 to represent Twitter. As I add authentication schemes, I may
                                 * increment that value by 100 for each. E.g., Facebook = 6100, Google = 6200. These 
                                 * are not standard. They are chosen by the developer.
                                 */
                                loggedInUser = UserCRUD.Login(TwitterAuthenticationId, AccessResponse.UserId);
                            }
                            catch { }

                            /*
                             * If the login above fails, the user object will still be null. It's via this check that we will
                             * know whether the login is successful or not. Null = unsuccessful.
                             * 
                             * For attempts that are authenticated against twitter, but don't have a user account within the 
                             * application, I chose to create their account automatically. You may, instead, choose
                             * to redirect the user to a form to establish a more complete profile before actually
                             * adding the user to the system.
                             */
                            if (loggedInUser == null)
                            {
                                /*
                                 * Establish the new, empty user object.
                                 */
                                var newUser = new UserData();

                                /*
                                 * This setting is often overlooked - so make sure you set it or everyone who signs in via
                                 * Twitter will become CMS Authors. Yikes!
                                 */
                                newUser.IsMemberShip = true;

                                /*
                                 * I'm using the visitor's Twitter Screen Name as their Username and Display Name within Ektron.
                                 * 
                                 * These values must be unique. In my case, it helps to prefix their names with an @ symbol
                                 * in order to more closely align them with Twitter. :)
                                 */
                                newUser.Username = string.Format("@{0}", AccessResponse.ScreenName);
                                newUser.DisplayName = newUser.Username;

                                /*
                                 * Authentication type id must be the same for every user authenticated against Twitter.
                                 */
                                newUser.AuthenticationTypeId = TwitterAuthenticationId;

                                /*
                                 * In Twitter, screen names can change, but User IDs cannnot. Use the User ID for this 
                                 * so the user can change their Twitter screen name but still log in to your site.
                                 */
                                newUser.AuthenticationUserId = AccessResponse.UserId;

                                /*
                                 * Random, meaningless password. Ektron provides the method below for generating a random password
                                 * based on the validation expression.
                                 */
                                newUser.Password = UserCRUD.GetRandomPasswordforDefaultRegex();

                                /*
                                 * The twitter methods used so far do not provide a reliable first and last name. Some Twitter
                                 * users choose to enter these, but many do not. You may use another API to request this information
                                 * from Twitter or, because the fields are required in Ektron, do as I have done and enter 
                                 * placeholder values.
                                 */
                                newUser.FirstName = "not set";
                                newUser.LastName = "not set";

                                /*
                                 * Time Zone is a required custom property in any default Ektron installation. You may have this or
                                 * other required fields for your users - develop accordingly.
                                 * 
                                 * There are ways to *guess* at a user's current time zone that are beyond the scope of this sample.
                                 * Ideas include:
                                 * * Requesting the information with JavaScript in a previous page load
                                 * * Using GeoIP data to get the time zone
                                 * 
                                 * The GetCustomPropertyList method below gets the full set of properties with their default values.
                                 * Simply set those you need and then assign the list to the new user object.
                                 */
                                var customProps = UserCRUD.GetCustomPropertyList();
                                customProps["Time Zone"].Value = "Eastern Standard Time";
                                newUser.CustomProperties = customProps;

                                /*
                                 * Add the new user to the CMS.
                                 */
                                newUser = UserCRUD.Add(newUser);

                                /*
                                 * Login the new user.
                                 */
                                UserCRUD.Login(newUser.AuthenticationTypeId, newUser.AuthenticationUserId);
                            }
                            /*
                             * Use a Redirect here to ensure Ektron's ECM cookie is properly set as well as to remove any lingering
                             * postback and unneeded viewstate data.
                             * 
                             * Also removing the querystring, which contained values used to verify the authentication of the 
                             * current user.
                             */
                            Response.Redirect(Request.RawUrl.Split('?')[0]);
                        }
                    }
                }
            }
        }
    }

    /*
     * When a visitor clicks the 'Sign in with Twitter' button, it triggers this method.
     */
    protected void uxTwitterLogin_Click(object sender, EventArgs e)
    {
        /*
         * The following request object is defined in a custom class below.
         * 
         * The purpose of this object is to obtain a request token which will allow the
         * code to redirect the visitor to Twitter for authentication. When they return, 
         * we'll be able to verify this token against the returned value in order to validate
         * that the request originated from our own page.
         */
        var request = new TwitterRequestToken();
        var authResponse = request.ExecuteAuthentication();

        /*
         * If the response from Twitter indicates all is well...
         */
        if (authResponse.CallbackVerified)
        {
            /*
             * Store the response within Session so we can retain it for comparision when
             * the user is returned from their authentication with Twitter.
             */
            Session["TwitterAuthValues"] = authResponse;

            /*
             * Redirect the user (using a 302 redirect, as recommended by Twitter) to 
             * Twitter. This includes the token which indicates it's a valid request to authenticate
             * with our application.
             */
            Response.Redirect(string.Format("https://api.twitter.com/oauth/authenticate?oauth_token={0}", authResponse.OAuthToken));
        }
        else
        {
            /*
             * We'll end here if there is an issue with the response.
             * 
             * The process below is simply to capture the error message and display a friendly
             * version to the end user.
             */
            string error = authResponse.ErrorMessage;
            if (string.IsNullOrEmpty(error))
            {
                error = "Unknown";
            }
            uxLoginError.InnerText = string.Format("Unable to login via Twitter at this time. Error: {0}", error);
            uxLoginError.Visible = true;
        }
    }

    /*
     * Logs the current user out.
     * 
     * Redirect to the current page in order to ensure that the cookies are properly reset
     * and postback data is cleared.
     */
    protected void uxLogout_Click(object sender, EventArgs e)
    {
        UserCRUD.Logout();
        Response.Redirect(Request.RawUrl);
    }
}

/*
 * Common Twitter strings used in this sample.
 */
public static class TwitterSettings
{
    /*
     * The following key and secret have been disabled. Please replace with your own.
     */
    public static string ConsumerKey = "dyYCFSECGJvnv77vSjfF1E8fA";
    public static string ConsumerSecret = "89AwxkghIQpd4cuG6oMAFawDoEqRWdzpBvRjHhlLwNSArEKF1w";

    public static string Key_Callback = "oauth_callback";
    public static string Key_ConsumerKey = "oauth_consumer_key";
    public static string Key_Nonce = "oauth_nonce";
    public static string Key_Signature = "oauth_signature";
    public static string Key_SignatureMethod = "oauth_signature_method";
    public static string Key_Timestamp = "oauth_timestamp";
    public static string Key_Version = "oauth_version";
    public static string Key_AuthToken = "oauth_token";
    public static string SignatureMethod = "HMAC-SHA1";
    public static string OAuthVersion = "1.0";
}

/*
 * Common methods used in this sample. Because this sample makes multiple, similar
 * requests to Twitter's APIs, it makes sense to centralize as much as possible.
 */
public class TwitterCommon
{
    /*
     * Twitter requires certain passed arguments be joined and hashed into a signature 
     * for verification. The method below is a generic way to support this for both 
     * requests necessary for authentication.
     */
    public string GetTwitterSignature(string Method, string ApiUrl, Dictionary<string, string> Params = null)
    {
        /*
         * Storing base params in a dictionary. These are the params that don't change 
         * per request.
         */
        Dictionary<string, string> SignatureParams = new Dictionary<string, string>();
        SignatureParams.Add(Uri.EscapeDataString(TwitterSettings.Key_ConsumerKey), Uri.EscapeDataString(TwitterSettings.ConsumerKey));
        SignatureParams.Add(Uri.EscapeDataString(TwitterSettings.Key_SignatureMethod), Uri.EscapeDataString(TwitterSettings.SignatureMethod));
        SignatureParams.Add(Uri.EscapeDataString(TwitterSettings.Key_Version), Uri.EscapeDataString(TwitterSettings.OAuthVersion));

        /*
         * Adding params passed to the method. These params are those which are specific
         * to the request. For example, each request will have a unique timestamp and 
         * nonce value.
         */
        foreach (var item in Params)
        {
            SignatureParams.Add(item.Key, item.Value);
        }

        /*
         * Sort the elements in the dictionary.
         */
        var orderedElements = (from pair in SignatureParams
                               orderby pair.Key
                               select pair).ToDictionary(p => p.Key, p => p.Value);

        /*
         * Get an array of strings which represents the combined key/value pairs with
         * equal signs between them.
         */
        var pairlist = (from pair in orderedElements
                        select pair.Key + "=" + pair.Value).ToArray();

        /*
         * Use string join to combine the key/value equations from above, using an
         * ampersand as the delimiter (so the final result looks like a querystring).
         * 
         * Also note that the values should be escaped. This is similar to URL Encoding.
         * However, in C#, using HttpUtility.UrlEncode will use lower-case encoded values
         * when Twitter expects them to be uppercase. For example:
         * 
         * Good = %2F
         * Bad = %2f
         * 
         * The Uri.EscapeDataString method provides the correct encoding.
         * 
         * The signing key below provides the key against which the hash is computed. 
         * This key is sufficient for both requests made in this sample. However, to make
         * further requests to twitter using the final token returned, that token also 
         * needs to be part of the key. That is beyond the scope of this sample.
         */
        var combinedpairs = string.Join("&", pairlist);
        var SignatureBaseString = string.Format("{0}&{1}&{2}", Method, Uri.EscapeDataString(ApiUrl), Uri.EscapeDataString(combinedpairs));
        var SigningKey = string.Format("{0}&", Uri.EscapeDataString(TwitterSettings.ConsumerSecret));

        /*
         * Twitter uses ASCII encoding.
         */
        var encoding = System.Text.Encoding.ASCII;

        var bSigningKey = encoding.GetBytes(SigningKey);
        var bSignatureBaseString = encoding.GetBytes(SignatureBaseString);

        /*
         * Use the HMAC-SHA1 algorithm to compute the signature hash, including
         * the key from above. Twitter will compute the same hash as part of validating
         * your request.
         */
        var HashingAlgorithm = new HMACSHA1(bSigningKey);
        var hash = HashingAlgorithm.ComputeHash(bSignatureBaseString);

        /*
         * Return the hash as a Base64 string.
         */
        return Convert.ToBase64String(hash);
    }

    /*
     * The Nonce is a random combination of letters (upper or lower case) and numbers
     * which should be unique for each request. This helps Twitter weed out duplicate
     * requests.
     * 
     * A single GUID is probably sufficient. I am combining two GUIDs to be extra random. (Moar random!)
     * 
     * As long as it's sufficiently random, Twitter doesn't mind.
     * 
     * I also am removing the hyphens from the generated GUIDs as Twitter's documentation
     * does not state that these characters are an allowed part of the Nonce value.
     */
    public string GetNonce()
    {
        var g1 = Guid.NewGuid();
        var g2 = Guid.NewGuid();
        return g1.ToString().Replace("-", "") + g2.ToString().Replace("-", "");
    }

    /*
     * Get the current Unix Epoch timestamp as a string (integer part).
     */
    public string GetTimestampAsIntegerString()
    {
        return GetTimestampAsInteger().ToString();
    }

    /*
     * Get the current Unix Epoch timestamp as an integer.
     */
    public int GetTimestampAsInteger()
    {
        return (int)GetTimestamp();
    }

    /*
     * Get the current Unix Epoch timestamp.
     */
    public double GetTimestamp()
    {
        return DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
    }
}

/*
 * An object representing the very first request we must make to Twitter.
 * 
 * This is used to retrieve the initial token which we will use to send the user
 * to Twitter for authentication and authorization.
 * 
 * The object below forms the request being made to Twitter's APIs.
 */
public class TwitterRequestToken
{
    /*
     * The API URL and Method for the request.
     */
    private string TwApiUrl = "https://api.twitter.com/oauth/request_token";
    private string TwMethod = "POST";

    /*
     * The following values will be created when the object is initialized
     * and passed to Twitter as part of the request.
     */
    private string Timestamp = null;
    private string Nonce = null;
    private string Signature = null;

    /*
     * Object for common methods - defined and explained above.
     */
    private TwitterCommon Twitter = new TwitterCommon();

    /*
     * Constructor for the Request object.
     * 
     * This constructor will use the Common class to generate new values for 
     * Timestamp and Nonce - which will be unique to this initialization of the object.
     * 
     * In addition, it adds these generated values to a dictionary which becomes
     * part of the generated hash signature - against which Twitter will verify
     * the request. Along with the API URL and request method.
     */
    public TwitterRequestToken()
    {
        this.Nonce = Twitter.GetNonce();
        this.Timestamp = Twitter.GetTimestampAsIntegerString();

        Dictionary<string, string> Params = new Dictionary<string, string>();
        Params.Add(Uri.EscapeDataString(TwitterSettings.Key_Timestamp), Uri.EscapeDataString(Timestamp));
        Params.Add(Uri.EscapeDataString(TwitterSettings.Key_Nonce), Uri.EscapeDataString(Nonce));
        this.Signature = Twitter.GetTwitterSignature(TwMethod, TwApiUrl, Params);
    }

    /*
     * Gets the Authorization string, which includes all defined values for the request
     * as well as the signature - against which the request is verified.
     * 
     * Returns a string in the proper format for attaching to the request Authorization
     * header.
     */
    public string GetAuthorizationString()
    {
        return string.Format("OAuth {0}=\"{1}\", {2}=\"{3}\", {4}=\"{5}\", {6}=\"{7}\", {8}=\"{9}\", {10}=\"{11}\"",
            TwitterSettings.Key_ConsumerKey,
            Uri.EscapeDataString(TwitterSettings.ConsumerKey),
            TwitterSettings.Key_Nonce,
            Uri.EscapeDataString(Nonce),
            TwitterSettings.Key_Signature,
            Uri.EscapeDataString(Signature),
            TwitterSettings.Key_SignatureMethod,
            TwitterSettings.SignatureMethod,
            TwitterSettings.Key_Timestamp,
            Timestamp,
            TwitterSettings.Key_Version,
            TwitterSettings.OAuthVersion);
    }

    /*
     * This method conducts the request to Twitter's APIs.
     */
    public TwitterRequestTokenResponse ExecuteAuthentication()
    {
        /*
         * The response object we're expecting from Twitter. This is a custom object
         * defined in a class below.
         */
        TwitterRequestTokenResponse parsedResponse = null;
        try
        {
            string response = null;
            string error = null;
            using (var client = new WebClient())
            {
                /*
                 * Using a try-catch within the Using statement should ensure that the WebClient is disposed.
                 * 
                 * WebClient is an easy, but possibly not optimal, solution here. Not optimal because
                 * it doesn't provide any opportunity to catch the response before it throws an error.
                 * Hence the try-catch.
                 * 
                 * Ideally, these calls would contain logic to catch the response code (400, 401, 404, 200, etc.)
                 * and react with messaging to the visitor accordingly.
                 */
                try
                {
                    client.Headers["Authorization"] = this.GetAuthorizationString();
                    response = client.UploadString(this.TwApiUrl, this.TwMethod, "");
                }
                catch (Exception ex)
                {
                    EkException.LogException(ex);
                    error = ex.Message;
                }
            }
            /*
             * The constructor for the Response object will parse the string.
             */
            parsedResponse = new TwitterRequestTokenResponse(response);
        }
        catch (Exception ex)
        {
            EkException.LogException(ex);
        }
        return parsedResponse;
    }
}

public class TwitterRequestTokenResponse
{
    /*
     * The following represent the data returned by Twitter after successful
     * completion of the request.
     * 
     * The exception is the ErrorMessage string, which I am setting in the event
     * of an error in the request.
     */
    public string OAuthToken { get; set; }
    public string OAuthTokenSecret { get; set; }
    public string ErrorMessage { get; set; }
    public bool CallbackVerified { get; set; }

    /*
     * Unfortunately, Twitter's response to this request is in a querystring-style
     * format, which means there is no simple Parse method we can employ.
     */
    public TwitterRequestTokenResponse(string response)
    {
        /*
         * Using a try-catch in case the returned string isn't in the expected format.
         * In which case, the error message will be set.
         */
        try
        {
            /*
             * The following two lines convert the name/value pairs from querystring-
             * style format to a dictionary so we can reference values by key.
             */
            var keypairs = response.Split('&');
            var keyvaluepairs = keypairs.ToDictionary(k => k.Split('=')[0], v => v.Split('=')[1]);

            /*
             * This determines whether the request was successful on Twitter's end.
             */
            CallbackVerified = bool.Parse(keyvaluepairs["oauth_callback_confirmed"]);
            /*
             * If so, then we want to retrieve the token and secret values.
             */
            if (CallbackVerified)
            {
                OAuthToken = keyvaluepairs["oauth_token"];
                OAuthTokenSecret = keyvaluepairs["oauth_token_secret"];
            }
        }
        catch (Exception ex)
        {
            CallbackVerified = false;
            ErrorMessage = ex.Message;
        }
    }
}

/*
 * An object representing the access token request to Twitter.
 * 
 * This is used to retrieve the access token which we could use to make 
 * requests to Twitter for more information. However, this also returns the
 * visitor's Twitter Screen Name and User ID, which is what we use to 
 * generate the user within Ektron.
 * 
 * The object below forms the request being made to Twitter's APIs.
 */
public class TwitterAccessTokenRequest
{
    /*
     * The API URL and Method for the request.
     */
    private string TwApiUrl = "https://api.twitter.com/oauth/access_token";
    private string TwMethod = "POST";

    /*
     * The following values will be created when the object is initialized
     * and passed to Twitter as part of the request.
     */
    private string Timestamp = null;
    private string Nonce = null;
    private string Signature = null;

    /*
     * The following values will be passed and set through the constructor.
     */
    private string AuthToken = null;
    private string AuthVerifier = null;

    /*
     * Object for common methods - defined and explained above.
     */
    private TwitterCommon Twitter = new TwitterCommon();

    /*
     * Constructor for the Request object.
     * 
     * This constructor will use the Common class to generate new values for 
     * Timestamp and Nonce - which will be unique to this initialization of the object.
     * 
     * The token and verifier passed to the constructor come from the Querystring after
     * the visitor has authenticated and Twitter redirects them to the login page.
     * 
     * In addition, it adds these generated values to a dictionary which becomes
     * part of the generated hash signature - against which Twitter will verify
     * the request. Along with the API URL and request method.
     */
    public TwitterAccessTokenRequest(string token, string verifier)
    {
        this.AuthToken = token;
        this.AuthVerifier = verifier;
        this.Nonce = Twitter.GetNonce();
        this.Timestamp = Twitter.GetTimestampAsIntegerString();

        Dictionary<string, string> Params = new Dictionary<string, string>();
        Params.Add(Uri.EscapeDataString(TwitterSettings.Key_Timestamp), Uri.EscapeDataString(Timestamp));
        Params.Add(Uri.EscapeDataString(TwitterSettings.Key_Nonce), Uri.EscapeDataString(Nonce));
        Params.Add(Uri.EscapeDataString(TwitterSettings.Key_AuthToken), Uri.EscapeDataString(AuthToken));
        this.Signature = Twitter.GetTwitterSignature(TwMethod, TwApiUrl, Params);
    }

    /*
     * Gets the Authorization string, which includes all defined values for the request
     * as well as the signature - against which the request is verified.
     * 
     * Returns a string in the proper format for attaching to the request Authorization
     * header.
     */
    public string GetAuthorizationString()
    {
        return string.Format("OAuth {0}=\"{1}\", {2}=\"{3}\", {4}=\"{5}\", {6}=\"{7}\", {8}=\"{9}\", {10}=\"{11}\", {12}=\"{13}\"",
            TwitterSettings.Key_ConsumerKey,
            Uri.EscapeDataString(TwitterSettings.ConsumerKey),
            TwitterSettings.Key_Nonce,
            Uri.EscapeDataString(Nonce),
            TwitterSettings.Key_Signature,
            Uri.EscapeDataString(Signature),
            TwitterSettings.Key_SignatureMethod,
            TwitterSettings.SignatureMethod,
            TwitterSettings.Key_Timestamp,
            Uri.EscapeDataString(Timestamp),
            TwitterSettings.Key_AuthToken,
            Uri.EscapeDataString(AuthToken),
            TwitterSettings.Key_Version,
            TwitterSettings.OAuthVersion);
    }

    /*
     * This method conducts the request to Twitter's APIs.
     */
    public TwitterAccessTokenResponse ExecuteAccessTokenRequest()
    {
        /*
         * The response object we're expecting from Twitter. This is a custom object
         * defined in a class below.
         */
        TwitterAccessTokenResponse parsedResponse = null;
        try
        {
            string response = null;
            string error = null;
            using (var client = new WebClient())
            {
                /*
                 * Using a try-catch within the Using statement should ensure that the WebClient is disposed.
                 * 
                 * WebClient is an easy, but possibly not optimal, solution here. Not optimal because
                 * it doesn't provide any opportunity to catch the response before it throws an error.
                 * Hence the try-catch.
                 * 
                 * Ideally, these calls would contain logic to catch the response code (400, 401, 404, 200, etc.)
                 * and react with messaging to the visitor accordingly.
                 */
                try
                {
                    client.Headers["Authorization"] = this.GetAuthorizationString();
                    /*
                     * Note that the verifier string is included as part of this request. Instead of being
                     * added to the header, as with the authorization string, this is put into the body of
                     * the request.
                     */
                    response = client.UploadString(this.TwApiUrl, this.TwMethod, string.Format("oauth_verifier={0}", AuthVerifier));
                    string l = string.Empty;
                }
                catch (Exception ex)
                {
                    EkException.LogException(ex);
                    error = ex.Message;
                }
            }
            /*
             * The constructor for the Response object will parse the string.
             */
            parsedResponse = new TwitterAccessTokenResponse(response);
        }
        catch (Exception ex)
        {
            EkException.LogException(ex);
        }
        return parsedResponse;
    }
}

public class TwitterAccessTokenResponse
{
    /*
     * The following represent the data returned by Twitter after successful
     * completion of the request.
     * 
     * The exception is the ErrorMessage string, which I am setting in the event
     * of an error in the request.
     */
    public string OAuthToken { get; set; }
    public string OAuthTokenSecret { get; set; }
    public string UserId { get; set; }
    public string ScreenName { get; set; }
    public string ErrorMessage { get; set; }

    /*
     * Unfortunately, Twitter's response to this request is in a querystring-style
     * format, which means there is no simple Parse method we can employ.
     */
    public TwitterAccessTokenResponse(string response)
    {
        /*
         * Using a try-catch in case the returned string isn't in the expected format.
         * In which case, the error message will be set.
         */
        try
        {
            /*
             * The following two lines convert the name/value pairs from querystring-
             * style format to a dictionary so we can reference values by key.
             */
            var keypairs = response.Split('&');
            var keyvaluepairs = keypairs.ToDictionary(k => k.Split('=')[0], v => v.Split('=')[1]);
            string tmp = string.Empty;
            bool success = false;
            
            /*
             * Because this API does not return a success boolean, we have to approach 
             * data retrieval with a bit more care. 
             * 
             * Below are a series of attempts and checks against each returned value.
             * If any error, then the method stops immediately.
             */
            success = keyvaluepairs.TryGetValue("oauth_token", out tmp);
            if (success)
                this.OAuthToken = tmp;
            else {
                ErrorMessage = "Could not retrieve auth token.";
                return;
            }

            success = keyvaluepairs.TryGetValue("oauth_token_secret", out tmp);
            if (success)
                this.OAuthTokenSecret = tmp;
            else
            {
                ErrorMessage = "Could not retrieve auth token secret.";
                return;
            }

            success = keyvaluepairs.TryGetValue("user_id", out tmp);
            if (success)
                this.UserId = tmp;
            else
            {
                ErrorMessage = "Could not retrieve Twitter User Id.";
                return;
            }

            success = keyvaluepairs.TryGetValue("screen_name", out tmp);
            if (success)
                this.ScreenName = tmp;
            else
            {
                ErrorMessage = "Could not retrieve Twitter Screen Name.";
                return;
            }

        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}