using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Ektron.Cms;
using Ektron.Cms.Framework.User;

public partial class webforms_SimpleThirdPartyAuth : System.Web.UI.Page
{
    private UserManager _userCRUD = null;
    private UserManager UserCRUD { get { return _userCRUD ?? (_userCRUD = new UserManager()); } }

    protected void Page_Load(object sender, EventArgs e)
    {
        /*
         * Sets the login/logout view based on the current user's context.
         * 
         * Note that this context service is the most efficient way to determine 
         * whether the current visitor is logged in as it does not require you 
         * to initialize any objects, such as the UserManager defined above.
         */
        if (Ektron.Cms.Framework.Context.UserContextService.Current.IsLoggedIn)
        {
            uxAuthenticationViews.SetActiveView(uxLogoutView);
        }
        else
        {
            uxAuthenticationViews.SetActiveView(uxLoginView);
        }
    }

    protected void uxLogin_Click(object sender, EventArgs e)
    {
        /*
         * The system against which the user will be authenticated.
         */
        var AuthenticationSystem = new AuthenticationClass();

        /*
         * Attempt to authenticate the user using third-party system.
         */
        bool authenticated = AuthenticationSystem.Authenticate(uxUsername.Text, uxPassword.Text);

        if (authenticated)
        {
            /*
             * The class used to login/create Ektron proxy users.
             */
            var EktronProxyUserManager = new ThirdPartyUserManagement();

            /*
             * Attempt login.
             */
            bool ektronLoginSuccess = EktronProxyUserManager.AttemptProxyUserLogin(AuthenticationSystem.AuthenticationSystemId, uxUsername.Text);

            /*
             * If login attempt failed...
             */
            if (!ektronLoginSuccess)
            {
                /*
                 * Create new user from auth system.
                 * 
                 * You may want to have the user complete a more robust profile before this step.
                 * I simply chose the path of least resistance here to illustrate one of several
                 * possible scenarios.
                 */
                bool ektronUserCreated = EktronProxyUserManager.CreateEktronProxyUser(AuthenticationSystem.AuthenticationSystemId, uxUsername.Text);

                /*
                 * If we were able to create the user...
                 */
                if (ektronUserCreated)
                {
                    /*
                     * Attempt to login the newly created user.
                     */
                    ektronLoginSuccess = EktronProxyUserManager.AttemptProxyUserLogin(AuthenticationSystem.AuthenticationSystemId, uxUsername.Text);
                }
            }

            if (ektronLoginSuccess)
            {
                /*
                 * Redirect to ensure the cookie is properly set and to clear any postback data.
                 */
                Response.Redirect(Request.RawUrl);
            }
            else
            {
                // show error message
            }
        }
    }

    protected void uxLogout_Click(object sender, EventArgs e)
    {
        UserCRUD.Logout();
        /*
        * Redirect to ensure the cookie is properly set and to clear any postback data.
        */
        Response.Redirect(Request.RawUrl);
    }
}

public class ThirdPartyUserManagement
{
    /*
     * Only initializes the UserManager when called.
     */
    private UserManager _userCRUD = null;
    private UserManager UserCRUD { get { return _userCRUD ?? (_userCRUD = new UserManager(Ektron.Cms.Framework.ApiAccessMode.Admin)); } }

    public bool CreateEktronProxyUser(long systemId, string username)
    {
        try
        {
            /*
             * Assuming the Username is not alterable in the third party system.
             * 
             * If it modifyable by the user, such as a Twitter Screen Name, then
             * use a different, immutable ID from the 3rd party system.
             * 
             * The following are required fields.
             * 
             * Remember to set the IsMembersip flag to prevent admin or author access.
             */
            var newUser = new UserData();
            newUser.IsMemberShip = true;
            newUser.Username = username;
            newUser.DisplayName = username;
            newUser.FirstName = "not set";
            newUser.LastName = "not set";
            newUser.Password = UserCRUD.GetRandomPasswordforDefaultRegex();

            /*
             * The authentication system ID and User ID to login this user.
             * 
             * The system ID should be unique for each 3rd party system and be
             * the same for every user who authenticates against this system.
             */
            newUser.AuthenticationTypeId = systemId;
            newUser.AuthenticationUserId = username;

            /*
             * Required custom properties.
             */
            var props = UserCRUD.GetCustomPropertyList();
            props["Time Zone"].Value = "Eastern Standard Time";
            newUser.CustomProperties = props;

            /*
             * Add the user.
             */
            UserCRUD.Add(newUser);
        }
        catch (Exception ex)
        {
            EkException.LogException(ex);
            return false;
        }
        return true;
    }

    public bool AttemptProxyUserLogin(long systemId, string username)
    {
        try
        {
            /*
             * Assuming the Username is not alterable in the third party system.
             * 
             * If it modifyable by the user, such as a Twitter Screen Name, then
             * use a different, immutable ID from the 3rd party system.
             * 
             * Note that this is the only way to login the user without having Ektron
             * also store the password. If you're authenticating against a third-party 
             * system, you do *not* want to store the password for that system within
             * Ektron nor authenticate proxy users against it. Instead, you want to rely
             * solely on the third party system to verify authentication and authorization.
             * 
             * One reason being that you never know when the password in the third party 
             * system has changed. If you relied upon that password, and the two were out
             * of sync, then you would break authentication using that system.
             */
            var userData = UserCRUD.Login(systemId, username);
        }
        catch (Exception ex)
        {
            /*
             * An exception is usually due to the user not existing. However, you can
             * still log it just in case something larger is wrong.
             */
            EkException.LogException(ex);
            return false;
        }
        return true;
    }
}

public class AuthenticationClass
{
    /*
     * This ID should be the same for all users who authenticate against a given third-party system.
     */
    public long AuthenticationSystemId { get { return 5900; } }

    public bool Authenticate(string username, string password)
    {
        /*
         * Do authentication here.
         * 
         * This is just a placeholder method which returns true as long 
         * as both parameters have a value.
         */
        return (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password));
    }

    public AuthenticationClass() { }
}