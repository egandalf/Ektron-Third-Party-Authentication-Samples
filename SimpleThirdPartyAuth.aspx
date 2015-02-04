<%@ Page Language="C#" AutoEventWireup="true" CodeFile="SimpleThirdPartyAuth.aspx.cs" Inherits="webforms_SimpleThirdPartyAuth" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Simple Third Party Auth</title>
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
    <form id="form1" runat="server">
        <div class="container">
            <div class="row">
                <div class="col-sm-6 col-sm-offset-3">
                    <asp:MultiView id="uxAuthenticationViews" runat="server">
                        <asp:View ID="uxLoginView" runat="server">
                            <div class="panel panel-primary">
                                <div class="panel-heading">
                                    Login
                                </div>
                                <div class="panel-body">
                                    <div class="alert alert-danger" id="uxLoginError" runat="server" visible="false"></div>
                                    <div class="form-group">
                                        <asp:Label id="uxUsernameLabel" runat="server" AssociatedControlID="uxUsername" Text="Username" CssClass="control-label" />
                                        <asp:TextBox ID="uxUsername" runat="server" Placeholder="Username" CssClass="form-control" />
                                    </div>
                                    <div class="form-group">
                                        <asp:Label ID="uxPasswordLabel" runat="server" AssociatedControlID="uxPassword" Text="Password" CssClass="control-label" />
                                        <asp:TextBox ID="uxPassword" runat="server" Placeholder="Password" CssClass="form-control" />
                                    </div>
                                    <asp:Button ID="uxLogin" runat="server" Text="Sign-in" OnClick="uxLogin_Click" />
                                </div>
                            </div>
                        </asp:View>
                        <asp:View ID="uxLogoutView" runat="server">
                            <div class="panel panel-primary">
                                <div class="panel-heading">
                                    Logout
                                </div>
                                <div class="panel-body">
                                    <div class="alert alert-danger" id="Div1" runat="server" visible="false"></div>
                                    <asp:Button ID="uxLogout" runat="server" Text="Sign Out" OnClick="uxLogout_Click" />
                                </div>
                            </div>
                        </asp:View>
                    </asp:MultiView>
                </div>
            </div>
        </div>
    </form>
</body>
</html>
