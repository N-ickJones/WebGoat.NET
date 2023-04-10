using System;
using System.Web;
using System.Web.UI;
using OWASP.WebGoat.NET.App_Code.DB;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET
{
	public partial class Default : System.Web.UI.Page
	{
        private IDbProvider du = Settings.CurrentDbProvider;
        
        protected void ButtonProceed_Click(object sender, EventArgs e)
        {
            Response.Redirect("RebuildDatabase.aspx");
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            if (du.TestConnection())
            {
                lblOutput.Text = string.Format("You appear to be connected to a valid {0} provider. " +
                                               "If you want to reconfigure or rebuild the database, click on the button below!", du.Name);
                Session["DBConfigured"] = true;

                HttpCookie cookie = new HttpCookie("Server", Encoder.Encode(Server.MachineName));
                Response.Cookies.Add(cookie);
            }
            else
            {
                lblOutput.Text = "Before proceeding, please ensure this instance of WebGoat.NET can connect to the database!";
            }

            ViewState["Session"] = Session.SessionID;
        }
    }
}

