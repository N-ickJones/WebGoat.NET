using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.Security;
using System.Web.Configuration;

namespace OWASP.WebGoat.NET
{
    public partial class LoginPage : System.Web.UI.Page
    {
		protected void Page_Load(object sender, EventArgs e)
    	{
    	}
    
    	protected void ButtonLogOn_Click(object sender, EventArgs e)
    	{
            Response.Redirect("/WebGoatCoins/CustomerLogin.aspx");

	    }
    	protected void ButtonAdminLogOn_Click(object sender, EventArgs e)
    	{
    
    	}
	}
}
