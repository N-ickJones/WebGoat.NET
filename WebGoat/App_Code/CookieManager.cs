using System;
using System.Web;
using System.Web.Security;

namespace OWASP.WebGoat.NET.App_Code
{
    public class CookieManager
    {
        public CookieManager()
        {
        }
        
        public static HttpCookie SetCookie(FormsAuthenticationTicket ticket, string cookieId, string cookieValue)
        {
            string encrypted_ticket = FormsAuthentication.Encrypt(ticket);
 
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted_ticket);

            if (ticket.IsPersistent)
                cookie.Expires = ticket.Expiration;
                
            return cookie;
            

        }
    }
}

