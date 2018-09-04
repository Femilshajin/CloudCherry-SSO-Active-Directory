using CloudCherrySSO.Helpers;
using CloudCherrySSO.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CloudCherrySSO.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public async Task<ActionResult> Index()
        {
            return View();
        }

        public async Task<ActionResult> CloudCherry()
        {

            try
            {
                string ssoKey = ConfigurationManager.AppSettings["ssokey"];
                string ccAccount = ConfigurationManager.AppSettings["ccaccount"];
                
                var identity = (ClaimsIdentity)User.Identity;
                if (identity != null)
                {
                    string userId = string.IsNullOrEmpty(identity.Name) ? null : Regex.Replace(identity.Name.Split('@').FirstOrDefault(), @"[^0-9a-zA-Z]+", string.Empty); ;
                    string emailId = identity.Name;

                    var subUser = new SSOSubUser
                    {
                        Userid = userId, // SSO user to login
                        Role = "ManagerReadOnly", //Manager Or ManagerReadOnly
                        Email = emailId,
                        TimeStamp = DateTime.UtcNow,
                        SSOKey = ssoKey,
                        ManagedBy = ccAccount
                    };


                    var redirectUrl = await SSOHelper.GetSSOTokenURL(subUser);

                    SSOHelper.WriteLog($"Redirecting {ccAccount} - {userId} to CloudCherry");
                    return Redirect(redirectUrl);
                }

                SSOHelper.WriteLog("Identity Not Found");
                return Redirect($"{SSOHelper.webBaseURL}#/login?errormsg=Unable to sign-in, contact administrator");
            }
            catch (Exception ex)
            {
                SSOHelper.WriteErrorLog(ex);
                return Redirect($"{SSOHelper.webBaseURL}#/login?errormsg=Unable to sign-in, contact administrator");
            }
        }

        public ActionResult About()
        {
            ViewBag.Message = "The Most Advanced, Simple to Use CX Platform on the Market";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "WE WOULD BE DELIGHTED TO ASSIST YOU.";

            return View();
        }
    }
}