# CloudCherry SSO through Active Directory

Large businesses can enable Role based SSO(Single Sign On) for their users who are already authenticated by their intranet/website or email system or software such as CMS/ERP/CRM/PoS; SSO prevents duplication of effort to create and maintain open hundreds of username/password profiles for large businesses with many employees. 

SSO works by building a information packet(JSON) with the authenticated user’s information and then encrypting the packet to obtain a SSO token that can be passed on to CloudCherry API for automatic login.

### Getting Started

- [ ] Install [Visual Studio](https://visualstudio.microsoft.com/).
- [ ] Clone this [repo](https://github.com/Femilshajin/CloudCherry-SSO-Active-Directory).
- [ ] Open the project in Visual Studio.
- [ ] Create a [Active Directory application](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal#get-application-id-and-authentication-key).
- [ ] Open Web.Config and replace the below values.
  - **ida:ClientId** - [Get Application id](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal#get-application-id-and-authentication-key)
  - **ida:TenantId** - [Get tenant id](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal#get-tenant-id)
  - **ida:Domain** - Your Domain for Active Directory
  - **ssokey** - SSO Key to be configured in CloudCherry Insight Centre.
  - **ccaccount** - You CloudCherry Account Name.
- [ ] Run the project.

#### What is happening when you run the MVC App?

[API Tech whitepaper - Page 29](https://contentcdn.azureedge.net/assets/CherryAPITechnologyWhitepaper.pdf) and [Sample code](https://www.getcloudcherry.com/api/) is here.

On Successful Authentication from your AD, you will be presented with a Web Page. By clicking on ***Login to CloudCherry*** SSOToken will be created and you would be redirected to CloudCherry Insight Centre along with SSOToken and account name ( "https://cx.getcloudcherry.com/#/login?sso=<accountName>&ssotoken=<token>").

[More info here](https://github.com/getcloudcherry/CloudCherry-SSO-Active-Directory/blob/master/docs/ADFS-SSO.pdf)

#### Where is the code for SSOToken Generation?

You can find it [here](https://github.com/Femilshajin/CloudCherry-SSO-Active-Directory/blob/master/CloudCherrySSO/Helpers/SSOHelper.cs).

#### How to use an On-Premise Identity Server and Connect to CloudCherry?

It's almost as similar as previous steps, [this blog](http://work.haufegroup.io/haufe-adfs-identity-for-aspnet-login/) explains it much better.
