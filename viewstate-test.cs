using System;
using System.Web.UI;

// Test file for ASP.NET ViewState vulnerability detection

public partial class VulnerablePage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // CRITICAL: Disabling ViewState MAC allows deserialization attacks
        this.EnableViewStateMac = false;

        // HIGH: Disabling encryption exposes ViewState contents
        this.ViewStateEncryptionMode = ViewStateEncryptionMode.Never;
    }

    protected void Page_Init(object sender, EventArgs e)
    {
        // Also vulnerable when set in Page_Init
        Page.EnableViewStateMac = false;
    }

    private void ConfigureViewState()
    {
        // Even in private helpers, this is a global config risk
        EnableViewStateMac = false;
        ViewStateEncryptionMode = ViewStateEncryptionMode.Never;
    }
}

// Web.config style patterns
/*
<configuration>
  <system.web>
    <pages enableViewStateMac="false" viewStateEncryptionMode="Never" />
    <machineKey validation="None" />
  </system.web>
</configuration>
*/

// Page directive style
// <%@ Page EnableViewStateMac="false" ViewStateEncryptionMode="Never" %>
