<%@ Page Title="About" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="About.aspx.cs" Inherits="twitter.About" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <h1>Tweet here</h1>
    <table>
         <tr>
            <td>
                <label id="Label2" runat="server">Consumer Key: </label>
            </td>
            <td>
                <asp:TextBox ID="txtConsumerKey" runat="server"></asp:TextBox>
            </td>
            <td>
                <label id="Label3" runat="server">Consumer Secret: </label>
            </td>
            <td>
                <asp:TextBox ID="txtConsumerSecret" runat="server"></asp:TextBox>
            </td>
        </tr>
        <tr>
            <td>
                <asp:Button ID="Button3" runat="server" OnClick="Button1_Click" Text="Authorize" />
            </td>



        </tr>
        <tr>
            <td>
               <label id="lblTweet" runat="server">Tweet Text: </label>
            </td>
            <td>

    <asp:TextBox ID="txtTweet" TextMode="MultiLine" runat="server"></asp:TextBox>
            </td>
            <td>
                <label id="lblpin" runat="server">Pin: </label>
            </td>
            <td>
                 <asp:TextBox ID="txtTweetPin" runat="server"></asp:TextBox>
            </td>
        </tr>
        <tr>
            <td colspan="4">
                   <asp:Button ID="btnTweet" runat="server"  Text="Tweet" OnClick="btnTweet_Click" />
            </td>
        </tr>
    </table>
</asp:Content>
