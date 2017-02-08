<%@ Page Title="Home Page" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="twitter._Default" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <h1>Twitter Application</h1>

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
                <label id="lblhashtag" runat="server">Enter Hashtag: </label>
            </td>
            <td>
                <asp:TextBox ID="txtHashtag" runat="server"></asp:TextBox>
            </td>
        </tr>
        <tr>
            <td>
                <label id="lblHandler" runat="server">Enter Handler: </label>
            </td>
            <td>
                <asp:TextBox ID="txtHandler" runat="server"></asp:TextBox>
            </td>
        </tr>
        <tr>
            <td>
                <label id="lblpin" runat="server">Enter Pin: </label>
            </td>

            <td>
                <asp:TextBox ID="txtPin" runat="server"></asp:TextBox>
            </td>
        </tr>
        <tr>
            <td>
                <asp:Button ID="Button2" runat="server" OnClick="Button2_Click" Text="Retweet" />
            </td>
        </tr>
        <tr>
            <td colspan="4">
               <label id="lblresponse"  visible="false" runat="server"> </label>
            </td>
        </tr>
       
     
    </table>
     <hr />
   


</asp:Content>
