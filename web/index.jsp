<%@ include file="/WEB-INF/views/jsp/common/include.jsp" %>

<tiles:insertDefinition name="center-layout" >
	
	<tiles:putAttribute type="string" name="title" value="ESGF Security Services" />
	
<tiles:putAttribute name="body">

<p/>
<h1>ESGF SECURITY WEB SERVICES</h1>

<p/>
Welcome to the ESGF Security Web Services home page.
<br/>These services are not intended to be invoked through a web browser, rather by web service clients running
either as stand-alone programs, or as part of a more complex application.
<br/>This home page is provided only as a convenient mechanism to verify that the deployed services are running,
and to debug the service response to user-specified input.	
	
<hr/>

<h2>ESGF Attribute Service</h2>
<p/>
The Attribute Service is used to query basic personal information and access control attributes about a user with a given identity (openid).
<br/>The user's identity must be found in whatever back-end database the Attribute Service is configured to look into, together with any attribute that
is requested. 
<br/>The service must be invoked with a properly formatted SAML (XML) request, and will return a SAML response.
<br/>
<b>Attribute Service relative URL</b>: <a href='<c:url value="/saml/soap/secure/attributeService.htm" />'>/saml/soap/secure/attributeService.htm</a>
<br/>
NOTE: clicking on the above link will verify whether the service is up, but will cause an HTTP/500 error because the service is invoked without an XML request.
<br/>
You can use the form below to send a properly formatted query to the Attribute Service.
<p/>
<div class="box">
	<form name="testAttributeServiceForm" method="post" action='<c:url value="/test/attributeService.htm"/>'>
		<table align="center">
			<caption>Attribute Service Test Form</caption>
			<tr>
				<td align="right"><b>OpenID</b></td>
				<td align="left"><input type="text" name="openid" value="https://localhost:8443/esgf-idp/openid/testUser" size="100"/></td>
			</tr>
			<tr>
				<td align="right" colspan="2"> <input type="submit" value="Submit"  /></td>
			</tr>
		</table>
	</form>
</div>

<hr/>
<h2>ESFG Authorization Service</h2>
<p/>
The Authorization Service is used to authorize a user with a given identity to execute an action on a given resource.

<br/>To return a positive authorization, the following information must be configured in the back-end services used by the Authorization Service:
<ul>
	<li><b>Policy Service</b>: the requested action must be permitted for the requested resource to all users that possess a given attribute (type, value) pair</li>
	<li><b>Registry Service</b>: the attribute type must be registered with an Attribute Service that can be queried to retrieve attribute values of that type about a given user
	<li><b>Attribute Service</b>: the user must be assigned the necessary attribute type and value
</ul>
<br/>
<b>Authorization Service relative URL</b>: <a href='<c:url value="/saml/soap/secure/authorizationService.htm" />'>/saml/soap/secure/authorizationService.htm</a>
<br/>
NOTE: clicking on the above link will verify whether the service is up, but will cause an HTTP/500 error because the service is invoked without an XML request.
<br/>
You can use the form below to send a properly formatted query to the Authorization Service.
<p/>
<div class="box">
	<form name="testAuthorizationServiceForm" method="post" action='<c:url value="/test/authorizationService.htm"/>'>
		<table align="center">
			<caption>Authorization Service Test Form</caption>
			<tr>
				<td align="right"><b>OpenID</b></td>
				<td align="left"><input type="text" name="openid" value="https://localhost:8443/esgf-idp/openid/testUser" size="100"/></td>
			</tr>
			<tr>
				<td align="right"><b>Resource</b></td>
				<td align="left"><input type="text" name="resource" value="/test/myfile" size="100"/></td>
			</tr>
			<tr>
				<td align="right"><b>Action</b></td>
				<td align="left"><input type="text" name="action" value="Read" size="100"/></td>
			</tr>
			<tr>
				<td align="right" colspan="2"> <input type="submit" value="Submit"  /></td>
			</tr>
		</table>
	</form>
</div>

<hr/>
<h2>ESFG Policy Service</h2>
<p/>
The Policy Service is used to determine the Policy Attributes required to execute an action on a given resource.
<p/>
<b>Policy Service relative URL</b>: <a href='<c:url value="/secure/policyService.htm" />'>/secure/policyService.htm</a>
<br/>
NOTE: clicking on the above link will verify whether the service is up, but will cause an HTTP/500 error because the service must be invoked with the proper HTTP parameters.
<br/>
You can use the form below to send a properly formatted query to the Policy Service.
<p/>
<div class="box">
	<form name="testPolicyServiceForm" method="post" action='<c:url value="/secure/policyService.htm"/>'>
		<table align="center">
			<caption>Policy Service Test Form</caption>
			<tr>
				<td align="right"><b>Resource</b></td>
				<td align="left"><input type="text" name="resource" value="/test/myfile" size="100"/></td>
			</tr>
			<tr>
				<td align="right"><b>Action</b></td>
				<td align="left"><input type="text" name="action" value="Read" size="100"/></td>
			</tr>
			<tr>
				<td align="right" colspan="2"> <input type="submit" value="Submit"  /></td>
			</tr>
		</table>
	</form>
</div>

</tiles:putAttribute>

</tiles:insertDefinition>