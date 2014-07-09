/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.security.webclient;

import java.io.File;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FileUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import esg.security.common.SOAPServiceClient;

/**
 * Demo controller provided for testing the deployed ESGF Security Services from a web interface.
 * 
 * The following optional HTTP parameters can be specified:
 * @param openid : the user's openid (Attribute and Authorization Services)
 * @param resource : the resource to be authorized (Authorization Service only)
 * @param action : the action to be authorized (Authorization Service only)
 * 
 * @author Luca Cinquini
 */
@Controller
@RequestMapping("/test/*")
public class TestController {
	
	// attribute service 
	private static final String ATTRIBUTE_REQUEST = "esg/security/attr/main/SAMLattributeQueryRequest.xml";
	private static final String ATTRIBUTE_SERVICE_URI = "/saml/soap/secure/attributeService.htm";  	
	 
	// authorization service
	private static final String AUTHORIZATION_SERVICE_URI = "/saml/soap/secure/authorizationService.htm";  	
	private static final String AUTHORIZATION_REQUEST = "esg/security/authz/main/SAMLauthorizationQueryRequest.xml";
	 
	// optional HTTP parameters and default values
	private static final String PARAM_OPENID = "openid";
	private static final String PARAM_OPENID_DEFAULT = "https://localhost:8443/esgf-idp/openid/testUser";
	private static final String PARAM_RESOURCE = "resource";
	private static final String PARAM_RESOURCE_DEFAULT = "/test/myfile";
	private static final String PARAM_ACTION = "action";
	private static final String PARAM_ACTION_DEFAULT = "Read";

	
	@RequestMapping(value="attributeService.htm", method = { RequestMethod.GET, RequestMethod.POST } )
	public void testAttributeService(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) throws Exception {
			
		  // Attribute Service full URL
		  final String serviceUrl = httpRequest.getRequestURL().toString().replace("/test/attributeService.htm", ATTRIBUTE_SERVICE_URI);
		  
		  // send SAML request to service, render SAML response to browser
		  doSoap(httpRequest, httpResponse, ATTRIBUTE_REQUEST, serviceUrl);

	}
	
	@RequestMapping(value="authorizationService.htm", method = { RequestMethod.GET, RequestMethod.POST} )
	public void testAuthorizationService(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) throws Exception {
		
		  // Attribute Service full URL
		  final String serviceUrl = httpRequest.getRequestURL().toString().replace("/test/authorizationService.htm", AUTHORIZATION_SERVICE_URI);
		  
		  // send SAML request to service, render SAML response to browser
		  doSoap(httpRequest, httpResponse, AUTHORIZATION_REQUEST, serviceUrl);

	}

	
	/**
	 * Method that executes most of the business logic to query the Attribute and Authorization Services.
	 * @param httpRequest
	 * @param httpResponse
	 * @param samlRequestFilePath
	 * @param serviceUrl
	 * @throws Exception
	 */
	private void doSoap(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse, final String samlRequestFilePath, final String serviceUrl) throws Exception {
		
		  // load example attribute query
		  final File file = new ClassPathResource(samlRequestFilePath).getFile();
		  String samlRequest = FileUtils.readFileToString(file);
		
		  // replace values of optional HTTP parameters
		  samlRequest = replaceDefaultValue(httpRequest, PARAM_OPENID, PARAM_OPENID_DEFAULT, samlRequest);
		  samlRequest = replaceDefaultValue(httpRequest, PARAM_RESOURCE, PARAM_RESOURCE_DEFAULT, samlRequest);
		  samlRequest = replaceDefaultValue(httpRequest, PARAM_ACTION, PARAM_ACTION_DEFAULT, samlRequest);
		
		  // SOAP request/response
		  final SOAPServiceClient client = SOAPServiceClient.getInstance();
		  final String text = client.doSoap(serviceUrl, samlRequest);
		  
		  // render SOAP response to view
		  final ServletOutputStream os = httpResponse.getOutputStream();
	      os.write(text.getBytes());
	      os.close();
	}
	
	/**
	 * Method to substitute for the default value if the HTTP request specifies the value of a named parameter.
	 * 
	 * @param httpRequest
	 * @param paramName
	 * @param paramDefaultValue
	 * @param xml
	 * @return
	 */
	private String replaceDefaultValue(final HttpServletRequest httpRequest, final String paramName, final String paramDefaultValue, String xml) {
		  final String parValue = httpRequest.getParameter(paramName);
		  if (StringUtils.hasText(parValue)) {
			  xml = xml.replace(paramDefaultValue, parValue);
		  }
		  return xml;
	}

}
