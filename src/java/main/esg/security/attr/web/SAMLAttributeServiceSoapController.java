/*******************************************************************************
 * Copyright (c) 2010 Earth System Grid Federation
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
package esg.security.attr.web;

import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import esg.security.attr.service.api.SAMLAttributeService;
import esg.security.common.SAMLParameters;
import esg.security.common.WhiteListCertificateProvider;

/**
 * Controller endpoint for SAML attribute requests with SOAP binding.
 * This controller is responsible only for managing the input and output streams of the HTTP request:
 * all other functionality is delegated to the underlying {@link SAMLAttributeService} specific to SOAP binding.
 * 
 * The controller can be optionally configured with a white-list of trusted clients that are allowed to invoke it,
 * in case mutual client-server authentication is requested.
 */
//@Controller("samlAttributeServiceSoapController")
@RequestMapping("/saml/soap/secure/attributeService.htm")
//@RequestMapping("/secure/client-cert/saml/soap/attributeService.htm")
public class SAMLAttributeServiceSoapController {
	
	private final SAMLAttributeService samlAttributeService;
	
	private WhiteListCertificateProvider whiteListCertificateProvider;
	
	@Autowired
	public SAMLAttributeServiceSoapController(final @Qualifier("samlAttributeService") SAMLAttributeService samlService) {
		this.samlAttributeService = samlService;
	}
	
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST} )
	public void process(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) throws Exception {
		
		// optional white-listing of clients for SSL mutual authentication
		if (httpRequest.isSecure() && whiteListCertificateProvider!=null) {
			if (!whiteListCertificateProvider.validate(httpRequest)) throw new Exception("Client is not included in server's white list");
		}
		
		// read SOAP/SAML request from HTTP request
		final InputStream inputStream = httpRequest.getInputStream();	
		
		// process SOAP/SAML request
		final String xml = samlAttributeService.processAttributeQuery(inputStream);
		
		// write SOAP/SAML response to HTTP response
		httpResponse.setContentType(SAMLParameters.CONTENT_TYPE_XML);
		httpResponse.getWriter().write( xml );
	
	}
	
	/**
	 * Setter method for optional {@link WhiteListCertificateProvider}.
	 * @param whiteListCertificateProvider
	 */
	public void setWhiteListCertificateProvider(final WhiteListCertificateProvider whiteListCertificateProvider) {
		this.whiteListCertificateProvider = whiteListCertificateProvider;
	}


}
