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
package esg.saml.authz.main;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.springframework.core.io.ClassPathResource;

import esg.saml.common.SOAPServiceClient;
import esg.saml.utils.ssl.CertUtils;

/**
 * Example client to contact a deployed ESG SAML Authorization Service via SOAP binding.
 * This class is setup to query a SAML Authorization Service deployed on localhost on the secure port 8443,
 * and to use its own certificate and trustore to setup mutual authentication with the service.
 * 
 * Note that if the remote Authorization Service is configured with a white list of authorized clients,
 * this client's certificate subject must be included in the white list.
 * 
 */
public class SecureSAMLAuthorizationServiceSOAPClient {

	  private static final String ENDPOINT = "https://localhost:8443/esg-saml/saml/soap/secure/authorizationService.htm";
	  private static final String SAML_REQUEST = "esg/saml/authz/main/SAMLauthorizationQueryRequest.xml";
	  
	  public static void main(String[] args) throws Exception {
		  
		  // setup client certificate and trustore for mutual authentication
		  CertUtils.setTruststore("esg/saml/resources/client-trustore.ks");
		  CertUtils.setKeystore("esg/saml/resources/client-cert.ks");
	  			  
		  final File file = new ClassPathResource(SAML_REQUEST).getFile();
		  final String samlRequest = FileUtils.readFileToString(file);
		  final SOAPServiceClient client = new SOAPServiceClient();
		  client.doSoap(ENDPOINT, samlRequest);
						  	  
	  }
	
}
