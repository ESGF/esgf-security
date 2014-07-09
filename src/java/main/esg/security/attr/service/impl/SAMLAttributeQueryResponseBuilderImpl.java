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
package esg.security.attr.service.impl;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributeQueryResponseBuilder;
import esg.security.attr.service.api.SAMLAttributeStatementHandler;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Standard implementation of {@link SAMLAttributeQueryResponseBuilder} that obtains the user attributes information
 * from a {@link SAMLAttributeFactory} implementation, passes it to a  {@link SAMLAttributeStatementHandler} to encode it
 * in a SAML assertion, and finally embeds the SAML assertion within a response document.
 */
class SAMLAttributeQueryResponseBuilderImpl implements SAMLAttributeQueryResponseBuilder {
		
	/**
	 * Factory used to create {@link SAMLAttributes} objects that are then encoded.
	 */
	private final SAMLAttributeFactory samlAttributesFactory;
		
	/**
	 * Utility class to help build SAML objects.
	 */
	private final SAMLBuilder builder;
	
	/**
	 * Collaborator handler responsible for building the SAML AttributeStatement Assertion following an AttributeQuery.
	 */
	private final SAMLAttributeStatementHandlerImpl samlAttributeStatementHandler;
        
    /**
     * Flag to disable inclusion of ID or IssueInstant within serialized output (to facilitate testing).
     */
    private boolean includeFlag = true;

    SAMLAttributeQueryResponseBuilderImpl(final SAMLAttributeFactory samlAttributesFactory) {
    	
    	this.samlAttributesFactory = samlAttributesFactory;
    	
    	this.builder = SAMLBuilder.getInstance();
    	this.samlAttributeStatementHandler = new SAMLAttributeStatementHandlerImpl();
    	
    }

	/**
	 * {@inheritDoc}
	 */
	public Response buildAttributeQueryResponse(final AttributeQuery request) {
		
		final String openid = request.getSubject().getNameID().getValue();
		final String requestID = request.getID();
		
		// <?xml version="1.0" encoding="UTF-8"?>
		// 		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="9566201b-63ad-4f14-b6c0-6cf6b35a90e0" IssueInstant="2009-07-28T23:07:00.081Z" Version="2.0"/>
		final Response response = builder.getResponse(requestID, includeFlag);
		
        // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
		response.setIssuer( builder.getIssuer( samlAttributesFactory.getIssuer()) );
		
		// retrieve SAML attributes for specified user
		try {
			
			final SAMLAttributes samlAttributes = samlAttributesFactory.newInstance(openid);
			
			final Assertion assertion = samlAttributeStatementHandler.buildAttributeStatement(samlAttributes, request.getAttributes());			
			
			// openid found > success
			//  <samlp:Status>
		    // 		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		    //	</samlp:Status>
			response.setStatus( builder.getStatus(true) );
			
			response.getAssertions().add(assertion);

			
		} catch(SAMLUnknownPrincipalException e) {
			
			// openid not found > failure
			response.setStatus( builder.getStatus(false) );

		}
				
		return response;
		
	}

	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
		this.samlAttributeStatementHandler.setIncludeFlag(includeFlag);
	}

}
