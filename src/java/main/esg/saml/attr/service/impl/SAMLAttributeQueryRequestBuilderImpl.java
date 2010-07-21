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
package esg.saml.attr.service.impl;

import org.opensaml.saml2.core.AttributeQuery;

import esg.saml.attr.service.api.SAMLAttributeQueryRequestBuilder;
import esg.saml.common.SAMLBuilder;
import esg.saml.common.SAMLParameters;

/**
 * Standard implementation of {@link SAMLAttributeQueryRequestBuilder} to request the user attributes
 * exchanged within the ESG federation.
 */
class SAMLAttributeQueryRequestBuilderImpl implements SAMLAttributeQueryRequestBuilder {
		
	/**
	 * Utility class to help build SAML objects.
	 */
	private final SAMLBuilder builder;
        
    /**
     * Flag to disable inclusion of ID or IssueInstant within serialized output (to facilitate testing).
     */
    private boolean includeFlag = true;

    SAMLAttributeQueryRequestBuilderImpl() { 
    	
    	this.builder = SAMLBuilder.getInstance();
    	
    }

	/**
	 * {@inheritDoc}
	 */
	public AttributeQuery buildAttributeQueryRequest(final String openid, final String issuer) {
					
		// <?xml version="1.0" encoding="UTF-8"?>
		//  <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="c9a2bd30-6186-46d7-a8f3-e51367921f51" IssueInstant="2009-07-28T15:24:52.895Z" Version="2.0"/>
		final AttributeQuery attributeQuery = builder.getAttributeQuery(includeFlag);
        
        // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
        attributeQuery.setIssuer( builder.getIssuer(issuer) );
        
        // <saml:Subject>
        // 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
        // </saml:Subject>
        attributeQuery.setSubject( builder.getSubject(openid) );
        
        // <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string"/>
        attributeQuery.getAttributes().add( builder.getAttribute(SAMLParameters.FIRST_NAME, SAMLParameters.FIRST_NAME_FRIENDLY, null) );
        
        // <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string"/>
        attributeQuery.getAttributes().add( builder.getAttribute(SAMLParameters.LAST_NAME, SAMLParameters.LAST_NAME_FRIENDLY, null) );
        
        // <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="EmailAddress" Name="urn:esg:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string"/>
        attributeQuery.getAttributes().add( builder.getAttribute(SAMLParameters.EMAIL_ADDRESS, SAMLParameters.EMAIL_ADDRESS_FRIENDLY, null) );
        
        // <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="GroupRole" Name="urn:esg:group:role" NameFormat="http://www.w3.org/2001/XMLSchema#string"/>
        attributeQuery.getAttributes().add( builder.getAttribute(SAMLParameters.GROUP_ROLE, SAMLParameters.GROUP_ROLE_FRIENDLY, null) );
		
		return attributeQuery;
			
	}
	
	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
	}

}
