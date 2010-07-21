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
package esg.saml.authz.service.impl;

import org.opensaml.saml2.core.AuthzDecisionQuery;

import esg.saml.authz.service.api.SAMLAuthorizationQueryRequestBuilder;
import esg.saml.common.SAMLBuilder;

/**
 * Standard implementation of {@link SAMLAuthorizationQueryRequestBuilder}.
 */
class SAMLAuthorizationQueryRequestBuilderImpl implements SAMLAuthorizationQueryRequestBuilder {
				
	/**
	 * Utility class to help build SAML objects.
	 */
	private final SAMLBuilder builder;
	        
    /**
     * Flag to disable inclusion of ID or IssueInstant within serialized output (to facilitate testing).
     */
    private boolean includeFlag = true;

    SAMLAuthorizationQueryRequestBuilderImpl() {
    	    	
    	this.builder = SAMLBuilder.getInstance();
    	
    }

	
	/**
	 * {@inheritDoc}
	 */
	public AuthzDecisionQuery buildAuthorizationQueryRequest(final String openid, String resource, String action, String issuer) {
		
		// <samlp:AuthzDecisionQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="b0f70731-8d1b-4744-a842-0fd26d2d0089" IssueInstant="2010-01-25T21:20:03.549Z" Resource="/PATH/TO/FILE" Version="2.0">
		final AuthzDecisionQuery authzDecisionQuery = builder.getAuthzDecisionQuery(includeFlag);
		authzDecisionQuery.setResource(resource);

        // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
		authzDecisionQuery.setIssuer( builder.getIssuer( issuer ) );

        // <saml:Subject>
        // 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
        // </saml:Subject>
        authzDecisionQuery.setSubject( builder.getSubject(openid) );
        
	    //<saml:Action xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">read</saml:Action>
        authzDecisionQuery.getActions().add( builder.getAction(action) );
		        
		return authzDecisionQuery;
	}
	
	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
	}

}
