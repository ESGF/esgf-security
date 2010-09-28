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
package esg.security.authz.service.impl;

import java.util.List;
import java.util.Vector;

import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.Response;

import esg.security.authz.service.api.SAMLAuthorizationFactory;
import esg.security.authz.service.api.SAMLAuthorizationQueryResponseBuilder;
import esg.security.authz.service.api.SAMLAuthorizations;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Standard implementation of {@link SAMLAuthorizationQueryResponseBuilder}.
 * This class builds the outer SAML response element,
 * while delegating the task of building the embedded assertion to the {@link SAMLAuthorizationStatementHandlerImpl} class.
 * The authorization decision is performed by the particular implementation of {@link SAMLAuthorizationFactory}.
 */
class SAMLAuthorizationQueryResponseBuilderImpl implements SAMLAuthorizationQueryResponseBuilder {
			
	/**
	 * Factory used to create {@link SAMLAuthorizations} objects that are then encoded.
	 */
	private final SAMLAuthorizationFactory samlAuthorizationsFactory;
	
	/**
	 * Utility class to help build SAML objects.
	 */
	private final SAMLBuilder builder;
	
	/**
	 * Collaborator handler responsible for building the SAML AttributeStatement Assertion following an AttributeQuery.
	 */
	private final SAMLAuthorizationStatementHandlerImpl samlAuthorizationStatementHandler;
        
    /**
     * Flag to disable inclusion of ID or IssueInstant within serialized output (to facilitate testing).
     */
    private boolean includeFlag = true;

    SAMLAuthorizationQueryResponseBuilderImpl(final SAMLAuthorizationFactory samlAuthorizationsFactory) {
    	
    	this.samlAuthorizationsFactory = samlAuthorizationsFactory;    	
    	this.builder = SAMLBuilder.getInstance();
    	this.samlAuthorizationStatementHandler = new SAMLAuthorizationStatementHandlerImpl();
    	
    }
	
	/**
	 * {@inheritDoc}
	 */
	public Response buildAuthorizationQueryResponse(final AuthzDecisionQuery authzDecisionQuery) {
		
		final String requestID = authzDecisionQuery.getID();
		final String openid = authzDecisionQuery.getSubject().getNameID().getValue();
		final String resource = authzDecisionQuery.getResource();
		final List<Action> actions = authzDecisionQuery.getActions();
		
		// <?xml version="1.0" encoding="UTF-8"?>
		// 		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="9566201b-63ad-4f14-b6c0-6cf6b35a90e0" IssueInstant="2009-07-28T23:07:00.081Z" Version="2.0"/>
		final Response response = builder.getResponse(requestID, includeFlag);
		
        // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
		response.setIssuer( builder.getIssuer( samlAuthorizationsFactory.getIssuer()) );
		
		try {
			
			final Vector<String> _actions = new Vector<String>();
			for (final Action action : actions) {
				_actions.add(action.getAction());
			}
			final SAMLAuthorizations samlAuthorizations = samlAuthorizationsFactory.newInstance(openid, resource, _actions);
			
			final Assertion assertion = samlAuthorizationStatementHandler.buildAuthzDecisionStatement(samlAuthorizations);

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
		this.samlAuthorizationStatementHandler.setIncludeFlag(includeFlag);
	}

}
