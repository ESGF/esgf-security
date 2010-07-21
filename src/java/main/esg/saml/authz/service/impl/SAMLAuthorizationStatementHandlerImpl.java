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

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.ActionBuilder;

import esg.saml.authz.service.api.SAMLAuthorization;
import esg.saml.authz.service.api.SAMLAuthorizationStatementHandler;
import esg.saml.authz.service.api.SAMLAuthorizations;
import esg.saml.common.SAMLBuilder;
import esg.saml.common.SAMLParameters;

/**
 * Standard implementation of {@link SAMLAuthorizationStatementHandler}.
 */
class SAMLAuthorizationStatementHandlerImpl implements SAMLAuthorizationStatementHandler {
		    
	/**
	 * Utility to help build SAML objects.
	 */
    private final SAMLBuilder builder;
    
    /**
     * Flag to disable ID or IssueInstant within serialized output.
     */
    private boolean includeFlag = true;
 
	
    /**
     * Constructor is not visible outside package.
     */
	SAMLAuthorizationStatementHandlerImpl() {
		this.builder = SAMLBuilder.getInstance();
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public Assertion buildAuthzDecisionStatement(final SAMLAuthorizations samlAuthorizations) {
		
		// <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
	    final Assertion assertion = builder.getAssertion(includeFlag);
	    
	    // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
	    assertion.setIssuer( builder.getIssuer(samlAuthorizations.getIssuer()) );
	    
		// 	<saml:Subject>
		// 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
		// 	</saml:Subject>
	    assertion.setSubject( builder.getSubject(samlAuthorizations.getIdentity()) );
	    
	    // <saml:Conditions NotBefore="2009-08-04T11:16:53.632Z" NotOnOrAfter="2009-08-05T11:16:53.632Z"/>
	    if (includeFlag) {
		    final DateTime notBefore = new DateTime();
		    final DateTime notOnOrAfter = notBefore.plusSeconds(SAMLParameters.ASSERTION_LIFETIME_IN_SECONDS);
		    assertion.setConditions( builder.getConditions(notBefore, notOnOrAfter) );
	    }
	    
	    final ActionBuilder actionBuilder = new ActionBuilder();
        	
        for (final SAMLAuthorization authz : samlAuthorizations.getAuthorizations()) {
        	
    	    // <saml:AuthzDecisionStatement Decision="Permit" Resource="/PATH/TO/FILE">
    	    final AuthzDecisionStatement authzDecisionStatement = builder.getAuthzDecisionStatement();
    	    	      
    	    authzDecisionStatement.setResource(authz.getResource());
    	    if (authz.getDecision().equalsIgnoreCase(DecisionTypeEnumeration.PERMIT.toString())) {
    	    	authzDecisionStatement.setDecision(DecisionTypeEnumeration.PERMIT);
    	    } else if (authz.getDecision().equalsIgnoreCase(DecisionTypeEnumeration.DENY.toString())) {
    	    	authzDecisionStatement.setDecision(DecisionTypeEnumeration.DENY);
    	    } else {
    	    	authzDecisionStatement.setDecision(DecisionTypeEnumeration.INDETERMINATE);
    	    }
	        
    	    //<saml:Action>read</saml:Action>
    	    for (final String _action : authz.getActions()) {
    	    	final Action action = actionBuilder.buildObject();
    	    	//action.setNamespace(SAMLParameters.AC_ACTION);
    	    	action.setAction(_action);
    	    	authzDecisionStatement.getActions().add(action);
    	    }
    	    assertion.getAuthzDecisionStatements().add(authzDecisionStatement);
	    
        }
        
	    return assertion;
	}
	
	/**
	 * {@inheritDoc}
	 * 
	 */
	public SAMLAuthorizations parseAuthzDecisionStatement(final Assertion assertion) {
		
		final SAMLAuthorizations samlAuthorizations = new SAMLAuthorizationsImpl();

		// extract authorization authority
		final Issuer issuer = assertion.getIssuer();
		if (issuer!=null) samlAuthorizations.setIssuer(issuer.getValue());
		
		final String openid = assertion.getSubject().getNameID().getValue();
		samlAuthorizations.setIdentity(openid);

		// loop over all SAML authzDecisionStatements in assertion
		for (final AuthzDecisionStatement authzStatement : assertion.getAuthzDecisionStatements()) {

			final SAMLAuthorization samlAuthorization = new SAMLAuthorizationImpl();

			// add resource
			samlAuthorization.setResource(authzStatement.getResource());

			// add decision
			if (authzStatement.getDecision() == DecisionTypeEnumeration.PERMIT) {
				samlAuthorization.setDecision(DecisionTypeEnumeration.PERMIT.toString());
			} else if (authzStatement.getDecision() == DecisionTypeEnumeration.DENY) {
				samlAuthorization.setDecision(DecisionTypeEnumeration.DENY.toString());			
			} else {
				samlAuthorization.setDecision(DecisionTypeEnumeration.INDETERMINATE.toString());
			}

			// add all actions
			for (final Action action : authzStatement.getActions()) {
				samlAuthorization.getActions().add(action.getAction());
			}
			
			samlAuthorizations.getAuthorizations().add(samlAuthorization);
		}
		
		return samlAuthorizations;
		
	}

	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
	}

	
}
