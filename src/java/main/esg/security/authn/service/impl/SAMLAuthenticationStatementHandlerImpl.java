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
package esg.security.authn.service.impl;

import java.util.Date;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Subject;

import esg.security.authn.service.api.SAMLAuthenticationStatementHandler;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLParameters;

/**
 * Standard implementation of {@link SAMLAuthenticationStatementHandler}.
 */
class SAMLAuthenticationStatementHandlerImpl implements SAMLAuthenticationStatementHandler {
		    
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
	SAMLAuthenticationStatementHandlerImpl() {
		this.builder = SAMLBuilder.getInstance();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public Assertion buildAuthenticationStatement(final String openid, final String issuer) {
		
		// <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
	    final Assertion assertion = builder.getAssertion(includeFlag);
	    
	    // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
	    assertion.setIssuer( builder.getIssuer(issuer) );
	    
		// 	<saml:Subject>
		// 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
		// 	</saml:Subject>
	    assertion.setSubject( builder.getSubject(openid) );
	    
	    // <saml:Conditions NotBefore="2009-08-04T11:16:53.632Z" NotOnOrAfter="2009-08-05T11:16:53.632Z"/>
	    DateTime now = null;
	    if (includeFlag) {
	    	now = new DateTime();
		    final DateTime notOnOrAfter = now.plusSeconds(SAMLParameters.ASSERTION_LIFETIME_IN_SECONDS);
		    assertion.setConditions( builder.getConditions(now, notOnOrAfter) );
	    }
	    
	    // <saml:AuthnStatement AuthnInstant="2009-12-22T11:58:23.786Z">
	    //    <saml:AuthnContext>
	    //       <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>
	    //    </saml:AuthnContext>
	    // </saml:AuthnStatement>
	    final AuthnStatement authnStatment = builder.getAuthnStatement(now);
	    assertion.getAuthnStatements().add(authnStatment);
	    
	    return assertion;
		
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String parseAuthenticationStatement(final Assertion assertion) {
		
		final Subject subject = assertion.getSubject();
		if (subject!=null) {
			return subject.getNameID().getValue();
		} else {
			return null;
		}
		
	}
	
    /**
     * {@inheritDoc}
     */
    public Date getValidTo(final Assertion assertion) {
        Conditions conditions = assertion.getConditions();
        if (conditions!=null) {
            return conditions.getNotOnOrAfter().toDate();
        } else {
            return null;
        }
    }
    /**
     * {@inheritDoc}
     */
    public Date getValidFrom(final Assertion assertion) {
        Conditions conditions = assertion.getConditions();
        if (conditions!=null) {
            return conditions.getNotBefore().toDate();
        } else {
            return null;
        }
    }
	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
	}

	
}
