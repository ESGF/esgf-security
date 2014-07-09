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
package esg.security.authz.service.impl;

import java.util.Vector;

import org.opensaml.saml2.core.DecisionTypeEnumeration;

import esg.security.authz.service.api.SAMLAuthorization;
import esg.security.authz.service.api.SAMLAuthorizationFactory;
import esg.security.authz.service.api.SAMLAuthorizations;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Trivial implementation of {@link SAMLAuthorizationFactory} that returns positive authorization
 * for a given user (for all resources and actions), negative authorization otherwise.
 */
public class SAMLAuthorizationFactoryTrivialImpl implements SAMLAuthorizationFactory {

	public SAMLAuthorizationFactoryTrivialImpl() {}
	
	private String issuer;

	public SAMLAuthorizations newInstance(final String identifier, final String resource, final Vector<String> actions) throws SAMLUnknownPrincipalException {
			
		if (identifier.equals("Test Openid")) {
			
			final SAMLAuthorization samlAuthorization = new SAMLAuthorizationImpl();		
			samlAuthorization.setResource(resource);
			samlAuthorization.setActions(actions);
			samlAuthorization.setDecision(DecisionTypeEnumeration.PERMIT.toString());
			
			final SAMLAuthorizations samlAuthorizations = new SAMLAuthorizationsImpl();
			samlAuthorizations.setIdentity(identifier);
			if (issuer!=null) samlAuthorizations.setIssuer(issuer);
			samlAuthorizations.addAuthorization(samlAuthorization);
			
			return samlAuthorizations;
		
		} else {
			throw new SAMLUnknownPrincipalException("Unknown user: "+identifier);
		}
	
	}
	
	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(final String issuer) {
		this.issuer = issuer;
	}

}
