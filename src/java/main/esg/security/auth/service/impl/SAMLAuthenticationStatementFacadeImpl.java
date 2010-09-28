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
package esg.security.auth.service.impl;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.util.Assert;
import org.w3c.dom.Element;

import esg.security.auth.service.api.SAMLAuthenticationStatementFacade;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLInvalidStatementException;
import esg.security.common.SecurityManager;
import esg.security.utils.xml.Serializer;

/**
 * Implementation of {@link SAMLAuthenticationStatementFacade} that stores the optional signing and trusted credentials.
 *
 */
public class SAMLAuthenticationStatementFacadeImpl implements SAMLAuthenticationStatementFacade {
	
	private final SAMLBuilder builder;
	private SAMLAuthenticationStatementHandlerImpl samlAuthenticationStatementHandler;
	
	/**
	 * Optional credential to sign SAML statements.
	 */
	private Credential signingCredential;
	
	/**
	 * Optional set of trusted credentials to validate signed SAML statements.
	 */
	private Map<String,Credential> trustedCredentials = new HashMap<String, Credential>();
	
	protected final static Log LOG = LogFactory.getLog(SAMLAuthenticationStatementFacadeImpl.class);
	
	/**
	 * Minimal constructor.
	 */
	public SAMLAuthenticationStatementFacadeImpl() {
		
		this.builder = SAMLBuilder.getInstance();
		this.samlAuthenticationStatementHandler = new SAMLAuthenticationStatementHandlerImpl();
		
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String buildAuthenticationStatement(final String identity, final String issuer, final boolean signit) throws Exception {
		
		// build statement
		final Assertion assertion = samlAuthenticationStatementHandler.buildAuthenticationStatement(identity, issuer);
		
		// optionally sign statement
		if (signit) {
			Assert.notNull(signingCredential);
			final Element assertionElement = builder.marshallAndSign(assertion, signingCredential);
			return Serializer.DOMtoString(assertionElement);
		} else {
			final Element assertionElement = builder.marshall(assertion);
			return Serializer.DOMtoString(assertionElement);
		}

	}

	/**
	 * {@inheritDoc}
	 */
	public String buildSignedAuthenticationStatement(final String identity) throws Exception {
		
		return this.buildAuthenticationStatement(identity, signingCredential.getEntityId(), true);
		
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String parseAuthenticationStatement(final String xml, final boolean validate) throws SAMLInvalidStatementException {
		
		try {
			
			final Element assertionElement = builder.parse(xml);
	        final Assertion assertion = (Assertion)builder.unmarshall(assertionElement); 
	        if (validate) this.validateAssertion(assertion);        
	        return samlAuthenticationStatementHandler.parseAuthenticationStatement(assertion);
        
		} catch(XMLParserException e) {
			throw new SAMLInvalidStatementException(e);
		} catch(UnmarshallingException e) {
			throw new SAMLInvalidStatementException(e);
		}
		
	}

	/**
	 * {@inheritDoc}
	 */
	public void setSigningCredential(final File keystore, final String keystorePassword, final String keystoreAlias) throws Exception {
		
		signingCredential = SecurityManager.getMyCredential(keystore, keystorePassword, keystoreAlias);
		if (LOG.isDebugEnabled()) LOG.debug("Set signinig credential "+signingCredential.getEntityId());
		
	}

	/**
	 * {@inheritDoc}
	 */
	public void setTrustedCredentials(final File trustore, final String trustorePassword) throws Exception {
		
		trustedCredentials = SecurityManager.getTrustedCredentials(trustore, trustorePassword);
		
	}
	
	/**
	 * Utility method to validate a SAML assertion versus the current trustore.
	 * @param assertion
	 * @throws SAMLInvalidStatementException
	 */
	private void validateAssertion(final Assertion assertion) throws SAMLInvalidStatementException {
			
		try {
			if (!builder.validateSignature(assertion, trustedCredentials)) {
				throw new SAMLInvalidStatementException("SAML statement signature is invalid");
			}
		} catch(SecurityException e) {
			throw new SAMLInvalidStatementException(e);
		}

	}

	/**
	 * Method to disable inclusion of dates in statements for testing.
	 * @param includeFlag
	 */
	void setIncludeFlag(final boolean includeFlag) {
		this.samlAuthenticationStatementHandler.setIncludeFlag(includeFlag);
	}
	
}
