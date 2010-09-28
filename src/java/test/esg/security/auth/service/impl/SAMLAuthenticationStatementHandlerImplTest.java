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

import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.auth.service.impl.SAMLAuthenticationStatementHandlerImpl;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLTestParameters;
import esg.security.common.SAMLUnknownPrincipalException;


/**
 * Test class for {@link SAMLAttributesServiceImpl}.
 */
public class SAMLAuthenticationStatementHandlerImplTest {
	
	private SAMLAuthenticationStatementHandlerImpl samlAuthenticationStatementHandler;
	private SAMLBuilder builder;
	
	protected final static Log LOG = LogFactory.getLog(SAMLAuthenticationStatementHandlerImplTest.class);
	
	@Before
	public void beforeSetup() throws ConfigurationException, SAMLUnknownPrincipalException {
				
		// SAML object builder
		builder = SAMLBuilder.getInstance();
		
		// instantiate a new SAMLAttributesService
		samlAuthenticationStatementHandler = new SAMLAuthenticationStatementHandlerImpl();
		samlAuthenticationStatementHandler.setIncludeFlag(false);
		
	}
	
	/**
	 * Tests construction of a SAML Authentication statement for a given openid identity.
	 * @throws Exception
	 */
	@Test
	public void testBuildAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// execute service invocation
			final Assertion assertion = samlAuthenticationStatementHandler.buildAuthenticationStatement(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER);

			// compare to expected test XML
			final Element assertionElement = builder.marshall(assertion);
			final String xml = XMLHelper.prettyPrintXML((Node)assertionElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
			
		}
		
	}
	
	/**
	 * Tests deserialization of the identity contained in a SAML Authentication Statement.
	 * @throws Exception
	 */
	@Test
	public void testParseAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final InputStream inputStream = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE).getInputStream();
	        final Element element = builder.parse(inputStream);
	        final Assertion assertion = (Assertion)builder.unmarshall(element);
	        
	        // parse SAML assertion
	        final String identity = samlAuthenticationStatementHandler.parseAuthenticationStatement(assertion);
	        Assert.assertEquals("Wrong identity extrected", SAMLTestParameters.IDENTIFIER, identity);
		}
		
	}
	
}
