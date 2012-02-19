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

import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Vector;

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

import esg.security.authz.service.api.SAMLAuthorizations;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLTestParameters;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.xml.XmlChecker;

/**
 * Test class for {@link SAMLAuthorizationStatementHandlerImpl}.
 */
public class SAMLAuthorizationStatementHandlerImplTest {
	
	private SAMLAuthorizationStatementHandlerImpl samlAuthorizationStatementHandler;
	private SAMLBuilder builder;
	
	private SAMLAuthorizations testAuthorizations;
	
	protected final static Log LOG = LogFactory.getLog(SAMLAuthorizationStatementHandlerImplTest.class);
	
    private static String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
    private static SimpleDateFormat df = new SimpleDateFormat(DATE_FORMAT);
    
    private final String NOT_BEFORE = "2012-02-02T16:39:58.047+0000";
    private final String NOT_ON_OR_AFTER = "2012-02-03T16:39:58.047+0000";

	
	@Before
	public void beforeSetup() throws ConfigurationException, SAMLUnknownPrincipalException, ParseException {
				
		// SAML object builder
		builder = SAMLBuilder.getInstance();
		
		// instantiate a new SAMLAttributesService
		samlAuthorizationStatementHandler = new SAMLAuthorizationStatementHandlerImpl();
		samlAuthorizationStatementHandler.setIncludeFlag(false);
				
		final SAMLAuthorizationFactoryTrivialImpl samlAuthorizationsFactory = new SAMLAuthorizationFactoryTrivialImpl();
		samlAuthorizationsFactory.setIssuer(SAMLTestParameters.ISSUER);
		final Vector<String> actions = new Vector<String>();
		actions.add(SAMLTestParameters.TEST_ACTION);
		testAuthorizations = samlAuthorizationsFactory.newInstance(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.TEST_RESOURCE_PATH, actions);
		testAuthorizations.setNotBefore(df.parse(NOT_BEFORE));
		testAuthorizations.setNotOnOrAfter(df.parse(NOT_ON_OR_AFTER));
		
	}
	
	/**
	 * Tests construction of a SAML AuthzDecisionStatement for a test user, resource and action.
	 * @throws Exception
	 */
	@Test
	public void testBuildAuthzDecisionStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// execute service invocation
			final Assertion assertion = samlAuthorizationStatementHandler.buildAuthzDecisionStatement(testAuthorizations);
			
			// compare to expected test XML
			final Element assertionElement = builder.marshall(assertion);
			final String xml = XMLHelper.prettyPrintXML((Node)assertionElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.AUTHZ_DECISION_STMT_FILE);	
		}
		
	}

	/**
	 * Tests deserialization of the authorizations for a test user from a SAML AuthzDecisionStatement.
	 */
	@Test
	public void testParseAuthzDecisionStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// retrieve test XML
	        final InputStream inputStream = new ClassPathResource(
	        		SAMLTestParameters.AUTHZ_DECISION_STMT_FILE).getInputStream();
	        final Element element = builder.parse(inputStream);
	        final Assertion assertion = (Assertion)builder.unmarshall(element);
	       
	        // execute service invocation
	        final SAMLAuthorizations samlAuthorizations = samlAuthorizationStatementHandler.parseAuthzDecisionStatement(assertion);
	        
	        // compare to expected result
	        Assert.assertEquals("Invalid authorization identity",SAMLTestParameters.IDENTIFIER, samlAuthorizations.getIdentity());
	        Assert.assertEquals("Number of authzDecisionStatements does not match", testAuthorizations.getAuthorizations().size(),
	        		samlAuthorizations.getAuthorizations().size());
	        Assert.assertEquals("Wrong resource name", samlAuthorizations.getAuthorizations().get(0).getResource(),
	        		testAuthorizations.getAuthorizations().get(0).getResource());
	        Assert.assertEquals("Wrong decision name", samlAuthorizations.getAuthorizations().get(0).getDecision(),
	        		testAuthorizations.getAuthorizations().get(0).getDecision());
	        Assert.assertEquals("Wrong action type", samlAuthorizations.getAuthorizations().get(0).getActions().get(0),
	        		testAuthorizations.getAuthorizations().get(0).getActions().get(0));
	        Assert.assertEquals(df.parse(NOT_BEFORE), testAuthorizations.getNotBefore());
	        Assert.assertEquals(df.parse(NOT_ON_OR_AFTER), testAuthorizations.getNotOnOrAfter());
	        	        
		}
	
	}
	
}
