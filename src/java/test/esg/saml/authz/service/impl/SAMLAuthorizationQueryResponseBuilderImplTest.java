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

import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.saml.common.SAMLBuilder;
import esg.saml.common.SAMLTestParameters;
import eske.utils.xml.XmlChecker;

/**
 * Test class for {@link SAMLAuthorizationQueryResponseBuilderImpl}.
 */
public class SAMLAuthorizationQueryResponseBuilderImplTest {
	
	private SAMLAuthorizationQueryResponseBuilderImpl samlAuthorizationQueryResponseBuilder;
	private SAMLBuilder builder;
		
	protected final static Log LOG = LogFactory.getLog(SAMLAuthorizationQueryResponseBuilderImplTest.class);
		
	@Before
	public void beforeSetup() throws ConfigurationException {
		
		builder = SAMLBuilder.getInstance();
			
		final SAMLAuthorizationFactoryTrivialImpl samlAuthorizationsFactory = new SAMLAuthorizationFactoryTrivialImpl();
		samlAuthorizationsFactory.setIssuer(SAMLTestParameters.ISSUER);
		
		samlAuthorizationQueryResponseBuilder = new SAMLAuthorizationQueryResponseBuilderImpl(samlAuthorizationsFactory);
		samlAuthorizationQueryResponseBuilder.setIncludeFlag(false);
		
	}
	
	/**
	 * Tests building a SAML Response for a valid OpenID.
	 */
	@Test
	public void testBuildAuthzDecisionQueryResponseSuccess() throws Exception {

		if (SAMLBuilder.isInitailized()) {
			final InputStream inputStream = new ClassPathResource(SAMLTestParameters.VALID_REQUEST).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AuthzDecisionQuery authzQueryRequest = (AuthzDecisionQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAuthorizationQueryResponseBuilder.buildAuthorizationQueryResponse(authzQueryRequest);
	        final Element authzQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)authzQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.RESPONSE_SUCCESS);
		}
	}
	
	/**
	 * Tests building a SAML Response for an invalid OpenID.
	 */
	@Test
	public void testBuildAuthzDecisionQueryQueryResponseFailure() throws Exception {

		if (SAMLBuilder.isInitailized()) {
						
			final InputStream inputStream = new ClassPathResource(SAMLTestParameters.INVALID_REQUEST).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AuthzDecisionQuery authzQueryRequest = (AuthzDecisionQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAuthorizationQueryResponseBuilder.buildAuthorizationQueryResponse(authzQueryRequest);
	        final Element authzQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)authzQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.RESPONSE_FAILURE);
		}

	}
	
}
