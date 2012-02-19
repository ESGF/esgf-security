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
package esg.security.attr.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.authz.service.impl.SAMLAuthorizationFactoryTrivialImpl;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLParameters;
import esg.security.common.SAMLTestParameters;
import esg.security.utils.xml.XmlChecker;

/**
 * Test class for {@link SAMLAttributeQueryResponseBuilderImpl}.
 */
public class SAMLAttributeQueryRequestBuilderImplTest {
	
	private SAMLAttributeQueryRequestBuilderImpl samlAttributeQueryRequestBuilder;
	private SAMLBuilder builder;
		
	protected final static Log LOG = LogFactory.getLog(SAMLAttributeQueryRequestBuilderImplTest.class);
		
	@Before
	public void beforeSetup() throws ConfigurationException {
		
		builder = SAMLBuilder.getInstance();
		
		final SAMLAttributeFactoryTrivialImpl samlAttributesFactory = new SAMLAttributeFactoryTrivialImpl();
		samlAttributesFactory.setIssuer(SAMLTestParameters.ISSUER);
		
		final SAMLAuthorizationFactoryTrivialImpl samlAuthorizationsFactory = new SAMLAuthorizationFactoryTrivialImpl();
		samlAuthorizationsFactory.setIssuer(SAMLTestParameters.ISSUER);
		
		samlAttributeQueryRequestBuilder = new SAMLAttributeQueryRequestBuilderImpl();
		samlAttributeQueryRequestBuilder.setIncludeFlag(false);
		
	}
		
	/**
	 * Tests building a SAML AttributeQuery for a given OpenID.
	 * @throws Exception
	 */
	@Test
	public void testBuildEmptyAttributeQueryRequest() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			final AttributeQuery attributeQuery 
				= samlAttributeQueryRequestBuilder.buildAttributeQueryRequest(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER, new ArrayList<Attribute>());
			final Element attributeQueryRequestElement = builder.marshall(attributeQuery);
			final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryRequestElement);
			if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTE_REQUEST_EMPTY);
		}
		
	}
	
	/**
	 * Tests building a SAML AttributeQuery for a given OpenID.
	 * @throws Exception
	 */
	@Test
	public void testBuildAttributeQueryRequestWithAttributes() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// requested attributes
			final List<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add( builder.getAttribute(SAMLParameters.FIRST_NAME, null, null) );
			attributes.add( builder.getAttribute(SAMLParameters.LAST_NAME, null, null) );
			attributes.add( builder.getAttribute(SAMLParameters.EMAIL_ADDRESS, null, null) );
			attributes.add( builder.getAttribute(SAMLTestParameters.TEST_ATTRIBUTE_NAME, null, null) );
			
			final AttributeQuery attributeQuery 
				= samlAttributeQueryRequestBuilder.buildAttributeQueryRequest(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER, attributes);
			final Element attributeQueryRequestElement = builder.marshall(attributeQuery);
			final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryRequestElement);
			if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTE_REQUEST_WITH_ATTRIBUTES);
	        
		}
		
	}
	
}
