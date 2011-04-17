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

import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.attr.service.impl.SAMLAttributeFactoryTrivialImpl;
import esg.security.attr.service.impl.SAMLAttributeQueryResponseBuilderImpl;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLTestParameters;
import eske.utils.xml.XmlChecker;

/**
 * Test class for {@link SAMLAuthorizationQueryRequestBuilderImpl}.
 */
public class SAMLAttributeQueryResponseBuilderImplTest {
	
	private SAMLAttributeQueryResponseBuilderImpl samlAttribuuteQueryResponseBuilder;
	private SAMLBuilder builder;
				
	protected final static Log LOG = LogFactory.getLog(SAMLAttributeQueryResponseBuilderImplTest.class);
		
	@Before
	public void beforeSetup() throws ConfigurationException {
		
		builder = SAMLBuilder.getInstance();
		
		final SAMLAttributeFactoryTrivialImpl samlAttributesFactory = new SAMLAttributeFactoryTrivialImpl();
		samlAttributesFactory.setIssuer(SAMLTestParameters.ISSUER);
				
		samlAttribuuteQueryResponseBuilder = new SAMLAttributeQueryResponseBuilderImpl(samlAttributesFactory);
		samlAttribuuteQueryResponseBuilder.setIncludeFlag(false);
		
	}
	
	/**
	 * Tests building a SAML Response for a valid OpenID and all attributes.
	 */
	@Test
	public void testBuildAttributeQueryResponseSuccess() throws Exception {

		if (SAMLBuilder.isInitailized()) {
			final InputStream inputStream = new ClassPathResource( SAMLTestParameters.ATTRIBUTE_REQUEST_EMPTY).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AttributeQuery attributeQueryRequest = (AttributeQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAttribuuteQueryResponseBuilder.buildAttributeQueryResponse(attributeQueryRequest);
	        final Element attributeQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml,  SAMLTestParameters.ATTRIBUTE_RESPONSE_SUCCESS);
		}

	}
	
	/**
	 * Tests building a SAML Response for a valid OpenID and specific attributes.
	 */
	@Test
	public void testBuildAttributeQueryResponseWithAttributesSuccess() throws Exception {

		if (SAMLBuilder.isInitailized()) {
			final InputStream inputStream = new ClassPathResource( SAMLTestParameters.ATTRIBUTE_REQUEST_WITH_ATTRIBUTES).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AttributeQuery attributeQueryRequest = (AttributeQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAttribuuteQueryResponseBuilder.buildAttributeQueryResponse(attributeQueryRequest);
	        final Element attributeQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml,  SAMLTestParameters.ATTRIBUTE_RESPONSE_WITH_ATTRIBUTES_SUCCESS);
		}

	}
	
	/**
	 * Tests building a SAML Response with partial attributes.
	 */
	@Test
	public void testBuildAttributeQueryPartialResponse() throws Exception {

		if (SAMLBuilder.isInitailized()) {
			final InputStream inputStream = new ClassPathResource(SAMLTestParameters.ATTRIBUTE_PARTIAL_REQUEST).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AttributeQuery attributeQueryRequest = (AttributeQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAttribuuteQueryResponseBuilder.buildAttributeQueryResponse(attributeQueryRequest);
	        final Element attributeQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTE_PARTIAL_RESPONSE);
		}

	}
	
	/**
	 * Tests building a SAML Response for an invalid OpenID.
	 */
	@Test
	public void testBuildAttributeQueryResponseFailure() throws Exception {

		if (SAMLBuilder.isInitailized()) {
						
			final InputStream inputStream = new ClassPathResource( SAMLTestParameters.ATTRIBUTE_INVALID_REQUEST).getInputStream();
	        final BasicParserPool parser = new BasicParserPool();
	        final Document document = parser.parse(inputStream);
	        final AttributeQuery attributeQueryRequest = (AttributeQuery)builder.unmarshall(document.getDocumentElement());
	        
	        final Response response = samlAttribuuteQueryResponseBuilder.buildAttributeQueryResponse(attributeQueryRequest);
	        final Element attributeQueryResponseElement = builder.marshall(response);
	        final String xml = XMLHelper.prettyPrintXML((Node)attributeQueryResponseElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml,  SAMLTestParameters.ATTRIBUTE_RESPONSE_FAILURE);
		}

	}
	
}
