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
package esg.saml.attr.service.impl;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.saml.attr.service.api.SAMLAttributes;
import esg.saml.common.SAMLBuilder;
import esg.saml.common.SAMLParameters;
import esg.saml.common.SAMLTestParameters;
import esg.saml.common.SAMLUnknownPrincipalException;
import eske.utils.xml.XmlChecker;


/**
 * Test class for {@link SAMLAttributeStatementHandlerImpl}.
 */
public class SAMLAttributeStatementHandlerImplTest {
	
	private SAMLAttributeStatementHandlerImpl samlAttributeStatementHandler;
	private SAMLBuilder builder;
	
	private SAMLAttributes testAttributes;
	private List<Attribute> requestAttributes;
		
	protected final static Log LOG = LogFactory.getLog(SAMLAttributeStatementHandlerImplTest.class);
	
	@Before
	public void beforeSetup() throws ConfigurationException, SAMLUnknownPrincipalException {
				
		// SAML object builder
		builder = SAMLBuilder.getInstance();
		
		// instantiate a new SAMLAttributesService
		samlAttributeStatementHandler = new SAMLAttributeStatementHandlerImpl();
		samlAttributeStatementHandler.setIncludeFlag(false);
		
		final SAMLAttributeFactoryTrivialImpl samlAttributesFactory = new SAMLAttributeFactoryTrivialImpl();
		samlAttributesFactory.setIssuer(SAMLTestParameters.ISSUER);
		testAttributes = samlAttributesFactory.newInstance(SAMLTestParameters.IDENTIFIER);
				
		if (SAMLBuilder.isInitailized()) {
			requestAttributes = new ArrayList<Attribute>();
			requestAttributes.add( builder.getAttribute(SAMLParameters.FIRST_NAME, SAMLParameters.FIRST_NAME_FRIENDLY, null) );
			requestAttributes.add( builder.getAttribute(SAMLParameters.LAST_NAME, SAMLParameters.LAST_NAME_FRIENDLY, null) );
			requestAttributes.add( builder.getAttribute(SAMLParameters.EMAIL_ADDRESS, SAMLParameters.EMAIL_ADDRESS_FRIENDLY, null) );
			requestAttributes.add( builder.getAttribute(SAMLParameters.GROUP_ROLE, SAMLParameters.GROUP_ROLE_FRIENDLY, null) );		
		}
		
	}
	
	
	/**
	 * Tests serialization of the attributes for a test user into a SAML Attribute Statement.
	 * @throws Exception
	 */
	@Test
	public void testBuildAttributeStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// execute service invocation
			final Assertion assertion = samlAttributeStatementHandler.buildAttributeStatement(testAttributes, requestAttributes);
	
			// compare to expected test XML
			final Element assertionElement = builder.marshall(assertion);
			final String xml = XMLHelper.prettyPrintXML((Node)assertionElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTES_FILE);
		} 
		
	}
	
	/**
	 * Tests that only requested attributes are included into attribute statement.
	 * @throws Exception
	 */
	@Test
	public void testBuildAttributeStatementWithPartialAttributes() throws Exception {
				
		if (SAMLBuilder.isInitailized()) {
			
			// re-initialize the requested attributes
			requestAttributes = new ArrayList<Attribute>();
			requestAttributes.add( builder.getAttribute(SAMLParameters.FIRST_NAME, SAMLParameters.FIRST_NAME_FRIENDLY, null) );
			requestAttributes.add( builder.getAttribute(SAMLParameters.LAST_NAME, SAMLParameters.LAST_NAME_FRIENDLY, null) );
			
			// execute service invocation
			final Assertion assertion = samlAttributeStatementHandler.buildAttributeStatement(testAttributes, requestAttributes);
	
			// compare to expected test XML
			final Element assertionElement = builder.marshall(assertion);
			final String xml = XMLHelper.prettyPrintXML((Node)assertionElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTES_FILE_PARTIAL);
		} 
		
	}
	
	/**
	 * Tests deserialization of the attributes for a test user from a SAML Attribute Statement.
	 */
	@Test
	public void testParseAttributeStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			// retrieve test XML
	        final InputStream inputStream = new ClassPathResource(SAMLTestParameters.ATTRIBUTES_FILE).getInputStream();
	        final Element element = builder.parse(inputStream);
	        final Assertion assertion = (Assertion)builder.unmarshall(element);
	       
	        // execute service invocation
	        final SAMLAttributes samlAttributes = samlAttributeStatementHandler.parseAttributeStatement(assertion);
	   
	        // compare to expected user attributes
	        Assert.assertEquals("Wrong user first name", testAttributes.getFirstName(), samlAttributes.getFirstName() );
	        Assert.assertEquals("Wrong user last name", testAttributes.getLastName(), samlAttributes.getLastName() );
	        Assert.assertEquals("Wrong user email address", testAttributes.getEmail(), samlAttributes.getEmail() );
	        
	        Assert.assertEquals("Number of attributes does not match", testAttributes.getAttributes().size(), samlAttributes.getAttributes().size());
	        for (final String attribute : testAttributes.getAttributes()) {
	        	 Assert.assertTrue("Missing attribute detected:"+attribute, samlAttributes.getAttributes().contains(attribute));
	        }
		}
		
	}
	
	/**
	 * Tests parsing of a SAML attribute statement from BADC
	 * @throws Exception
	 */
	@Test
	public void testParseAttributeStatementBADC() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// retrieve test XML
	        final InputStream inputStream = new ClassPathResource(SAMLTestParameters.ATTRIBUTES_FILE_BADC).getInputStream();
	        final Element element = builder.parse(inputStream);
	        final Assertion assertion = (Assertion)builder.unmarshall(element);
	       
	        // execute service invocation
	        final SAMLAttributes samlAttributes = samlAttributeStatementHandler.parseAttributeStatement(assertion);
	   
	        // compare to expected user attributes
	        Assert.assertEquals("Wrong user first name", "Philip", samlAttributes.getFirstName() );
	        Assert.assertEquals("Wrong user last name", "Kershaw", samlAttributes.getLastName() );
	        Assert.assertEquals("Wrong user email address", "p.j.k@somewhere", samlAttributes.getEmail() );
	        
	        Assert.assertEquals("Number of attributes does not match", 6, samlAttributes.getAttributes().size());
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:admin"));
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:rapid"));
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:coapec"));
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:midas"));
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:quest"));
	        Assert.assertTrue(samlAttributes.getAttributes().contains("urn:badc:security:authz:1.0:attr:staff"));
		}

	}
	
}
