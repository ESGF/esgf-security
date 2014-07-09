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
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLParameters;
import esg.security.common.SAMLTestParameters;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.xml.Serializer;
import esg.security.utils.xml.XmlChecker;


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
			requestAttributes.add( builder.getAttribute(SAMLTestParameters.TEST_ATTRIBUTE_NAME, null, null) );		
			requestAttributes.add( builder.getAttribute(SAMLTestParameters.TEST_GROUPROLE_ATTRIBUTE_NAME, null, null) );
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
			final String xml = Serializer.DOMtoString((Node)assertionElement);
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
			final String xml = Serializer.DOMtoString((Node)assertionElement);
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTES_FILE_PARTIAL);
		} 
		
	}
	
	/**
     * Tests retrieval of all attributes when none is explicitly specified.
     * @throws Exception
     */
    @Test
    public void testBuildAttributeStatementWithAllAttributes() throws Exception {
                
        if (SAMLBuilder.isInitailized()) {
            
            // re-initialize the requested attributes
            requestAttributes = new ArrayList<Attribute>();
            
            // execute service invocation
            final Assertion assertion = samlAttributeStatementHandler.buildAttributeStatement(testAttributes, requestAttributes);
    
            // compare to expected test XML
            final Element assertionElement = builder.marshall(assertion);
            final String xml = Serializer.DOMtoString((Node)assertionElement);
            if (LOG.isDebugEnabled()) LOG.debug(xml);
            XmlChecker.compare(xml, SAMLTestParameters.ATTRIBUTES_FILE_FULL);
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
	        
	        // compare to expected simple attributes
	        Assert.assertEquals("Number of string attributes keys does not match", testAttributes.getAttributes().size(), samlAttributes.getGroupAndRoles().size());
	        Assert.assertEquals("Number of string attributes values does not match", testAttributes.getAttributes().get(SAMLTestParameters.TEST_ATTRIBUTE_NAME).size(), samlAttributes.getAttributes().get(SAMLTestParameters.TEST_ATTRIBUTE_NAME).size());
	        Assert.assertTrue("Missing string attribute from parsing attribute statement", samlAttributes.getAttributes().get(SAMLTestParameters.TEST_ATTRIBUTE_NAME).contains("test_attribute_value1") );
	        Assert.assertTrue("Missing string attribute from parsing attribute statement", samlAttributes.getAttributes().get(SAMLTestParameters.TEST_ATTRIBUTE_NAME).contains("test_attribute_value2") );
	        
	        // compare to expected (group,role) attributes
	        Assert.assertEquals("Number of (group,role) attributes keys does not match", testAttributes.getGroupAndRoles().size(), samlAttributes.getGroupAndRoles().size());
	        Assert.assertEquals("Number of (group,role) attributes values does not match", testAttributes.getGroupAndRoles().get(SAMLTestParameters.TEST_GROUPROLE_ATTRIBUTE_NAME).size(), samlAttributes.getGroupAndRoles().get(SAMLTestParameters.TEST_GROUPROLE_ATTRIBUTE_NAME).size());
	        Assert.assertTrue("Missing (group,role) attribute from parsing attribute statement", samlAttributes.getGroupAndRoles().get(SAMLTestParameters.TEST_GROUPROLE_ATTRIBUTE_NAME).contains(new GroupRoleImpl("all_users","admin")) );
	        Assert.assertTrue("Missing (group,role) attribute from parsing attribute statement", samlAttributes.getGroupAndRoles().get(SAMLTestParameters.TEST_GROUPROLE_ATTRIBUTE_NAME).contains(new GroupRoleImpl("super_users","standard")) );
		}
		
	}
	
	/**
	 * Tests parsing of a SAML attribute statement from BADC
	 * @throws Exception
	 */
	@Test
	public void testParseAttributeStatementBADC() throws Exception {
		
		final String badc_attribute_name = "urn:badc:security:authz:1.0:attr";
		
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
	        
	        Assert.assertEquals("Number of attribute names does not match", 1, samlAttributes.getAttributes().size());
	        Assert.assertTrue(samlAttributes.getAttributes().containsKey(badc_attribute_name));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:admin"));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:rapid"));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:coapec"));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:midas"));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:quest"));
	        Assert.assertTrue(samlAttributes.getAttributes().get(badc_attribute_name).contains("urn:badc:security:authz:1.0:attr:staff"));
		}

	}
	
}
