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

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSGroupRole;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import esg.security.attr.service.api.GroupRole;
import esg.security.attr.service.api.SAMLAttributeStatementHandler;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLParameters;

/**
 * Standard implementation of {@link SAMLAttributeStatementHandler}.
 */
class SAMLAttributeStatementHandlerImpl implements SAMLAttributeStatementHandler {
		    
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
	SAMLAttributeStatementHandlerImpl() {
		this.builder = SAMLBuilder.getInstance();
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public Assertion buildAttributeStatement(final SAMLAttributes samlAttributes, final List<Attribute> requestedAttributes) {
				
		// <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
	    final Assertion assertion = builder.getAssertion(includeFlag);
	    
	    // <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
	    assertion.setIssuer( builder.getIssuer(samlAttributes.getIssuer()) );
	    
		// 	<saml:Subject>
		// 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
		// 	</saml:Subject>
	    assertion.setSubject( builder.getSubject(samlAttributes.getOpenid()) );
	    
	    // <saml:Conditions NotBefore="2009-08-04T11:16:53.632Z" NotOnOrAfter="2009-08-05T11:16:53.632Z"/>
	    if (includeFlag) {
		    final DateTime notBefore = new DateTime();
		    final DateTime notOnOrAfter = notBefore.plusSeconds(SAMLParameters.ASSERTION_LIFETIME_IN_SECONDS);
		    assertion.setConditions( builder.getConditions(notBefore, notOnOrAfter) );
	    }
	       
	    // <saml:AttributeStatement>
	    final AttributeStatement attributeStatement = builder.getAttributeStatement();
	    
	    // include all available attributes
	    if (requestedAttributes==null || requestedAttributes.size()==0) {
	    
	    	// add all personal attributes
	    	this.addFirstName(attributeStatement, samlAttributes);
	    	this.addLastName(attributeStatement, samlAttributes);
	    	this.addEmailAddress(attributeStatement, samlAttributes);
	    		    	
	    	// add all string-based attributes
	    	for (final String attName : samlAttributes.getAttributes().keySet()) {
    			this.addAttributes(attributeStatement, samlAttributes, attName);
	    	}
	    	
	    	// add all (group,role) attributes
	    	for (final String attName : samlAttributes.getGroupAndRoles().keySet()) {
    			addGroupAndRoles(attributeStatement, samlAttributes, attName);
	    	}
	    	
	    // include only requested attributes, if available
	    } else {
	    	
	    	for (final Attribute attribute : requestedAttributes) {
	    		final String attName = attribute.getName();
	    		
	    		if (attName.equals(SAMLParameters.FIRST_NAME)) {
	    	    	this.addFirstName(attributeStatement, samlAttributes);
    		
	    		} else if (attName.equals(SAMLParameters.LAST_NAME)) {
	    	    	this.addLastName(attributeStatement, samlAttributes);
	    		
	    		} else if (attName.equals(SAMLParameters.EMAIL_ADDRESS)) {
	    	    	this.addEmailAddress(attributeStatement, samlAttributes);
	    			
	    		} else {
	    			
		    		if (samlAttributes.getAttributes().containsKey(attName)) {
		    			this.addAttributes(attributeStatement, samlAttributes, attName);
		    		} else if (samlAttributes.getGroupAndRoles().containsKey(attName)) {	
		    			this.addGroupAndRoles(attributeStatement, samlAttributes, attName);
		    		}

	    		}
	    	}
	    }
	    	
	    assertion.getAttributeStatements().add(attributeStatement);
	    return assertion;

	}
	

	
	/**
	 * {@inheritDoc}
	 * 
	 */
	public SAMLAttributes parseAttributeStatement(final Assertion assertion) {
				
		// create new (unsaved) User
		final SAMLAttributes samlAttributes = new SAMLAttributesImpl();
		
		// extract attribute authority
		final Issuer issuer = assertion.getIssuer();
		if (issuer!=null) samlAttributes.setIssuer(issuer.getValue());
					
		// loop over all SAML attributes
		final List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
		for (final AttributeStatement attributeStatement : attributeStatements) {
			
			for (final Attribute attribute : attributeStatement.getAttributes()) {
				
				if (attribute.getName().equals(SAMLParameters.FIRST_NAME)) {
					samlAttributes.setFirstName(this.getAttributeValues(attribute).get(0));
					
				} else if (attribute.getName().equals(SAMLParameters.LAST_NAME)) {
					samlAttributes.setLastName(this.getAttributeValues(attribute).get(0));
						
				} else if (attribute.getName().equals(SAMLParameters.EMAIL_ADDRESS)) {
					samlAttributes.setEmail(this.getAttributeValues(attribute).get(0));
					
				} else {
					for (final XMLObject attributeValue : attribute.getAttributeValues()) {
						
						if (attributeValue instanceof XSAny) {
							
							// process complex (group,role) based attribute
							final XSAny xsAny = (XSAny)attributeValue;
							for (final XMLObject xmlObject : xsAny.getUnknownXMLObjects()) {
								final XSGroupRole groupRole = (XSGroupRole)xmlObject;
								final String groupName = groupRole.getGroup();
								final String roleName = groupRole.getRole();
								samlAttributes.addGroupAndRole(attribute.getName(), new GroupRoleImpl(groupName, roleName));
								// FIXME (temporary): tranform GroupRole attribute into (attribute name, attribute type) pair
								samlAttributes.addAttribute(groupName, roleName);
							}
							
						} else {
							
							// process string-based attribute
							final Element element = attributeValue.getDOM();
							final Text text = (Text)element.getFirstChild();
							samlAttributes.addAttribute(attribute.getName(), text.getData().trim());
							
						}
					}
				}
					
			}
			
		}
				
		return samlAttributes;
		
	}
	
	/**
	 * Utility method to add the "first name" personal attribute to a SAML attribute statement.
	 * @param attributeStatement
	 * @param samlAttributes
	 */
	public void addFirstName(final AttributeStatement attributeStatement, final SAMLAttributes samlAttributes) {
        
	    //  <saml:Attribute FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
        //		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Tester</saml:AttributeValue>
        //	</saml:Attribute>
		attributeStatement.getAttributes().add( builder.getAttribute(SAMLParameters.FIRST_NAME, SAMLParameters.FIRST_NAME_FRIENDLY, samlAttributes.getFirstName()) );
	}
	
	/**
	 * Utility method to add the "last name" personal attribute to a SAML attribute statement.
	 * @param attributeStatement
	 * @param samlAttributes
	 */
	public void addLastName(final AttributeStatement attributeStatement, final SAMLAttributes samlAttributes) {
        
	    //  <saml:Attribute FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
        //		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">ValidUser</saml:AttributeValue>
        //	</saml:Attribute>	    			

		attributeStatement.getAttributes().add( builder.getAttribute(SAMLParameters.LAST_NAME, SAMLParameters.LAST_NAME_FRIENDLY, samlAttributes.getLastName()) );
	}
	
	/**
	 * Utility method to add the "email address" personal attribute to a SAML attribute statement.
	 * @param attributeStatement
	 * @param samlAttributes
	 */
	public void addEmailAddress(final AttributeStatement attributeStatement, final SAMLAttributes samlAttributes) {
        	    
		//  <saml:Attribute FriendlyName="EmailAddress" Name="urn:esg:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string">
        //		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">testUserValid@test.com</saml:AttributeValue>
        //	</saml:Attribute>	    		
		attributeStatement.getAttributes().add( builder.getAttribute(SAMLParameters.EMAIL_ADDRESS, SAMLParameters.EMAIL_ADDRESS_FRIENDLY, samlAttributes.getEmail()) );
	}
	
	/**
	 * Utility method to add all simple string-based attributes of a given name to a SAML attribute statement.
	 * @param attributeStatement
	 * @param samlAttributes
	 * @param attName
	 */
	private void addAttributes(final AttributeStatement attributeStatement, final SAMLAttributes samlAttributes, final String attName) {
		
        // <saml2:Attribute Name="urn:esgf:test:attribute_name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
        // 		<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">test_attribute_value</saml2:AttributeValue>
        // </saml2:Attribute>
		for (final String attValue : samlAttributes.getAttributes().get(attName)) {	
			attributeStatement.getAttributes().add( builder.getAttribute(attName, null, attValue) );
		}
		
	}

	/**
	 * Utility method to add all complex (group,role) attributes of a given name to a SAML attribute statement.
	 * @param attributeStatement
	 * @param samlAttributes
	 * @param attName
	 */
	private void addGroupAndRoles(final AttributeStatement attributeStatement, final SAMLAttributes samlAttributes, final String attName) {
		
	    //  <saml:Attribute FriendlyName="GroupRole" Name="urn:esg:group:role" NameFormat="groupRole">
        //		<saml:AttributeValue>
        //			<esg:groupRole xmlns:esg="http://www.esg.org" group="Test Group A" role="default"/>
	    //		</saml:AttributeValue>
	    //		<saml:AttributeValue>
        //			<esg:groupRole xmlns:esg="http://www.esg.org" group="User" role="default"/>
	    //		</saml:AttributeValue>
	    //	</saml:Attribute>
		for (final GroupRole grouprole :  samlAttributes.getGroupAndRoles().get(attName)) {
		    final Attribute grAttribute = builder.getGroupRoleAttribute(attName);
	    	final XSAny grAttributeValue = builder.getGroupRoleAttributeValue(grouprole.getGroup(), grouprole.getRole());
	        grAttribute.getAttributeValues().add(grAttributeValue);
		    attributeStatement.getAttributes().add(grAttribute);
		}
	    
	}
	
	/**
	 * Utility method to extract all the values of a givenSAML attribute.
	 * @param attribute
	 * @return
	 */
	private List<String> getAttributeValues(final Attribute attribute) {
		final List<String> values = new ArrayList<String>();
		for (final XMLObject attributeValue : attribute.getAttributeValues()) {
			final Element element = attributeValue.getDOM();
			final Text text = (Text)element.getFirstChild();
			values.add(text.getData().trim());
		}
		return values;
	}

	void setIncludeFlag(boolean includeFlag) {
		this.includeFlag = includeFlag;
	}

}
