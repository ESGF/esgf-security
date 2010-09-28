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
package esg.security.attr.service.impl;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Trivial implementation of {@link SAMLAttributeFactory} that returns attributes for only one user.
 */
public class SAMLAttributeFactoryTrivialImpl implements SAMLAttributeFactory {

	public SAMLAttributeFactoryTrivialImpl() {}
	
	private String issuer;

	private String samlStringAttributeName = "urn:esgf:test:attribute_name";
	private String samlGroupRoleAttributeName = "urn:esgf:test:grouprole";
	
	public SAMLAttributes newInstance(final String identifier) throws SAMLUnknownPrincipalException {
		
		if (identifier.equals("Test Openid")) {
			
			final SAMLAttributes samlAttributes = new SAMLAttributesImpl();
			
			// user information
			samlAttributes.setFirstName("Test First Name");
			samlAttributes.setLastName("Test Last Name");
			samlAttributes.setOpenid("Test Openid");
			samlAttributes.setEmail("Test Email");
			
			// access control attributes
			samlAttributes.addAttribute(samlStringAttributeName, "test_attribute_value1");
			samlAttributes.addAttribute(samlStringAttributeName, "test_attribute_value2");
			
			// (group,role) attributes
			samlAttributes.addGroupAndRole(samlGroupRoleAttributeName, new GroupRoleImpl("all_users","admin"));
			samlAttributes.addGroupAndRole(samlGroupRoleAttributeName, new GroupRoleImpl("super_users","standard"));
			
			// authority
			samlAttributes.setIssuer(this.getIssuer());
			
			return samlAttributes;
		
		} else {
			throw new SAMLUnknownPrincipalException("Unknown principal: "+identifier);
		}
		
	}
	

	public String getSamlStringAttributeName() {
		return samlStringAttributeName;
	}


	public String getSamlGroupRoleAttributeName() {
		return samlGroupRoleAttributeName;
	}


	/**
	 * Method to configure the "name" of the string-based SAML attributes issued by this factory implementation.
	 * @param samlAttributeName
	 */
	public void setSamlStringAttributeName(String samlAttributeName) {
		this.samlStringAttributeName = samlAttributeName;
	}
	
	/**
	 * Method to configure the "name" of the complex (group,role) SAML attributes issued by this factory implementation.
	 * @param samlAttributeName
	 */
	public void setSamlGroupRoleAttributeName(String samlGroupRoleAttributeName) {
		this.samlGroupRoleAttributeName = samlGroupRoleAttributeName;
	}
	
	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(final String issuer) {
		this.issuer = issuer;
	}

}
