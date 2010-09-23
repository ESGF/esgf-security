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

import esg.saml.attr.service.api.SAMLAttributeFactory;
import esg.saml.attr.service.api.SAMLAttributes;
import esg.saml.common.SAMLUnknownPrincipalException;

/**
 * Trivial implementation of {@link SAMLAttributeFactory} that returns attributes for only one user.
 */
public class SAMLAttributeFactoryTrivialImpl implements SAMLAttributeFactory {

	public SAMLAttributeFactoryTrivialImpl() {}
	
	private String issuer;

	private String samlAttributeName = "urn:esgf:test:grouprole";
	
	public SAMLAttributes newInstance(final String identifier) throws SAMLUnknownPrincipalException {
		
		if (identifier.equals("Test Openid")) {
			
			final SAMLAttributes samlAttributes = new SAMLAttributesImpl();
			
			// user information
			samlAttributes.setFirstName("Test First Name");
			samlAttributes.setLastName("Test Last Name");
			samlAttributes.setOpenid("Test Openid");
			samlAttributes.setEmail("Test Email");
			
			// access control attributes
			samlAttributes.addAttribute(samlAttributeName, "group_TestGroup_role_default");
			samlAttributes.addAttribute(samlAttributeName, "group_TestGroup_role_publisher");
			
			// authority
			samlAttributes.setIssuer(this.getIssuer());
			
			return samlAttributes;
		
		} else {
			throw new SAMLUnknownPrincipalException("Unknown principal: "+identifier);
		}
		
	}
	
	/**
	 * Method to configure the "name" of the SAML attributes issued by this factory implementation.
	 * @param samlAttributeName
	 */
	public void setSamlAttributeName(String samlAttributeName) {
		this.samlAttributeName = samlAttributeName;
	}
	
	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(final String issuer) {
		this.issuer = issuer;
	}

}
