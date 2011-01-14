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
package esg.security.attr.service.api;

import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

import esg.security.attr.service.api.exceptions.SAMLAttributeServiceClientResponseException;

/**
 * Client-side API for interacting with a {@link SAMLAttrbuteService}.
 * Note that this API is binding-agnostic.
 */
public interface SAMLAttributeServiceClient {
	
	
	/**
	 * Method to build a SAML attribute query for a user with given OpenID.
	 * @param openid : the user unique identifier.
	 * @param attributes : the named attributes to request - if empty or null, the server will send all attributes available.
	 * @return the SAML attribute request (with binding) serialized as string, to be sent to the SAML attribute service.
	 */
	AttributeQuery buildAttributeQuery(String identifier, List<Attribute> attributes);
	
	/**
	 * Simplified method to build a SAML attribute query for string-type attributes.
	 * @param openid : the user unique identifier.
	 * @param attributes : the named attributes to request - if empty or null, the server will send all attributes available.
	 * @return the SAML attribute request (with binding) serialized as string, to be sent to the SAML attribute service.
	 */
	AttributeQuery buildStringAttributeQuery(String identifier, List<String> attributes);
	
	/**
	 * Method to build a serialized SAML attribute request containing a given attribute query.
	 * @param openid : the user unique identifier.
	 * @param attributes : the named attributes to request - if empty or null, the server will send all attributes available.
	 * @return the SAML attribute request (with binding) serialized as string, to be sent to the SAML attribute service.
	 */
	String buildAttributeRequest(AttributeQuery attributeQuery) throws MarshallingException;

	/**
	 * Method to parse a serialized SAML attribute response.
	 * @param attributeQuery
	 * @param attributeResponse
	 * @return
	 * @throws XMLParserException
	 * @throws UnmarshallingException
	 * @throws SAMLAttributeServiceClientResponseException
	 */
	SAMLAttributes parseAttributeResponse(final AttributeQuery attributeQuery, final String attributeResponse) 
	               throws XMLParserException, UnmarshallingException, SAMLAttributeServiceClientResponseException;
	
}
