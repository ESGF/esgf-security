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
package esg.saml.authz.service.api;

import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

/**
 * Client-side API for interacting with a {@link SAMLAuthorizationService}.
 * Note that this API is binding-agnostic.
 */
public interface SAMLAuthorizationServiceClient {
		
	/**
	 * Method to build a serialized SAML authorization request for a user with given OpenID, a given resource, and a given action.
	 * @param openid : the user unique identifier.
	 * @param resource : the resource requested.
	 * @param action : the operation to be performed on the resource.
	 * @return the SAML authorization request (with binding) serialized as string, to be sent to the SAML attribute service.
	 */
	String buildAuthorizationRequest(String openid, String resource, String action) throws MarshallingException;

	/**
	 * Method to parse a serialized SAML authorization response into a user object.
	 * @param authorizationResponse :  the SAML authorization response obtained from the SAML service, serialized as string.
	 * @return : object populated with authorizations extracted from the SAML response.
	 */
	SAMLAuthorizations parseAuthorizationResponse(String authorizationResponse) throws XMLParserException, UnmarshallingException;
}
