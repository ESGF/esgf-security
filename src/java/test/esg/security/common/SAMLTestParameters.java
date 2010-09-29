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
package esg.security.common;

import org.junit.Test;
import org.opensaml.saml2.core.Action;

/**
 * Class that contains common test parameters.
 */
public class SAMLTestParameters {
	
	public final static String IDENTIFIER = "Test Openid";
	public final static String ISSUER = "Test SAML Issuer";
	
	public final static String KEYSTORE_PATH = "esg/security/resources/server-cert.ks";
	public final static String KEYSTORE_PASSWORD = "changeit";
	public final static String KEYSTORE_ALIAS = "tomcat";
	
	public final static String TRUSTORE_PATH = "esg/security/resources/client-trustore.ks";
	public final static String TRUSTORE_PASSWORD = "changeit";
	
	public final static String TEST_RESOURCE_PATH = "/PATH/TO/FILE";
	
	public final static String TEST_ACTION = Action.READ_ACTION;
	
	// test attribute
	public final static String TEST_ATTRIBUTE_NAME = "urn:esgf:test:attribute_name";
	public final static String TEST_GROUPROLE_ATTRIBUTE_NAME = "urn:esgf:test:grouprole";
	
	// authentication test files
	public final static String AUTHENTICATION_FILE = "esg/security/authn/service/data/SAMLauthenticationStatement.xml";
	public final static String AUTHENTICATION_FILE_SIGNED = "esg/security/authn/service/data/SAMLauthenticationStatementSigned.xml";
	public final static String AUTHENTICATION_FILE_SIGNED_INVALID = "esg/security/authn/service/data/SAMLauthenticationStatementSignedInvalid.xml";
		
	// attributes test files
	public final static String ATTRIBUTES_FILE ="esg/security/attr/service/data/SAMLattributeStatement.xml";
	public final static String ATTRIBUTES_FILE_SIGNED ="esg/security/attr/service/data/SAMLattributeStatementSigned.xml";
	public final static String ATTRIBUTES_FILE_BADC ="esg/security/attr/service/data/SAMLattributeStatementBADC.xml";
	public final static String ATTRIBUTES_FILE_PARTIAL ="esg/security/attr/service/data/SAMLattributeStatementPartial.xml";
	public final static String ATTRIBUTE_REQUEST_EMPTY ="esg/security/attr/service/data/SAMLattributeQueryEmpty.xml";
	public final static String ATTRIBUTE_REQUEST_WITH_ATTRIBUTES ="esg/security/attr/service/data/SAMLattributeQueryWithAttributes.xml";
	public final static String ATTRIBUTE_RESPONSE_SUCCESS ="esg/security/attr/service/data/SAMLattributeQueryResponseSuccess.xml";
	public final static String ATTRIBUTE_RESPONSE_WITH_ATTRIBUTES_SUCCESS ="esg/security/attr/service/data/SAMLattributeQueryResponseWithAttributesSuccess.xml";
	public final static String ATTRIBUTE_INVALID_REQUEST ="esg/security/attr/service/data/SAMLattributeQueryInvalidRequest.xml";
	public final static String ATTRIBUTE_RESPONSE_FAILURE ="esg/security/attr/service/data/SAMLattributeQueryResponseFailure.xml";
	public final static String ATTRIBUTE_PARTIAL_REQUEST ="esg/security/attr/service/data/SAMLattributeQueryPartialRequest.xml";
	public final static String ATTRIBUTE_PARTIAL_RESPONSE ="esg/security/attr/service/data/SAMLattributeQueryPartialResponse.xml";
	public static final String ATTRIBUTE_SOAP_REQUEST = "esg/security/attr/service/data/SAMLattributeQueryRequestSOAP.xml";
	public static final String ATTRIBUTE_SOAP_RESPONSE = "esg/security/attr/service/data/SAMLattributeQueryResponseSOAP.xml";

	// authorization test files
	public final static String SOAP_REQUEST = "esg/security/authz/service/data/SAMLauthorizationQueryRequestSOAP.xml";
	public final static String SOAP_RESPONSE = "esg/security/authz/service/data/SAMLauthorizationQueryResponseSOAP.xml";
	public final static String REQUEST ="esg/security/authz/service/data/SAMLauthorizationQuery.xml";
	public final static String VALID_REQUEST ="esg/security/authz/service/data/SAMLauthorizationQueryValidRequest.xml";
	public final static String RESPONSE_SUCCESS ="esg/security/authz/service/data/SAMLauthorizationQueryResponseSuccess.xml";	
	public final static String INVALID_REQUEST ="esg/security/authz/service/data/SAMLauthorizationQueryInvalidRequest.xml";
	public final static String RESPONSE_FAILURE ="esg/security/authz/service/data/SAMLauthorizationQueryResponseFailure.xml";
	public final static String AUTHZ_DECISION_STMT_FILE = "esg/security/authz/service/data/SAMLauthzDecisionStatement.xml";
			
	@Test
	public void testNothing() {}


}
