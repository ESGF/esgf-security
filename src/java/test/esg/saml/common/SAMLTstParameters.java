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
package esg.saml.common;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml2.core.Action;

/**
 * Class that contains common test parameters.
 */
public abstract class SAMLTstParameters {
	
	public final static String IDENTIFIER = "Test Openid";
	public final static String ISSUER = "Test SAML Issuer";
	
	public final static String KEYSTORE_PATH = "esg/saml/resources/keystore-localhost";
	public final static String KEYSTORE_PASSWORD = "changeit";
	public final static String KEYSTORE_ALIAS = "tomcat";
	
	public final static String TRUSTORE_PATH = "esg/saml/resources/jssecacerts";
	public final static String TRUSTORE_PASSWORD = "changeit";
	
	public final static String TEST_RESOURCE_PATH = "/PATH/TO/FILE";
	
	public final static String TEST_ACTION = Action.READ_ACTION;
	
	// authentication test files
	public final static String AUTHENTICATION_FILE = "esg/saml/auth/service/data/SAMLauthenticationStatement.xml";
	public final static String AUTHENTICATION_FILE_SIGNED = "esg/saml/auth/service/data/SAMLauthenticationStatementSigned.xml";
	public final static String AUTHENTICATION_FILE_SIGNED_INVALID = "esg/saml/auth/service/data/SAMLauthenticationStatementSignedInvalid.xml";
		
	// attributes test files
	public final static String ATTRIBUTES_FILE ="esg/saml/attr/service/data/SAMLattributeStatement.xml";
	public final static String ATTRIBUTES_FILE_SIGNED ="esg/saml/attr/service/data/SAMLattributeStatementSigned.xml";
	public final static String ATTRIBUTES_FILE_BADC ="esg/saml/attr/service/data/SAMLattributeStatementBADC.xml";
	public final static String ATTRIBUTES_FILE_PARTIAL ="esg/saml/attr/service/data/SAMLattributeStatementPartial.xml";
	public final static String ATTRIBUTE_REQUEST ="esg/saml/attr/service/data/SAMLattributeQuery.xml";
	public final static String ATTRIBUTE_VALID_REQUEST ="esg/saml/attr/service/data/SAMLattributeQueryValidRequest.xml";
	public final static String ATTRIBUTE_RESPONSE_SUCCESS ="esg/saml/attr/service/data/SAMLattributeQueryResponseSuccess.xml";
	public final static String ATTRIBUTE_INVALID_REQUEST ="esg/saml/attr/service/data/SAMLattributeQueryInvalidRequest.xml";
	public final static String ATTRIBUTE_RESPONSE_FAILURE ="esg/saml/attr/service/data/SAMLattributeQueryResponseFailure.xml";
	public final static String ATTRIBUTE_PARTIAL_REQUEST ="esg/saml/attr/service/data/SAMLattributeQueryPartialRequest.xml";
	public final static String ATTRIBUTE_PARTIAL_RESPONSE ="esg/saml/attr/service/data/SAMLattributeQueryPartialResponse.xml";
	public static final String ATTRIBUTE_SOAP_REQUEST = "esg/saml/attr/service/data/SAMLattributeQueryRequestSOAP.xml";
	public static final String ATTRIBUTE_SOAP_RESPONSE = "esg/saml/attr/service/data/SAMLattributeQueryResponseSOAP.xml";



	
	// authorization test files
	public final static String SOAP_REQUEST = "esg/saml/authz/service/data/SAMLauthorizationQueryRequestSOAP.xml";
	public final static String SOAP_RESPONSE = "esg/saml/authz/service/data/SAMLauthorizationQueryResponseSOAP.xml";
	public final static String REQUEST ="esg/saml/authz/service/data/SAMLauthorizationQuery.xml";
	public final static String VALID_REQUEST ="esg/saml/authz/service/data/SAMLauthorizationQueryValidRequest.xml";
	public final static String RESPONSE_SUCCESS ="esg/saml/authz/service/data/SAMLauthorizationQueryResponseSuccess.xml";	
	public final static String INVALID_REQUEST ="esg/saml/authz/service/data/SAMLauthorizationQueryInvalidRequest.xml";
	public final static String RESPONSE_FAILURE ="esg/saml/authz/service/data/SAMLauthorizationQueryResponseFailure.xml";
	public final static String AUTHZ_DECISION_STMT_FILE = "esg/saml/authz/service/data/SAMLauthzDecisionStatement.xml";
			
	@Test
	public void testNothing() {
		 Assert.assertTrue(true);
	}

}
