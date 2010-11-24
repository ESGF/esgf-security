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
package esg.security.authn.service.api;

import java.io.File;
import java.security.cert.Certificate;

import esg.security.common.SAMLInvalidStatementException;

/**
 * High level API to build and process SAML authentication statements.
 */
public interface SAMLAuthenticationStatementFacade {
    /**
	 * Method to generate a SAML authentication statement.
	 * @param identity : the identity asserted in the SAML statement.
	 * @param issuer : the issuer of the SAML statement.
	 * @param signit : true to digitally sign the statement (requires signing credential).
	 * @return : the SAML authentication statement serialized as a string.
	 */
	String buildAuthenticationStatement(String identity, String issuer, boolean signit) throws Exception;
	
	/**
	 * Shortcut method to generate a signed SAML authentication statement, issued by the identity of the signing credential.
	 * @param identity
	 * @return
	 * @throws Exceoption
	 */
	String buildSignedAuthenticationStatement(String identity) throws Exception;
	
	/**
	 * Method to process a SAML authentication statement and extracted the asserted identity.
	 * @param xml : the SAML authentication statement serialized as a string.
	 * @param validateSignature : true to validate the statement signature (requires a set of trusted credentials).
	 * @return : the asserted identity.
	 * @throws SAMLInvalidStatementException : if the SAML statement did not validate.
	 */
	String parseAuthenticationStatement(String xml, boolean validateSignature) throws SAMLInvalidStatementException;
	
	/**
	 * Method to process a SAML authentication statement and extracted the asserted identity.
	 * @param cert : certificate used for validating the signature
	 * @param xml : the SAML authentication statement serialized as a string.
	 * @return : the asserted identity.
	 * @throws SAMLInvalidStatementException : if the SAML statement did not validate.
	 */
	SAMLAuthentication getAuthentication(Certificate cert, String xml) throws SAMLInvalidStatementException;
	
	/**
	 * Method to specify the optional credential to sign SAML assertions.
	 * @param keystore
	 * @param keystorePassword
	 * @param keystoreAlias
	 */
	void setSigningCredential(File keystoreFile, String keystorePassword, String keystoreAlias) throws Exception;
	
	/**
	 * Method to specify a set of optional trusted credentials to validate the statement signature.
	 * @param trustore
	 * @param trustorePassword
	 */
	void setTrustedCredentials(File trustoreFile, String trustorePassword) throws Exception;

}
