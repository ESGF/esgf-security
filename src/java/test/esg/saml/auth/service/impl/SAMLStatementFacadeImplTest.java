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
package esg.saml.auth.service.impl;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.xml.ConfigurationException;
import org.springframework.core.io.ClassPathResource;

import esg.saml.auth.service.impl.SAMLAuthenticationStatementFacadeImpl;
import esg.saml.common.SAMLBuilder;
import esg.saml.common.SAMLInvalidStatementException;
import esg.saml.common.SAMLTstParameters;
import esg.saml.common.SAMLUnknownPrincipalException;
import eske.utils.xml.XmlChecker;

public class SAMLStatementFacadeImplTest {
	
	protected final static Log LOG = LogFactory.getLog(SAMLStatementFacadeImplTest.class);
	
	private SAMLAuthenticationStatementFacadeImpl statementFacade;
	
	@Before
	public void beforeSetup() throws ConfigurationException, SAMLUnknownPrincipalException {
				
		statementFacade = new SAMLAuthenticationStatementFacadeImpl();
		statementFacade.setIncludeFlag(false);

	}
	
	/**
	 * Tests generation of an unsigned SAML authentication statement.
	 * @throws Exception
	 */
	@Test
	public void testBuildUnsignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
		
			// build statement
			final boolean signit = false;
			final String xml = statementFacade.buildAuthenticationStatement(SAMLTstParameters.IDENTIFIER, SAMLTstParameters.ISSUER, signit);
			
			// compare to expected test XML
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTstParameters.AUTHENTICATION_FILE);
			
		}
		
	}
	
	/**
	 * Tests generation of a signed SAML authentication statement.
	 * @throws Exception
	 */
	@Test
	public void testBuildSignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
			
			// set signing credential
			setKeystore();
		
			// build statement
			final boolean signit = true;
			final String xml = statementFacade.buildAuthenticationStatement(SAMLTstParameters.IDENTIFIER, SAMLTstParameters.ISSUER, signit);
			
			// compare to expected test XML
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTstParameters.AUTHENTICATION_FILE_SIGNED);
			
		}
		
	}
	
	/**
	 * Tests generation of a signed SAML authentication statement without signing credential.
	 * @throws Exception
	 */
	@Test(expected=IllegalArgumentException.class)
	public void testBuildSignedAuthenticationStatementWithNoCredential() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
					
			// build statement
			final boolean signit = true;
			statementFacade.buildAuthenticationStatement(SAMLTstParameters.IDENTIFIER, SAMLTstParameters.ISSUER, signit);
						
		}
		
	}
	
	/**
	 * Tests processing of a SAML authentication statement.
	 * @throws Exception
	 */
	@Test
	public void testParseAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final File file = new ClassPathResource(SAMLTstParameters.AUTHENTICATION_FILE).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // process statement
	        final boolean validate = false;
	        final String identity = statementFacade.parseAuthenticationStatement(xml, validate);
	        Assert.assertEquals("Wrong identity extrected", SAMLTstParameters.IDENTIFIER, identity);
		}
		
	} 
	
	/**
	 * Tests processing of a SAML signed authentication statement.
	 * @throws Exception
	 */
	@Test()
	public void testParseSignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final File file = new ClassPathResource(SAMLTstParameters.AUTHENTICATION_FILE_SIGNED).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // set trustore
	        setTrustore();	
	        
	        // process and validate statement
	        final boolean validate = true;
	        final String identity = statementFacade.parseAuthenticationStatement(xml, validate);
	        Assert.assertEquals("Wrong identity extrected", SAMLTstParameters.IDENTIFIER, identity);
		}
		
	} 
	
	/**
	 * Tests processing of an unsigned SAML authentication statement with validation requested.
	 * @throws Exception
	 */
	@Test(expected=SAMLInvalidStatementException.class)
	public void testParseUnsignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final File file = new ClassPathResource(SAMLTstParameters.AUTHENTICATION_FILE).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // set trustore
	        setTrustore();	
	        
	        // process and validate statement
	        final boolean validate = true;
	        statementFacade.parseAuthenticationStatement(xml, validate);
	        
		}
		
	} 
	
	/**
	 * Tests processing of a corrupted signed SAML authentication statement.
	 * @throws Exception
	 */
	@Test(expected=SAMLInvalidStatementException.class)
	public void testParseInvalidSignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final File file = new ClassPathResource(SAMLTstParameters.AUTHENTICATION_FILE_SIGNED_INVALID).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // set trustore
	        setTrustore();	
	        
	        // process and validate statement
	        final boolean validate = true;
	        statementFacade.parseAuthenticationStatement(xml, validate);
	        
		}
		
	} 
	
	/**
	 * Tests processing of a SAML signed authentication statement without a trustore.
	 * @throws Exception
	 */
	@Test(expected=SAMLInvalidStatementException.class)
	public void testParseSignedAuthenticationStatementWithNoTrustore() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			// retrieve test XML
	        final File file = new ClassPathResource(SAMLTstParameters.AUTHENTICATION_FILE_SIGNED).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // process and validate statement
	        final boolean validate = true;
	        statementFacade.parseAuthenticationStatement(xml, validate);
	       
		}
		
	} 
	
	/**
	 * Method to set trusted credentials on the class instance under test.
	 * @throws Exception
	 */
	private void setTrustore() throws Exception {
        final File trustore = new ClassPathResource(SAMLTstParameters.TRUSTORE_PATH).getFile();
        statementFacade.setTrustedCredentials(trustore, SAMLTstParameters.TRUSTORE_PASSWORD);
	}

	/**
	 * Method to set the signing credential on the class instance under test.
	 * @param facade
	 * @throws Exception
	 */
	private void setKeystore() throws Exception {
		final File keystore = new ClassPathResource(SAMLTstParameters.KEYSTORE_PATH).getFile();
		statementFacade.setSigningCredential(keystore, SAMLTstParameters.KEYSTORE_PASSWORD, SAMLTstParameters.KEYSTORE_ALIAS);
	}

}
