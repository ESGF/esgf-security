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
package esg.security.authn.service.impl;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.xml.ConfigurationException;
import org.springframework.core.io.ClassPathResource;

import esg.security.authn.service.api.SAMLAuthentication;
import esg.security.common.SAMLBuilder;
import esg.security.common.SAMLInvalidStatementException;
import esg.security.common.SAMLParameters;
import esg.security.common.SAMLTestParameters;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.ssl.TrivialCertGenerator;
import esg.security.utils.xml.XmlChecker;

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
			final String xml = statementFacade.buildAuthenticationStatement(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER, signit);
			
			// compare to expected test XML
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.AUTHENTICATION_FILE);
			
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
			final String xml = statementFacade.buildAuthenticationStatement(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER, signit);
			
			// compare to expected test XML
	        if (LOG.isDebugEnabled()) LOG.debug(xml);
	        XmlChecker.compare(xml, SAMLTestParameters.AUTHENTICATION_FILE_SIGNED);
			
		}
		
	}
	
	/**
	 * Tests generation of a signed SAML authentication statement without signing credential.
	 * @throws Exception
	 */
	@Test//(expected=IllegalArgumentException.class)
	public void testBuildSignedAuthenticationStatementWithNoCredential() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
					
			try {
				
				// build statement
				final boolean signit = true;
				statementFacade.buildAuthenticationStatement(SAMLTestParameters.IDENTIFIER, SAMLTestParameters.ISSUER, signit);
				
				// fail if exception has not been thrown
				Assert.fail();
				
			} catch(Exception e) {
				Assert.assertTrue(e instanceof IllegalArgumentException);
			}

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
	        final File file = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // process statement
	        final boolean validate = false;
	        final String identity = statementFacade.parseAuthenticationStatement(xml, validate);
	        Assert.assertEquals("Wrong identity extrected", SAMLTestParameters.IDENTIFIER, identity);
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
	        final File file = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE_SIGNED).getFile();
	        final String xml = FileUtils.readFileToString(file);
	        
	        // set trustore
	        setTrustore();	
	        
	        // process and validate statement
	        final boolean validate = true;
	        final String identity = statementFacade.parseAuthenticationStatement(xml, validate);
	        Assert.assertEquals("Wrong identity extrected", SAMLTestParameters.IDENTIFIER, identity);
		}
		
	} 
	
	/**
	 * Tests processing of an unsigned SAML authentication statement with validation requested.
	 * @throws Exception
	 */
	@Test//(expected=SAMLInvalidStatementException.class)
	public void testParseUnsignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			try {
				// retrieve test XML
		        final File file = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE).getFile();
		        final String xml = FileUtils.readFileToString(file);
		        
		        // set trustore
		        setTrustore();	
		        
		        // process and validate statement
		        final boolean validate = true;
		        statementFacade.parseAuthenticationStatement(xml, validate);
		        
		        // fail if exception has not been thrown
		        Assert.fail();
		        
			} catch(Exception e) {
				Assert.assertTrue(e instanceof SAMLInvalidStatementException);
			}

	        
		}
		
	} 
	
	/**
	 * Tests processing of a corrupted signed SAML authentication statement.
	 * @throws Exception
	 */
	@Test//(expected=SAMLInvalidStatementException.class)
	public void testParseInvalidSignedAuthenticationStatement() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
					
			try {
				
				// retrieve test XML
		        final File file = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE_SIGNED_INVALID).getFile();
		        final String xml = FileUtils.readFileToString(file);
		        
		        // set trustore
		        setTrustore();	
		        
		        // process and validate statement
		        final boolean validate = true;
		        statementFacade.parseAuthenticationStatement(xml, validate);
		        
				// fail if exception has not been thrown
				Assert.fail();
				
			} catch(Exception e) {
				Assert.assertTrue(e instanceof SAMLInvalidStatementException);
			}
	        
		}
		
	} 
	
	/**
	 * Tests processing of a SAML signed authentication statement without a trustore.
	 * @throws Exception
	 */
	@Test//(expected=SAMLInvalidStatementException.class)
	public void testParseSignedAuthenticationStatementWithNoTrustore() throws Exception {
		
		if (SAMLBuilder.isInitailized()) {
						
			try {
				
				// retrieve test XML
		        final File file = new ClassPathResource(SAMLTestParameters.AUTHENTICATION_FILE_SIGNED).getFile();
		        final String xml = FileUtils.readFileToString(file);
		        
		        // process and validate statement
		        final boolean validate = true;
		        statementFacade.parseAuthenticationStatement(xml, validate);
		        
				// fail if exception has not been thrown
				Assert.fail();
			
			} catch(Exception e) {
				Assert.assertTrue(e instanceof SAMLInvalidStatementException);
			}
	       
		}
		
	} 
	
	/**
     * GetAuthentication: check the authentication retrieval 
     */
    @Test
    public void testGetAuthentication() throws Exception {
        statementFacade.setIncludeFlag(true);
        setKeystore();
        setTrustore();
        
        Assert.assertTrue(SAMLBuilder.isInitailized());
        String identity = "thisIsMe" ;
        String saml = statementFacade.buildSignedAuthenticationStatement(identity);
        String oid = statementFacade.parseAuthenticationStatement(saml, true);
        
        KeyStore ks = TrivialCertGenerator.loadKeystore(new ClassPathResource(
                SAMLTestParameters.TRUSTORE_PATH).getFile(),
                SAMLTestParameters.TRUSTORE_PASSWORD);
        Certificate cert = ks.getCertificate(SAMLTestParameters.KEYSTORE_ALIAS);
        
        SAMLAuthentication authentication = statementFacade.getAuthentication(cert, saml);
        Assert.assertEquals(oid, authentication.getIdentity());
        
        //assure it gets the proper valid from (current time)
        long now = new java.util.Date().getTime();
        Assert.assertTrue(now > authentication.getValidFrom().getTime());
        Assert.assertTrue(now < authentication.getValidFrom().getTime() + 5 * 1000);
        
        //check the date is as expected (within 5 seconds of lifetime)
        long span = authentication.getValidTo().getTime() - now;
        long samlSpan = SAMLParameters.ASSERTION_LIFETIME_IN_SECONDS * 1000;
        Assert.assertTrue(span > samlSpan - 5 * 1000);
        Assert.assertTrue(span <= samlSpan);
        
        Assert.assertEquals(saml, authentication.getSaml());
        
    }
    
    /**
     * Timezones: check the authentication retrieval 
     */
    @Test
    public void testTimezones() throws Exception {
        statementFacade.setIncludeFlag(true);
        setKeystore();
        setTrustore();

        //prepare the test
        Assert.assertTrue(SAMLBuilder.isInitailized());
        String identity = "thisIsMe" ;
        KeyStore ks = TrivialCertGenerator.loadKeystore(new ClassPathResource(
                SAMLTestParameters.TRUSTORE_PATH).getFile(),
                SAMLTestParameters.TRUSTORE_PASSWORD);
        Certificate cert = ks.getCertificate(SAMLTestParameters.KEYSTORE_ALIAS);
        TimeZone tz1 = TimeZone.getTimeZone("GMT-10:00");
        TimeZone tz2 = TimeZone.getTimeZone("GMT+10:00");

        
        // write saml at time zone 1 GMT-10:00
        TimeZone.setDefault(tz1);
        String saml = statementFacade.buildSignedAuthenticationStatement(identity);
        
        //read SAML at time zone GTM+11:00
        TimeZone.setDefault(tz2);
        SAMLAuthentication authentication = statementFacade.getAuthentication(cert, saml);
        long diff = new Date().getTime() - authentication.getValidFrom().getTime();
        Assert.assertTrue(diff > 0);
        Assert.assertTrue(diff < 5 * 1000);
       
    }
    

    
	/**
	 * Method to set trusted credentials on the class instance under test.
	 * @throws Exception
	 */
	private void setTrustore() throws Exception {
        final File trustore = new ClassPathResource(SAMLTestParameters.TRUSTORE_PATH).getFile();
        statementFacade.setTrustedCredentials(trustore, SAMLTestParameters.TRUSTORE_PASSWORD);
	}

	/**
	 * Method to set the signing credential on the class instance under test.
	 * @param facade
	 * @throws Exception
	 */
	private void setKeystore() throws Exception {
		final File keystore = new ClassPathResource(SAMLTestParameters.KEYSTORE_PATH).getFile();
		statementFacade.setSigningCredential(keystore, SAMLTestParameters.KEYSTORE_PASSWORD, SAMLTestParameters.KEYSTORE_ALIAS);
	}

}
