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
package esg.security.utils.ssl;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import esg.security.utils.ssl.exceptions.HttpsClientInitException;
import esg.security.utils.ssl.exceptions.HttpsClientRetrievalException;


public class HttpsClientTest {

	public final static String PROPERTIES_FILE = "https-client-test.properties";
	public final static String TRUSTSTORE_FILE = "https-client-test-truststore.ks";
	public final static String TEST01_URI = "test01.uri";
	public final static String TEST02_URI = "test02.uri";
	public final static String URI = "https://pcmdi3.llnl.gov";
	protected final static Log LOG = LogFactory.getLog(HttpsClientTest.class);
	protected Properties props = null;
	
	@Before
	public void beforeSetup() throws IOException {
		InputStream propertiesFile = this.getClass().getResourceAsStream(PROPERTIES_FILE);
		
    	props = new Properties();
		props.load(propertiesFile);
		
		//Find the file from this classloader and put the path in the proper variable
		props.put("esg.security.utils.ssl.DnWhitelistX509TrustMgr.trustStoreFilePath", 
		        this.getClass().getResource(TRUSTSTORE_FILE).getFile());
		
	}
	
	@Test
	public void test01CertTimestampError() throws IOException, 
		HttpsClientInitException, HttpsClientRetrievalException {
		
		String sUri = props.getProperty(TEST01_URI, null);
		if (sUri == null) {
			LOG.warn("No URI set for test 01, skipping test ...");
			return;
		}
		final URL uri = new URL(sUri);
		
		HttpsClient httpsClient = new HttpsClient(props);
		
		try {
			httpsClient.retrieve(uri, null, null);
			
		} catch (IOException e) {
			LOG.debug("PASS: Caught expected timestamp exception: " + e);
			return;
		}
		fail("Expecting timestamp exception for URI " + uri.toString());
	}
	
	@Test
	public void test02ValidConnection() throws IOException, 
		HttpsClientInitException, HttpsClientRetrievalException {
		
		String sUri = props.getProperty(TEST02_URI, null);
		if (sUri == null) {
			LOG.warn("No URI set for test 02, skipping test ...");
			return;
		}
		final URL uri = new URL(sUri);		

		HttpsClient httpsClient = new HttpsClient(props);
		
		String content = httpsClient.retrieve(uri, null, null);
		Assert.assertNotNull(content);
	}
}
