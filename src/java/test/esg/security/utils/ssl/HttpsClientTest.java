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
import esg.security.utils.ssl.HttpsClient;


public class HttpsClientTest {

	public final static String PROPERTIES_FILE = "https-client-test.properties";
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
