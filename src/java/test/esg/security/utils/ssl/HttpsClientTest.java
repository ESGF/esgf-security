package esg.security.utils.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.junit.Assert;
import org.junit.Test;

import esg.security.utils.ssl.exceptions.HttpsClientInitException;
import esg.security.utils.ssl.exceptions.HttpsClientRetrievalException;


public class HttpsClientTest {

	public final static String PROPERTIES_FILE = "https-client-test.properties";
	public final static String URI = "https://pcmdi3.llnl.gov";
	
	@Test
	public void test01NoClientAuthnWithPropertiesFile() throws IOException, 
		HttpsClientInitException, HttpsClientRetrievalException {
		
		InputStream propertiesFile = this.getClass().getResourceAsStream(PROPERTIES_FILE);
		HttpsClient httpsClient = new HttpsClient(propertiesFile);
		final URL uri = new URL(URI);
		String content = httpsClient.retrieve(uri, null, null);
		Assert.assertNotNull(content);
	}
}
