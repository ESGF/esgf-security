package esg.security.openid2emailresolution;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import javax.mail.internet.InternetAddress;

import org.junit.Assert;
import org.junit.Test;

import esg.security.openid2emailresolution.exceptions.AttributeServiceQueryException;
import esg.security.openid2emailresolution.exceptions.NoMatchingXrdsServiceException;
import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


public class OpenId2EmailAddrResolutionTest {
	@Test
	public void testResolution() throws IOException, 
		NoMatchingXrdsServiceException, 
		XrdsParseException, 
		AttributeServiceQueryException, 
		DnWhitelistX509TrustMgrInitException, 
		YadisRetrievalException {
		
		InputStream propertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
								"OpenId2EmailAddrResolutionTest.properties");
		
		Assert.assertTrue("Properties file is not set", propertiesFile != null);
    	Properties applicationProps = new Properties();
    	applicationProps.load(propertiesFile);
		
		// Key store file may be null in which case standard locations are
		// searched instead
		URL yadisURL = new URL(applicationProps.getProperty("yadisURL", null));
		
		// Input DNs for whitelisting read from file.  Different settings
		// may be made for the Yadis and Attribute Service connections
		InputStream yadisPropertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
								"yadis-retrieval-ssl.properties");

		InputStream attributeServiceClientPropertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
								"attribute-service-client-ssl.properties");
		
		String attributeQueryIssuer = "/CN=test/O=NDG/OU=BADC";
		OpenId2EmailAddrResolution openid2EmailAddr = new 
			OpenId2EmailAddrResolution(attributeQueryIssuer,
					yadisPropertiesFile, 
					attributeServiceClientPropertiesFile);

		InternetAddress email;
		email = openid2EmailAddr.resolve(yadisURL);
		
		Assert.assertTrue("e-mail address resolves", email.toString() != null);
		System.out.println("OpenID: " + yadisURL.toString() + " resolves to " +
				"e-mail address: " + email.toString());
	}
}
