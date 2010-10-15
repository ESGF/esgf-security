package esg.security.openid2emailresolution;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.mail.internet.InternetAddress;

import org.junit.Test;

import esg.security.openid2emailresolution.exceptions.AttributeServiceQueryException;
import esg.security.openid2emailresolution.exceptions.NoMatchingXrdsServiceException;
import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.yadis.exception.XrdsParseException;
import esg.security.yadis.exception.YadisRetrievalException;


public class OpenId2EmailAddrResolutionTest {
	@Test
	public void testResolution() throws IOException, 
		NoMatchingXrdsServiceException, 
		XrdsParseException, 
		AttributeServiceQueryException, 
		DnWhitelistX509TrustMgrInitException, 
		YadisRetrievalException
	{
		// Input DNs for whitelisting read from file.  Different settings
		// may be made for the Yadis and Attribute Service connections
		InputStream yadisPropertiesFile = 
			OpenId2EmailAddrResolution.class.getResourceAsStream(
								"yadis-retrieval-ssl.properties");

		InputStream attributeServiceClientPropertiesFile = 
			OpenId2EmailAddrResolution.class.getResourceAsStream(
								"attribute-service-client-ssl.properties");
		
		OpenId2EmailAddrResolution openid2EmailAddr = new 
			OpenId2EmailAddrResolution(yadisPropertiesFile, 
					attributeServiceClientPropertiesFile);
		
		URL yadisURL = new URL("https://localhost:7443/openid/philip.kershaw");

		InternetAddress email;
		email = openid2EmailAddr.resolve(yadisURL);
		System.out.println("OpenID: " + yadisURL.toString() + " resolves to " +
				"e-mail address: " + email.toString());
	}
}
