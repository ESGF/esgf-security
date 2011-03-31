package esg.security.openid2emailresolution;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import javax.mail.internet.InternetAddress;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import esg.security.openid2emailresolution.exceptions.AttributeServiceQueryException;
import esg.security.openid2emailresolution.exceptions.NoMatchingXrdsServiceException;
import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.yadis.YadisRetrievalTest;
import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


public class OpenId2EmailAddrResolutionTest {
	public final String ESGF_SECURITY_ATTRIBUTE_SERVICE_URN = 
		"urn:esg:security:attribute-service";
	public final String PROPERTIES_FILE = 
		"OpenId2EmailAddrResolutionTest.properties";
	public final String YADIS_RETRIEVAL_PROPERTIES_FILE = 
		"yadis-retrieval.properties";
	public final String ATTRIBUTE_SERVICE_CLIENT_SSL_PROPERTIES_FILE = 
		"attribute-service-client-ssl.properties";
	public final String URL_PROPNAME = "yadisURL";
	public final String ATTRIBUTE_QUERY_ISSUER_PROPNAME = "attributeQueryIssuer";
	protected final static Log LOG = LogFactory.getLog(YadisRetrievalTest.class);

	@Test
	public void testResolution() throws IOException, 
		NoMatchingXrdsServiceException, 
		XrdsParseException, 
		AttributeServiceQueryException, 
		DnWhitelistX509TrustMgrInitException, 
		YadisRetrievalException {
		
		InputStream propertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
					PROPERTIES_FILE);
		
		Assert.assertTrue("Properties file is not set", propertiesFile != null);
    	Properties applicationProps = new Properties();
    	applicationProps.load(propertiesFile);
		
		String sYadisURL = applicationProps.getProperty(URL_PROPNAME, null);
		if (sYadisURL == null) {
			LOG.warn("No \"" + URL_PROPNAME + "\" property is set in the " +
					 "\"" + PROPERTIES_FILE + "\" file - skipping test!");
			return;
		}
		URL yadisURL = new URL(sYadisURL);
		
		String attributeQueryIssuer = applicationProps.getProperty(
				ATTRIBUTE_QUERY_ISSUER_PROPNAME, null);
		if (attributeQueryIssuer == null) {
			LOG.warn("No \"" + ATTRIBUTE_QUERY_ISSUER_PROPNAME + "\" " +
					 "property is set in the \"" + PROPERTIES_FILE + 
					 "\" file - skipping test!");
			return;
		}
		
		// Input DNs for whitelisting read from file.  Different settings
		// may be made for the Yadis and Attribute Service connections
		InputStream yadisPropertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
								YADIS_RETRIEVAL_PROPERTIES_FILE);

		InputStream attributeServiceClientPropertiesFile = 
			OpenId2EmailAddrResolutionTest.class.getResourceAsStream(
								ATTRIBUTE_SERVICE_CLIENT_SSL_PROPERTIES_FILE);
		
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
