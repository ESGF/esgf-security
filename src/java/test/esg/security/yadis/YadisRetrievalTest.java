/**
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 13/10/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * @author pjkersha
 */
package esg.security.yadis;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


public class YadisRetrievalTest {
	public final String ESGF_SECURITY_ATTRIBUTE_SERVICE_URN = 
		"urn:esg:security:attribute-service";
	public final String PROPERTIES_FILE = "YadisRetrievalTest.properties";
	public final String URL_PROPNAME = "yadisURL";
	protected final static Log LOG = LogFactory.getLog(YadisRetrievalTest.class);
	
	@Test
	public void testRetrieval() throws IOException, XrdsParseException, 
		YadisRetrievalException {
		
		InputStream propertiesFile = 
			YadisRetrievalTest.class.getResourceAsStream(PROPERTIES_FILE);
		
    	Properties applicationProps = new Properties();
		Assert.assertTrue("Properties file is not set", propertiesFile != null);
    	applicationProps.load(propertiesFile);
		
		String sYadisURL = applicationProps.getProperty(URL_PROPNAME, null);
		if (sYadisURL == null) {
			LOG.warn("No \"" + URL_PROPNAME + "\" property is set in the " +
					 "\"" + PROPERTIES_FILE + "\" file - skipping test!");
			return;
		}
		URL yadisURL = new URL(sYadisURL);
		
		// Input DNs from a file
		InputStream whiteListPropertiesFile = 
			YadisRetrievalTest.class.getResourceAsStream(
												"yadis-retrieval.properties");
		Assert.assertTrue("SSL Properties file is not set", propertiesFile != null);
		
		YadisRetrieval yadis = new YadisRetrieval(whiteListPropertiesFile);
		
		// 1) Retrieve as string content
		String content = null;
		content = yadis.retrieve(yadisURL);

		System.out.println("Yadis content = " + content);
		
		// 2) Retrieve as list of services
		List<XrdsServiceElem> serviceElems = null;
		
		// Retrieve only services matching these type(s)
		String elem [] = {ESGF_SECURITY_ATTRIBUTE_SERVICE_URN};
		HashSet<String> hashSet = new HashSet<String>(Arrays.asList(elem));
		Set<String> targetTypes = hashSet;
		serviceElems = yadis.retrieveAndParse(yadisURL, targetTypes);
		
		if (serviceElems.isEmpty())
			fail("No services found for " + elem[0] + " type");
		
		Assert.assertEquals(serviceElems.toArray().length, 1);
		for (XrdsServiceElem serviceElem : serviceElems) {
			System.out.println(serviceElem);
			Assert.assertTrue("Expecting service priority = 20", 
					serviceElem.getServicePriority() == 20);
		}
	}
}
