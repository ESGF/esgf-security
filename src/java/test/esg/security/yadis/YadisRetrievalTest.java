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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


public class YadisRetrievalTest {
	@Test
	public void testRetrieval() throws IOException, XrdsParseException, 
		YadisRetrievalException {
		
		InputStream propertiesFile = 
			YadisRetrievalTest.class.getResourceAsStream(
								"YadisRetrievalTest.properties");
		
    	Properties applicationProps = new Properties();
		Assert.assertTrue("Properties file is not set", propertiesFile != null);
    	applicationProps.load(propertiesFile);
		
		// Key store file may be null in which case standard locations are
		// searched instead
		URL yadisURL = new URL(applicationProps.getProperty("yadisURL", null));
		
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
		String elem [] = {"urn:esg:security:attribute-service"};
		HashSet<String> hashSet = new HashSet<String>(Arrays.asList(elem));
		Set<String> targetTypes = hashSet;
		serviceElems = yadis.retrieveAndParse(yadisURL, targetTypes);
		
		if (serviceElems.isEmpty())
			System.out.println("No services found for " + elem[0] + " type");
		
		Assert.assertEquals(serviceElems.toArray().length, 3);
		for (XrdsServiceElem serviceElem : serviceElems) {
			System.out.println(serviceElem);
			Assert.assertTrue("Local ID is null", 
					serviceElem.getLocalId() != null);
		}
	}
}
