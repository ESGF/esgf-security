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
import org.junit.Before;

import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


public class YadisRetrievalTest {
	public final String ESGF_SECURITY_ATTRIBUTE_SERVICE_URN = 
		"urn:esg:security:attribute-service";
	public final String PROPERTIES_FILE = "YadisRetrievalTest.properties";
	public final String URL_PROPNAME = "yadisURL";
	protected final static Log LOG = LogFactory.getLog(YadisRetrievalTest.class);
	
	protected URL yadisURL = null;
	protected YadisRetrieval yadis = null;
	
	@Before
	public void setUp() throws IOException, XrdsParseException, 
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
		yadisURL = new URL(sYadisURL);
		
		// Input DNs from a file
		InputStream whiteListPropertiesFile = 
			YadisRetrievalTest.class.getResourceAsStream(
												"yadis-retrieval.properties");
		Assert.assertTrue("SSL Properties file is not set", propertiesFile != null);
		
		yadis = new YadisRetrieval(whiteListPropertiesFile);
	}
	
	/**
	 * Retrieve XRDS document as a string with Yadis.
	 * @throws IOException
	 * @throws XrdsParseException
	 * @throws YadisRetrievalException
	 */
	@Test
	public void testRetrieval() throws IOException, XrdsParseException, 
			YadisRetrievalException {
		
		// skip test if no URL was set
		if (yadisURL == null)
			return;
		
		String content = null;
		
		content = yadis.retrieve(yadisURL);

		System.out.println("Retrieved XRDS = " + content);
	}
	
	/**
	 * Retrieve XRDS document with Yadis and parse into a list of services
	 * @throws XrdsParseException
	 * @throws YadisRetrievalException
	 */
	@Test
	public void testRetrievalAndParse() throws XrdsParseException, 
			YadisRetrievalException {
		
		// skip test if no URL was set
		if (yadisURL == null)
			return;
		
		// 2) 
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
