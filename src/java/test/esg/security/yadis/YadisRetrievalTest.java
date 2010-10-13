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
import java.util.Set;

import org.junit.Test;

import esg.security.utils.ssl.DnWhitelistX509TrustMgr;
import esg.security.yadis.exception.XrdsParseException;
import esg.security.yadis.exception.YadisRetrievalException;

public class YadisRetrievalTest {
	@Test
	public void testRetrieval() throws IOException {
		// Input Whitelist DNs as a string array
		//	X500Principal [] whitelist = {
		//	new X500Principal("CN=ceda.ac.uk, OU=RAL-SPBU, O=Science and Technology Facilities Council, C=GB")
		//};
		
		// Input DNs from a file
		InputStream propertiesFile = 
			DnWhitelistX509TrustMgr.class.getResourceAsStream(
								"DnWhitelistX509TrustMgr.properties");

		YadisRetrieval yadis = null;
		try {
			yadis = new YadisRetrieval(propertiesFile);
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		URL yadisURL = new URL("https://ceda.ac.uk/openid/Philip.Kershaw");
//		URL yadisURL = new URL("https://localhost:7443/openid/PJKershaw");
		
		// 1) Retrieve as string content
		String content = null;
		try {
			content = yadis.retrieve(yadisURL);
			
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Yadis content = " + content);
		
		// 2) Retrieve as list of services
		List<XrdsServiceElem> serviceElems = null;
		
		// Retrieve only services matching these type(s)
		String elem [] = {"urn:esg:security:attribute-service"};
		HashSet<String> hashSet = new HashSet<String>(Arrays.asList(elem));
		Set<String> targetTypes = hashSet;
		try {
			serviceElems = yadis.retrieveAndParse(yadisURL, targetTypes);
			
		} catch (XrdsParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if (serviceElems.isEmpty())
			System.out.println("No services found for " + elem[0] + " type");
		
		for (XrdsServiceElem serviceElem : serviceElems)
			System.out.println(serviceElem);
	}
}
