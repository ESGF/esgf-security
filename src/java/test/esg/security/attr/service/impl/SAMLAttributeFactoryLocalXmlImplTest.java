package esg.security.attr.service.impl;

import java.util.Map;
import java.util.Set;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Test class for {@link SAMLAttributeFactoryLocalXmlImpl}.
 * @author luca.cinquini
 *
 */
public class SAMLAttributeFactoryLocalXmlImplTest {
	
	private static String ISSUER = "ESGF NODE"; 
	private static String XMLFILE = "esg/security/attr/service/data/ESGFusers.xml";
	
	private SAMLAttributeFactory factory;
	
	
	@Before
	public void setup() throws Exception {
		factory = new SAMLAttributeFactoryLocalXmlImpl(ISSUER, XMLFILE);
		((SAMLAttributeFactoryLocalXmlImpl)factory).print();
	}
	
	@Test
	public void test() throws SAMLUnknownPrincipalException {
		
		String openid = "https://esg-gateway.jpl.nasa.gov/myopenid/rootAdmin";
		SAMLAttributes atts = factory.newInstance(openid);
		Assert.assertEquals(openid, atts.getOpenid());
		Assert.assertEquals("root", atts.getFirstName());
		Assert.assertEquals("admin", atts.getLastName());
		Assert.assertEquals("root@admin", atts.getEmail());
		Assert.assertEquals(ISSUER, atts.getIssuer());
		
		final Map<String,Set<String>> acatts = atts.getAttributes();
		Assert.assertTrue(acatts.containsKey("AIRS"));
		Assert.assertTrue(acatts.get("AIRS").contains("User"));
		Assert.assertTrue(acatts.containsKey("CMIP5 Research"));
		Assert.assertTrue(acatts.get("CMIP5 Research").contains("User"));
		Assert.assertTrue(acatts.get("CMIP5 Research").contains("Admin"));
		
	}
	

}
