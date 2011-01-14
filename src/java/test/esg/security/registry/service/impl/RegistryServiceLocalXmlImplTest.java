package esg.security.registry.service.impl;

import java.net.URL;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import esg.security.registry.service.api.RegistryService;

/**
 * Test class for {@link RegistryServiceLocalXmlImpl}
 * 
 * @author luca.cinquini
 */
public class RegistryServiceLocalXmlImplTest {
	
	private static String XMLFILE = "esg/security/registry/service/data/ESGFregistry.xml";
	
	private RegistryService service;
	
	@Before
	public void setup() throws Exception {
		service = new RegistryServiceLocalXmlImpl(XMLFILE);
	}
	
	
	@Test
	public void testGetAttributeService() throws Exception {
		
		Assert.assertEquals(service.getAttributeService("CMIP5 Research"), new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm"));
		Assert.assertEquals(service.getAttributeService("CMIP5 Commercial"), new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm"));
		Assert.assertEquals(service.getAttributeService("AIRS"), new URL("https://esg-gateway.jpl.nasa.gov/saml/soap/secure/attributeService.htm"));
		
	}
	
}
