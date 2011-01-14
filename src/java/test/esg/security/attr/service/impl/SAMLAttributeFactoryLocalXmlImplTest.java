package esg.security.attr.service.impl;

import org.junit.Before;
import org.junit.Test;

import esg.security.attr.service.api.SAMLAttributeFactory;

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
	public void test() {
		
	}
	

}
