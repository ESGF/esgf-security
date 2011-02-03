package esg.security.authz.service.impl;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import esg.security.attr.service.api.SAMLAttributes;
import esg.security.attr.service.impl.SAMLAttributesImpl;
import esg.security.policy.service.api.PolicyAction;
import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;
import esg.security.policy.service.impl.PolicyAttributeImpl;
import esg.security.policy.service.impl.PolicyServiceLocalXmlImpl;
import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.impl.RegistryServiceLocalXmlImpl;

/**
 * Test class for {@link SAMLAuthorizationFactoryImpl}.
 * 
 * @author luca.cinquini
 *
 */
public class SAMLAuthorizationFactoryImplTest {
	
	private static String ISSUER = "ESGF Test";
	private static String POLICY_FILE = "esg/security/policy/service/data/ESGFpolicies.xml";
	private static String REGISTRY_FILE = "esg/security/registry/service/data/ESGFregistry.xml";
	
	private SAMLAuthorizationFactoryImpl factory;
	private PolicyService policyService;
	private RegistryService registryService;

	@Before
	public void setup() throws Exception {
		
		policyService = new PolicyServiceLocalXmlImpl(POLICY_FILE);
		registryService = new RegistryServiceLocalXmlImpl(REGISTRY_FILE);
		factory = new SAMLAuthorizationFactoryImpl(ISSUER, policyService, registryService);

	}
	
	@Test
	public void testGetAttributeServices() throws MalformedURLException {
		
		String resource = "cmip5.file";
		Vector<String> actions = new Vector<String>();
		actions.add(PolicyAction.Read.toString());
		actions.add(PolicyAction.Write.toString());
		Map<URL, Set<String>> attServices = factory.getAttributeServices(resource, factory.getPolicies(resource, actions));
		URL url = new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm");
		Assert.assertTrue(attServices.containsKey(url));
		final Set<String> attTypes = attServices.get(url);
		Assert.assertEquals(2,attTypes.size());
		Assert.assertTrue(attTypes.contains("CMIP5 Research"));
		Assert.assertTrue(attTypes.contains("CMIP5 Commercial"));
		
	}
	
	@Test
	public void testGetAttributeServices2() throws MalformedURLException {
		
		String resource = "x.airs.x";
		Vector<String> actions = new Vector<String>();
		actions.add(PolicyAction.Read.toString());
		Map<URL, Set<String>> attServices = factory.getAttributeServices(resource, factory.getPolicies(resource, actions));
		URL url = new URL("https://esg-gateway.jpl.nasa.gov/saml/soap/secure/attributeService.htm");
		Assert.assertTrue(attServices.containsKey(url));
		final Set<String> attTypes = attServices.get(url);
		Assert.assertEquals(1,attTypes.size());
		Assert.assertTrue(attTypes.contains("AIRS"));
	}
	
	@Test
	public void testGetAttributeServices3() throws MalformedURLException {
		
		String resource = "doesnotexist";
		Vector<String> actions = new Vector<String>();
		actions.add(PolicyAction.Read.toString());
		Map<URL, Set<String>> attServices = factory.getAttributeServices(resource, factory.getPolicies(resource, actions));
		Assert.assertTrue(attServices.isEmpty());	

	}
	
	@Test
	public void testGetAttributeServices4() throws MalformedURLException {
		
		String resource = "x.airs.x";
		Vector<String> actions = new Vector<String>();
		Map<URL, Set<String>> attServices = factory.getAttributeServices(resource, factory.getPolicies(resource, actions));
		Assert.assertTrue(attServices.isEmpty());	

	}
	
	@Test
	public void testGetAttributeServices5() throws MalformedURLException {
		
		String resource = "x.airs.x";
		Vector<String> actions = new Vector<String>();
		actions.add("Invalid Action");
		Map<URL, Set<String>> attServices = factory.getAttributeServices(resource, factory.getPolicies(resource, actions));
		Assert.assertTrue(attServices.isEmpty());	

	}
	
	@Test
	public void testCorrectMatch() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research", "User");
		Assert.assertEquals(true, factory.match(policies, userAttributes));
		
	}
	
	@Test
	public void testMatchForUserWithNoAttributes() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		Assert.assertEquals(false, factory.match(policies, userAttributes));
		
	}
	
	@Test
	public void testMatchForWrongUserAttributeValue() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research", "SuperUser");
		Assert.assertEquals(false, factory.match(policies, userAttributes));
		
	}
	
	@Test
	public void testMatchForWrongAttributeType() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Public", "User");
		Assert.assertEquals(false, factory.match(policies, userAttributes));
		
	}
	
	@Test
	public void testMatchForUserWithExtraAttributes() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research","User");
		userAttributes.addAttribute("CMIP5 Commercial","Admin");
		userAttributes.addAttribute("AIRS","Admin");
		Assert.assertEquals(true, factory.match(policies, userAttributes));
		
	}
	
	@Test
	public void testMatchForNoPolicies() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research","User");
		userAttributes.addAttribute("CMIP5 Commercial","Admin");
		Assert.assertEquals(false, factory.match(policies, userAttributes));
	
	}
	
	@Test
	public void testIsFree() {
		
		String resource = "/root/free/somefile";
		List<PolicyAttribute> policies = policyService.getRequiredAttributes(resource, "Read");
		Assert.assertTrue( factory.isFree(policies) );
		policies = policyService.getRequiredAttributes(resource, "Write");
		Assert.assertFalse( factory.isFree(policies) );
		resource = "/thisisnotfree/file";
		Assert.assertFalse( factory.isFree(policies) );
		
	}
	
	
}
