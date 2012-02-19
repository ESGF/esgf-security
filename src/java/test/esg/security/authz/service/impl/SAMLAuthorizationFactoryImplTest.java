/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
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
	private static String POLICY_FILE = "esg/security/policy/service/data/esgf_policies.xml";
	private static String REGISTRY_FILE = "esg/security/registry/service/data/esgf_ats.xml";
	private static String IDENTIFIER = "user_openid";
	
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
		
		URL url = new URL("https://pcmdi9.llnl.gov/esgf-security/saml/soap/secure/attributeService.htm");
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
		URL url = new URL("https://esg-datanode.jpl.nasa.gov/esgf-security/saml/soap/secure/attributeService.htm");
		Assert.assertTrue(attServices.containsKey(url));
		final Set<String> attTypes = attServices.get(url);
		Assert.assertEquals(1,attTypes.size());
		Assert.assertTrue(attTypes.contains("NASA OBS"));
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
		Assert.assertEquals(true, factory.match(policies, userAttributes, IDENTIFIER));
		
	}
	
	@Test
	public void testMatchForUserWithNoAttributes() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		Assert.assertEquals(false, factory.match(policies, userAttributes, IDENTIFIER));
		
	}
	
	@Test
	public void testMatchForWrongUserAttributeValue() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research", "SuperUser");
		Assert.assertEquals(false, factory.match(policies, userAttributes, IDENTIFIER));
		
	}
	
	@Test
	public void testMatchForWrongAttributeType() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		policies.add(new PolicyAttributeImpl("CMIP5 Research","User"));
		policies.add(new PolicyAttributeImpl("CMIP5 Commercial","Admin"));
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Public", "User");
		Assert.assertEquals(false, factory.match(policies, userAttributes, IDENTIFIER));
		
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
		Assert.assertEquals(true, factory.match(policies, userAttributes, IDENTIFIER));
		
	}
	
	@Test
	public void testMatchForNoPolicies() {
		
		List<PolicyAttribute> policies = new ArrayList<PolicyAttribute>();
		
		SAMLAttributes userAttributes = new SAMLAttributesImpl("some user", "some issuer");
		userAttributes.addAttribute("CMIP5 Research","User");
		userAttributes.addAttribute("CMIP5 Commercial","Admin");
		Assert.assertEquals(false, factory.match(policies, userAttributes, IDENTIFIER));
	
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
