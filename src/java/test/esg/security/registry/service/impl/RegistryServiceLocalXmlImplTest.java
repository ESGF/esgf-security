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
package esg.security.registry.service.impl;

import java.net.URL;

import org.junit.Assert;
import org.junit.Test;

import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.api.UnknownPolicyAttributeTypeException;

/**
 * Test class for {@link RegistryServiceLocalXmlImpl}
 * 
 * @author luca.cinquini
 */
public class RegistryServiceLocalXmlImplTest {
	
	private static String ESGF_ATS = "esg/security/registry/service/data/esgf_ats.xml";
	private static String ESGF_IDP = "esg/security/registry/service/data/esgf_idp.xml";
	
	
	@Test
	public void testGetAttributeService() throws Exception {
	    
	    final RegistryService service = new RegistryServiceLocalXmlImpl(ESGF_ATS);
		
		Assert.assertTrue(service.getAttributeServices("CMIP5 Research").contains( new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm")));
	    Assert.assertTrue(service.getAttributeServices("CMIP5 Research").contains( new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService2.htm")));
		Assert.assertTrue(service.getAttributeServices("CMIP5 Commercial").contains( new URL("https://pcmdi3.llnl.gov/esgcet/saml/soap/secure/attributeService.htm")));
		Assert.assertTrue(service.getAttributeServices("AIRS").contains( new URL("https://esg-gateway.jpl.nasa.gov/saml/soap/secure/attributeService.htm")));
		
	}
	
	@Test(expected=UnknownPolicyAttributeTypeException.class)
	public void testGetAttributeServiceForUnkwonType() throws Exception {
	    
	    final RegistryService service = new RegistryServiceLocalXmlImpl(ESGF_ATS);
		service.getAttributeServices("DoesNotExist");	
		
	}
	
    @Test
    public void testgetIdentityProviders() throws Exception {
        
        final RegistryService service = new RegistryServiceLocalXmlImpl(ESGF_IDP);
        
        Assert.assertTrue(service.getIdentityProviders().contains( new URL("https://pcmdi3.llnl.gov/esgcet/openid/provider.htm")) );
        
    }
	
}
