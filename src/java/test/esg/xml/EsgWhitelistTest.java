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
package esg.xml;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import esg.xml.EsgWhitelist.TrustedCAs;
import esg.xml.EsgWhitelist.TrustedCAs.OpenIdCA;
import esg.xml.EsgWhitelist.TrustedCAs.PkiCA;
import esg.xml.EsgWhitelist.TrustedServices;
import esg.xml.EsgWhitelist.TrustedServices.Datanode;
import esg.xml.EsgWhitelist.TrustedServices.Gateway;
import esg.xml.EsgWhitelist.TrustedServices.OpenIdIdentityProvider;

public class EsgWhitelistTest {
	
	protected final static Log LOG = LogFactory.getLog(EsgWhitelistTest.class);
	
	@Before
	public void beforeSetup()
        {
	}
	
	/**
	 * Tests the parsing of the whitelist
	 * @throws Exception
	 */
	@Test
	public void testParseWhitelist() throws Exception
        {
            try
            {
                JAXBContext jc = JAXBContext.newInstance("esg.xml");
                Unmarshaller u = jc.createUnmarshaller();
                EsgWhitelist ewl = (EsgWhitelist)u.unmarshal(
                    new ClassPathResource("esg/xml/EsgWhitelist.xml").getInputStream());

                Integer versionDate = ewl.getVersionDate();
                EsgWhitelistUtil.printVersionDate(versionDate);

                TrustedCAs tcas = ewl.getTrustedCAs();

                List<PkiCA> pkicas = tcas.getPkiCA();
                EsgWhitelistUtil.printPkiCAList(pkicas);

                List<OpenIdCA> openIdCAs = tcas.getOpenIdCA();
                EsgWhitelistUtil.printOpenIdCAList(openIdCAs);

                TrustedServices tsvs = ewl.getTrustedServices();

                List<OpenIdIdentityProvider> idps = tsvs.getOpenIdIdentityProvider();
                EsgWhitelistUtil.printOpenIdIdentityProviderList(idps);
            
                List<Gateway> gateways = tsvs.getGateway();
                EsgWhitelistUtil.printGatewayList(gateways);

                List<Datanode> datanodes = tsvs.getDatanode();
                EsgWhitelistUtil.printDatanodeList(datanodes);
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
            // if (LOG.isDebugEnabled()) LOG.debug(xml);
	}
}
