/*******************************************************************************
 * Copyright (c) 2010 Earth System Grid Federation
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

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.api.UnknownPolicyAttributeTypeException;
import esg.security.utils.xml.Parser;

/**
 * Implementation of {@link RegistryService} backed up by a local XML configuration file.
 * 
 * @author luca.cinquini
 */
public class RegistryServiceLocalXmlImpl implements RegistryService {
	
	// local storage of attribute type to attribute service mapping
	private Map<String, URL> attributeServices = new HashMap<String, URL>();
	
	public RegistryServiceLocalXmlImpl(final String xmlFilePath) throws Exception {
		
		final File file = new ClassPathResource(xmlFilePath).getFile();
		parseRegistry(file);
	}

	@Override
	public URL getAttributeService(final String attributeType) throws UnknownPolicyAttributeTypeException {
		if (attributeServices.containsKey(attributeType)) {
			return attributeServices.get(attributeType);
		} else {
			throw new UnknownPolicyAttributeTypeException("Cannot resolve attribute type="+attributeType);
		}
	}

	// method to parse the XML registry into the local map.
	void parseRegistry(final File file) throws MalformedURLException, IOException, JDOMException {
		
		final Document doc = Parser.toJDOM(file.getAbsolutePath(), false);
		final Element root = doc.getRootElement();
		
		for (final Object attr : root.getChildren("attribute")) {
			final Element _attr = (Element)attr;
			attributeServices.put(_attr.getAttributeValue("type"), new URL(_attr.getAttributeValue("service")));
		}
		
	}
}
