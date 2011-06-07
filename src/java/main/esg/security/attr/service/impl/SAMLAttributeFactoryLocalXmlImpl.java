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
package esg.security.attr.service.impl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.xml.Parser;

/**
 * Implementation of {@link SAMLAttributeFactory} backed up by a local XML configuration file.
 * Note that this implementation is NOT scalable and is only intended for deploying a small prototype system.
 * 
 * @author luca.cinquini
 */
public class SAMLAttributeFactoryLocalXmlImpl implements SAMLAttributeFactory {
	
	final Map<String, SAMLAttributes> attributes = new HashMap<String, SAMLAttributes>();
	final private String issuer;
	
	public SAMLAttributeFactoryLocalXmlImpl(final String issuer, final String xmlfilepath) throws Exception {
		
		this.issuer = issuer;
		final File file = new ClassPathResource(xmlfilepath).getFile();
		parseXml(file);
		
	}

	@Override
	public SAMLAttributes newInstance(String identifier) throws SAMLUnknownPrincipalException {
		if (attributes.containsKey(identifier)) {
			// return ALL available attributes:
			// the invoking service takes care of selecting the required types,
			// or returning all attributes if none is specified
			return attributes.get(identifier);
		} else {
			throw new SAMLUnknownPrincipalException("Unknown identifier: "+identifier);
		}
	}

	@Override
	public String getIssuer() {
		return issuer;
	}
	
	// method to parse the XML attributes file into the local map of SAMLattributes
	void parseXml(final File file) throws MalformedURLException, IOException, JDOMException {
		
		final Document doc = Parser.toJDOM(file.getAbsolutePath(), false);
		final Element root = doc.getRootElement();
		
		for (final Object user : root.getChildren("user")) {
			final Element _user = (Element)user;
			// parse personal information
			final String openid = _user.getAttributeValue("openid");
			final SAMLAttributes atts = new SAMLAttributesImpl(openid, issuer);
			atts.setFirstName(_user.getAttributeValue("first_name"));
			atts.setLastName(_user.getAttributeValue("last_name"));
			atts.setEmail(_user.getAttributeValue("email"));
			// parse normal attributes
			for (final Object attribute : _user.getChildren("attribute")) {
				final Element _attribute = (Element)attribute;
				atts.addAttribute(_attribute.getAttributeValue("attribute_type"), _attribute.getAttributeValue("attribute_value"));
			}
			// parse complex (group,role) attributes
			for (final Object gr : _user.getChildren("grouprole")) {
			    final Element grouprole = (Element)gr;
			    final String type = grouprole.getAttributeValue("attribute_type");
			    final String group = grouprole.getAttributeValue("group");
			    final String role = grouprole.getAttributeValue("role");
			    atts.addGroupAndRole(type, new GroupRoleImpl(group, role));
			}
			attributes.put(openid, atts);
		}
		
	}
	
	/**
	 * Debug method.
	 */
	public void print() {
		
		for (final String identity : attributes.keySet()) {
			System.out.println("User="+identity);
			System.out.println(attributes.get(identity));
		}
		
	}

}
