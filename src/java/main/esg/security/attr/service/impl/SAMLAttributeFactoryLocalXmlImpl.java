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
			final String identity = _user.getAttributeValue("identity");
			if (!attributes.containsKey(identity)) {
				attributes.put(identity, new SAMLAttributesImpl(identity, issuer));
			}
			final SAMLAttributes atts = attributes.get(identity);
			for (final Object attribute : _user.getChildren("attribute")) {
				final Element _attribute = (Element)attribute;
				atts.addAttribute(_attribute.getAttributeValue("attribute_type"), _attribute.getAttributeValue("attribute_value"));
			}
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
