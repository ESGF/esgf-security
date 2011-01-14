package esg.security.policy.service.impl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;
import esg.security.policy.service.api.PolicyStatement;
import esg.security.utils.xml.Parser;

/**
 * Implementation of {@link esg.security.policy.service.api.PolicyService} backed up by a local XML configuration file.
 * The XML file contains regular expressions matching the resource identifiers, and this service implementation will return
 * the policy statements for the first match found, for the given action.
 * 
 * @author luca.cinquini
 *
 */
public class PolicyServiceLocalXmlImpl implements PolicyService {
	
	final LinkedHashMap<Pattern, List<PolicyStatement>> policies = new LinkedHashMap<Pattern, List<PolicyStatement>>();
	
	public PolicyServiceLocalXmlImpl(final String xmlFilePath) throws Exception {
		
		final File file = new ClassPathResource(xmlFilePath).getFile();
		parseXml(file);
		
	}

	@Override
	public List<PolicyAttribute> getRequiredAttributes(String resource, String action) {

		final List<PolicyAttribute> attributes = new ArrayList<PolicyAttribute>();
		
		for (final Pattern pattern : policies.keySet()) {
			Matcher matcher = pattern.matcher(resource);
			if (matcher.matches()) {
				for (final PolicyStatement pstmt : policies.get(pattern)) {
					if (pstmt.getAction().toString().equals(action)) {
						attributes.add(pstmt.getAttribute());
					}
				}
			}
		}
		
		return attributes;

	}
	
	// method to parse the XML file containing the policy statements into the local map.
	void parseXml(final File file) throws MalformedURLException, IOException, JDOMException {
		
		final Document doc = Parser.toJDOM(file.getAbsolutePath(), false);
		final Element root = doc.getRootElement();
		
		// must store additional map because Pattern does not re-implement hashCode()
		final Map<String, Pattern> patterns = new HashMap<String, Pattern>();
		
		for (final Object pol : root.getChildren("policy")) {
			final Element policy = (Element)pol;
			final String resource = policy.getAttributeValue("resource");
			final Pattern pattern = Pattern.compile(resource);
			if (patterns.get(resource)==null) {
				patterns.put(resource, pattern);
				policies.put(pattern, new ArrayList<PolicyStatement>());
			}
			policies.get(patterns.get(resource)).add(
					new PolicyStatementImpl(policy.getAttributeValue("resource"), 
					    		            policy.getAttributeValue("attribute_type"), 
					    		            policy.getAttributeValue("attribute_value"),
					    		            policy.getAttributeValue("action")) 
			);
		}
		
	}
	
	// debug method
	public void print() {
		
		for (final Pattern p : policies.keySet()) {
			System.out.println("Resource Pattern="+p.toString());
			for (final PolicyStatement pstmt : policies.get(p)) {
				System.out.println("\t"+pstmt);
			}
		}
	}

}
