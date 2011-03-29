/**
 * Unit tests for eXtensible Resource Descriptor class adapted from 
 * org.openid4java.discovery.xrds.XrdsParserImpl
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: Apache License 2.0
 * 
 * @author pjkersha
 */
package esg.security.yadis;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.SAXException;

import org.springframework.core.io.ClassPathResource;
import org.apache.commons.io.IOUtils;

import esg.security.yadis.exceptions.XrdsParseException;

public class XrdsDocTest {	
	public static final String YADIS_FILEPATH = "esg/security/yadis/yadis.xml";
	
	@Test
//	@Ignore		
	public void testParseDoc() throws ParserConfigurationException, 
		SAXException, 
		IOException, XPathExpressionException, XrdsParseException {
		
		final InputStream yadisDocFile = new ClassPathResource(YADIS_FILEPATH).getInputStream();
		StringWriter writer = new StringWriter();
		IOUtils.copy(yadisDocFile, writer, "UTF-8");
		String yadisDocContent = writer.toString();
		
		XrdsDoc yadisParser = new XrdsDoc();
		
		List<XrdsServiceElem> serviceElems = yadisParser.parse(yadisDocContent);
		Assert.assertEquals(serviceElems.toArray().length, 3);
		for (XrdsServiceElem elem : serviceElems) {
			String localId = elem.getLocalId();
			if (localId != null) {
				Assert.assertEquals(elem.getLocalId(), 
						"https://openid.somewhere.ac.uk/PJKershaw");
			}
			Set<String> types = elem.getTypes();
			System.out.printf("Service: Priority=%d; Type=%s; URI=%s;\n", 
					elem.getServicePriority(),
					types.toString(),
					elem.getUri());
		}
	}

}
