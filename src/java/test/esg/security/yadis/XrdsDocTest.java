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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.SAXException;

import esg.security.yadis.exceptions.XrdsParseException;

public class XrdsDocTest {
	@Test
	@Ignore
	public void testParseDoc() throws ParserConfigurationException, 
		SAXException, 
		IOException, XPathExpressionException, XrdsParseException {
		
		URL url = this.getClass().getResource("yadis.xml");
		Assert.assertTrue("Yadis file not found", url != null);
		File yadisDocFile = new File(url.getFile());
		XrdsDoc yadisParser = new XrdsDoc();
		StringBuffer contents = new StringBuffer();

		FileReader fileReader = new FileReader(yadisDocFile);
		BufferedReader in = new BufferedReader(fileReader); 
		try 
		{ 		
			String text = null;

			while ((text = in.readLine()) != null)
			{ 
				contents.append(text);
				contents.append(System.getProperty("line.separator"));
			} 
			in.close(); 
		} 
		catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } 
		catch (IOException e)
        {
            e.printStackTrace();
        } 
        finally
        {
            try
            {
                if (in != null)
                {
                    in.close();
                }
            } catch (IOException e)
            {
                e.printStackTrace();
            }
        }
         
		String yadisDocContent = contents.toString();		
		List<XrdsServiceElem> serviceElems = yadisParser.parse(yadisDocContent);
		Assert.assertEquals(serviceElems.toArray().length, 3);
		for (XrdsServiceElem elem : serviceElems) {
			Assert.assertEquals(elem.getLocalId(), 
					"https://somewhere.ac.uk/openid/PJKershaw");
		}
	}

}
