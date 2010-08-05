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
package esg.saml.utils.xml;

import java.io.File;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.Document;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.Assert;

/**
 * Utility class to compare two XML documents.
 */
public class XmlChecker {
	
	private static final Log LOG = LogFactory.getLog(XmlChecker.class);
	
	/**
	 * Method to verify that an XML document equals an expected XML file.
	 * @param jdoc : XML document to be checked.
	 * @param filepath : classpath location of reference XML document.
	 */
	public static void compare(final Document jdoc, final String fileclasspath) throws IOException, JDOMException {
		LOG.debug( "\n"+Serializer.JDOMtoString(jdoc, true) );
		final File file = new ClassPathResource(fileclasspath).getFile();
		final Document expected = Parser.toJDOM(file.getAbsolutePath(),false);
		//Serializer.JDOMout(jdoc);
		Assert.isTrue(Serializer.JDOMtoString(expected).equals(Serializer.JDOMtoString(jdoc)), "XML documents are different");
	}
	
	/**
	 * Method to verify that an XML document equals an expected XML file.
	 * @param xml : XML document to be checked, serialized as a string.
	 * @param filepath : classpath location of reference XML document.
	 */
	public static void compare(final String xml, final String fileclasspath) throws IOException, JDOMException {
		final Document jdoc = Parser.StringToJDOM(xml, false);
		compare(jdoc, fileclasspath);
	}

}
