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
package esg.security.utils.xml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Enumeration;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

import org.jdom2.Document;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.XMLOutputter;


/**
 * Utility class to parse input XML documents. It contains only static methods. 
 */
public class Parser {
	
	// XML parser of choice
	final static String parser = "org.apache.xerces.parsers.SAXParser";
	static SAXBuilder builder = null;  // shared instance
	
  /** Main method
   * 
   * @param xmlfile: local patgh or URL of XML file
   * @param validate: false to check XML well-formdness, true to perform schema validation
   * @return
   * @throws IOException
   * @throws JDOMException
   */
	public static void main(String[] args) throws JDOMException, IOException {
	  
		// input arguments
		if (args.length!=2) {
			System.out.println("USAGE: esg.security.utils.xml.Parser xmlURI validate");
			System.exit(-1);
		}
		String xmlUri = args[0];
		boolean validate = (Boolean.valueOf(args[1]).booleanValue());
		
		init(validate);
		Document doc = toJDOM(xmlUri);
		
	}
		
	/** Class initialization method instantiates a validating or non-validating
	 *  parser instance that may be shared by all succesive following calls  
	 *  @param validate : true to enable schema validation ,false otherwise
	 */
	public static synchronized void init(boolean validate) {
		if (builder==null) builder = getBuilder(validate);
	} // init()

  /**
   * Method to parse an input xml file and return a string representation
   * NOTE: this method uses the shared parser instance initialized by a previous init() call
   * @param xmlfile : local pathname or uri of XML file
   */
  public static String toString(String xmlfile) throws JDOMException, IOException {
    Document jdoc = toJDOM(xmlfile);
    XMLOutputter outputter = new XMLOutputter(org.jdom2.output.Format.getCompactFormat());
    return outputter.outputString(jdoc);
  } // toString()

  /**
   * Method to parse an input xml file and return a JDOM document
   * NOTE: this method uses the shared parser instance initialized by a previous init() call
   * @param xmlfile : local pathname or uri of XML file
   */
  public static Document toJDOM(String xmlfile) throws JDOMException, IOException {

     FileInputStream in = new FileInputStream( xmlfile );
     Document jdoc = builder.build( in );
     in.close();
     return jdoc;

  } // toJDOM()

  /**
   * Method to parse an input XML String and return a JDOM document
   * NOTE: this method uses the shared parser instance initialized by a previous init() call
   * @param xmlfile : XML serialized as String
   */
  public static Document StringToJDOM(String xmlstring) throws JDOMException, IOException {

     StringReader sr = new StringReader(xmlstring);
     Document jdoc =  builder.build(sr);
     sr.close();
     return jdoc;

  } // StringToJDOM()

  /**
   * Method to parse an input xml file and return a string representation
   * NOTE: this method uses the shared parser instance initialized by a previous init() call
   * @param xmlfile : local pathname or uri of XML file
   */
  public static String toString(String xmlfile, boolean validate) throws JDOMException, IOException {
    Document jdoc = toJDOM(xmlfile, validate);
    XMLOutputter outputter = new XMLOutputter(org.jdom2.output.Format.getCompactFormat());
    return outputter.outputString(jdoc);
  } // toString()

  /**
   * Method to parse an input xml file and return a JDOM document
   * @param xmlfile : local pathname or uri of XML file
   * @param validate : true to turn on schema validation
   */
  public static Document toJDOM(String xmlfile, boolean validate) throws JDOMException, IOException {

     SAXBuilder _builder = getBuilder(validate);
     FileInputStream in = new FileInputStream( xmlfile );
     Document jdoc = _builder.build( in );
     in.close();
     return jdoc;

  } // toJDOM()
  
  /**
   * Method to parse an input xml file retrieved with the class loader and return a JDOM document
   * @param xmlfile : name of XML file, located in classpath
   * @param validate : true to turn on schema validation
   */
  public static Document classpathToJDOM(String xmlfile, boolean validate) throws JDOMException, IOException {

     SAXBuilder _builder = getBuilder(validate);
     if (xmlfile.indexOf("classpath:")>=0) xmlfile = xmlfile.substring(10);  // remove "classpath:"
     InputStream in = (new Parser()).getClass().getClassLoader().getResourceAsStream(xmlfile);
     Document jdoc = _builder.build(in);
     in.close();
     return jdoc;

  } // classpathToJDOM()
  
  
  /**
   * Method to load an XML resource found in the classpath and return a JDOM document
   * @param filename  path of XML resource relative to classpath (starting with a '/'), for example: /somedir/somefile.xml
   * @param validate  true to turn on schema validation
   */
  public static Document classpathResourceToJDOM(String filename, boolean validate) throws JDOMException, IOException {
     SAXBuilder _builder = getBuilder(validate);     
     InputStream is = ClassLoader.getSystemClassLoader().getResource(filename).openStream();
     //InputStream is = new Object().getClass().getResourceAsStream (filename);
     Document jdoc = _builder.build( is );
     is.close();
     return jdoc;

  } // classpathResourceToJDOM()
  

  /**
   * Method to parse an input XML String and return a JDOM document
   * @param xmlfile : local pathname or uri of XML file
   * @param validate : true to turn on schema validation
   */
  public static Document StringToJDOM(String xmlstring, boolean validate) throws JDOMException, IOException {

     StringReader sr = new StringReader(xmlstring);
     SAXBuilder _builder = getBuilder(validate);
     Document jdoc =  _builder.build(sr);
     sr.close();
     return jdoc;

  } // StringToJDOM()
  
  /** Utility method to load and configure XML parser */
  private static SAXBuilder getBuilder(boolean validate) {
  	
    	SAXBuilder _builder = new SAXBuilder(parser, validate);
    _builder.setFeature("http://xml.org/sax/features/namespaces",true);
    _builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    _builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
    _builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    _builder.setExpandEntities(false);
    //  builder.setIgnoringElementContentWhitespace(true);
    
    // load schema locations
    if (validate) {
	    	_builder.setFeature("http://apache.org/xml/features/validation/schema",true);
	    ResourceBundle rb = PropertyResourceBundle.getBundle("ucar.xml.schemas");
	    Enumeration schemas = rb.getKeys();
	    StringBuffer sb = new StringBuffer();
	    while (schemas.hasMoreElements()) {
	    		String schema = (String)schemas.nextElement();
	    		String location = rb.getString(schema);
	    		sb.append(sb.length()>0 ? " " : "").append(schema).append(" ").append(location);
	    }
	    _builder.setProperty("http://apache.org/xml/properties/schema/external-schemaLocation", sb.toString());
 
	    //	cache grammars for subsequent reuse
	    //builder.setFeature("http://apache.org/xml/features/validation/cache-grammarFromParse",true);
    } // validate
    
    return _builder;
    
  } // getBuilder()

} // Parser

