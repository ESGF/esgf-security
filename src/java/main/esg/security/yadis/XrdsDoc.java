/**
 * eXtensible Resource Descriptor class adapted from 
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
 * $Id: XrdsDoc.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.yadis;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Entity;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.ErrorHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.security.yadis.exception.XrdsParseException;


public class XrdsDoc {
    private static final Log _log = LogFactory.getLog(XrdsDoc.class);
    private static final boolean DEBUG = _log.isDebugEnabled();
    
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

    public static final String XRDS_SCHEMA = "xrds.xsd";
    public static final String XRD_SCHEMA = "xrd.xsd";
    public static final String XRD_NS = "xri://$xrd*($v*2.0)";
    public static final String XRD_ELEM_XRD = "XRD";
    public static final String XRD_ELEM_TYPE = "Type";
    public static final String XRD_ELEM_URI = "URI";
    public static final String XRD_ELEM_LOCALID = "LocalID";
    public static final String XRD_ELEM_CANONICALID = "CanonicalID";
    public static final String XRD_ATTR_PRIORITY = "priority";
    public static final String OPENID_NS = "http://openid.net/xmlns/1.0";
    public static final String OPENID_ELEM_DELEGATE = "Delegate";
      
    protected Document parseXmlInput(String input) throws XrdsParseException
    {
        if (input == null)
            throw new XrdsParseException("No XML message set");

        try
        {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setValidating(true);
            dbf.setAttribute(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
            dbf.setAttribute(JAXP_SCHEMA_SOURCE, new Object[] {
                this.getClass().getResourceAsStream(XRD_SCHEMA),
                this.getClass().getResourceAsStream(XRDS_SCHEMA),
            });
            DocumentBuilder builder = dbf.newDocumentBuilder();
            builder.setErrorHandler(new ErrorHandler() {
                public void error(SAXParseException exception) throws SAXException {
                    throw exception;
                }

                public void fatalError(SAXParseException exception) throws SAXException {
                    throw exception;
                }

                public void warning(SAXParseException exception) throws SAXException {
                    throw exception;
                }
            });

            return builder.parse(new ByteArrayInputStream(input.getBytes()));
        }
        catch (ParserConfigurationException e)
        {
            throw new XrdsParseException("Parser configuration error", e);
        }
        catch (SAXException e)
        {
            throw new XrdsParseException("Error parsing XML document", e);
        }
        catch (IOException e)
        {
            throw new XrdsParseException("Error reading XRDS document", e);
        }
    }

    protected Map extractElementsByParent(String ns, String elem, Set parents, 
    		Document document)
    {
        Map result = new HashMap();
        NodeList nodes = document.getElementsByTagNameNS(ns, elem);
        Node node;
        for (int i = 0; i < nodes.getLength(); i++) {
            node = nodes.item(i);
            if (node == null || !parents.contains(node.getParentNode())) continue;

            String localId = node.getFirstChild() != null && 
            	node.getFirstChild().getNodeType() == Node.TEXT_NODE ?
                node.getFirstChild().getNodeValue() : null;

            result.put(node.getParentNode(), localId);
        }
        return result;
    }
    
    protected void addServiceType(Map serviceTypes, Node serviceNode, 
    		String type)
    {
        Set types = (Set) serviceTypes.get(serviceNode);
        if (types == null)
        {
            types = new HashSet();
            serviceTypes.put(serviceNode, types);
        }
        types.add(type);
    }

    protected int getPriority(Node node)
    {
        if (node.hasAttributes())
        {
            Node priority = node.getAttributes().getNamedItem(XRD_ATTR_PRIORITY);
            if (priority != null)
                return Integer.parseInt(priority.getNodeValue());
            else
                return XrdsServiceElem.LOWEST_PRIORITY;
        }

        return 0;
    }
    
    public List parse(String input, Set targetTypes) throws XrdsParseException
    {
        Document document = parseXmlInput(input);

        NodeList XRDs = document.getElementsByTagNameNS(XRD_NS, XRD_ELEM_XRD);
        Node lastXRD;
        if (XRDs.getLength() < 1 || 
        	(lastXRD = XRDs.item(XRDs.getLength() - 1)) == null)
            throw new XrdsParseException("No XRD elements found.");

        // get the canonical ID, if any (needed for XRIs)
        String canonicalId = null;
        Node canonicalIdNode;
        NodeList canonicalIDs = document.getElementsByTagNameNS(XRD_NS, 
        												XRD_ELEM_CANONICALID);
        for (int i = 0; i < canonicalIDs.getLength(); i++) {
            canonicalIdNode = canonicalIDs.item(i);
            if (canonicalIdNode.getParentNode() != lastXRD) continue;
            if (canonicalId != null)
                throw new XrdsParseException("More than one Canonical ID found.");
            canonicalId = canonicalIdNode.getFirstChild() != null && 
            	canonicalIdNode.getFirstChild().getNodeType() == Node.TEXT_NODE ?
                canonicalIdNode.getFirstChild().getNodeValue() : null;
        }

        // extract the services that match the specified target types
        NodeList types = document.getElementsByTagNameNS(XRD_NS, XRD_ELEM_TYPE);
        Map serviceTypes = new HashMap();
        Set selectedServices = new HashSet();
        Node typeNode, serviceNode;
        for (int i = 0; i < types.getLength(); i++) {
            typeNode = types.item(i);
            String type = typeNode != null && 
            	typeNode.getFirstChild() != null && 
            	typeNode.getFirstChild().getNodeType() == Node.TEXT_NODE ?
                typeNode.getFirstChild().getNodeValue() : null;
            if (type == null) continue;

            serviceNode = typeNode.getParentNode();

            if (targetTypes == null)
            	selectedServices.add(serviceNode);
            
            else if (targetTypes.contains(type))
                selectedServices.add(serviceNode);
            
            addServiceType(serviceTypes, serviceNode, type);
        }

        // extract local IDs
        Map serviceLocalIDs = extractElementsByParent(XRD_NS, XRD_ELEM_LOCALID, 
        		selectedServices, 
        		document);
        Map serviceDelegates = extractElementsByParent(OPENID_NS, 
        		OPENID_ELEM_DELEGATE, 
        		selectedServices, 
        		document);

        // build XrdsServiceEndpoints for all URIs in the found services
        List result = new ArrayList();
        NodeList uris = document.getElementsByTagNameNS(XRD_NS, XRD_ELEM_URI);
        Node uriNode;
        for (int i = 0; i < uris.getLength(); i++) {
            uriNode = uris.item(i);
            if (uriNode == null || 
            	!selectedServices.contains(uriNode.getParentNode())) 
            	continue;

            String uri = uriNode.getFirstChild() != null && 
            	uriNode.getFirstChild().getNodeType() == Node.TEXT_NODE ?
                uriNode.getFirstChild().getNodeValue() : null;

            serviceNode = uriNode.getParentNode();
            Set typeSet = (Set) serviceTypes.get(serviceNode);

            String localId = (String) serviceLocalIDs.get(serviceNode);
            String delegate = (String) serviceDelegates.get(serviceNode);

            XrdsServiceElem endpoint = new XrdsServiceElem(uri, 
            		typeSet, getPriority(serviceNode), getPriority(uriNode), 
            		localId, delegate, canonicalId);
            result.add(endpoint);
        }

        Collections.sort(result);
        return result;
    }
    
    // Parse Yadis document extracting the given target types
    public List parse(String yadisDocContent) throws XrdsParseException
    {
    	return parse(yadisDocContent, null);
    }
    
	/**
	 * TODO: move this test harness to unit tests
	 * @param args
	 * @throws IOException 
	 * @throws SAXException 
	 * @throws ParserConfigurationException 
	 * @throws XPathExpressionException 
	 * @throws XrdsParseException 
	 */
	public static void main(String[] args) throws ParserConfigurationException, 
		SAXException, 
		IOException, XPathExpressionException, XrdsParseException {
				        
        String yadisDocFilePath = "/home/pjkersha/workspace/EsgYadisParser/data/yadis.xml";
		XrdsDoc yadisParser = new XrdsDoc();
		StringBuffer contents = new StringBuffer();

		FileReader fileReader = new FileReader(yadisDocFilePath);
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
		yadisParser.parse(yadisDocContent);
	}
}
