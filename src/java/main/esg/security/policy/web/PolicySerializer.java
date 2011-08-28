package esg.security.policy.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.Namespace;

import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.impl.PolicyAttributeImpl;
import esg.security.utils.xml.Parser;
import eske.utils.xml.Serializer;

/**
 * Utility class for XML serialization/deserialization of policy attributes.
 * 
 * @author Luca Cinquini
 *
 */
public class PolicySerializer {
    
    // XML namespace
    public final static Namespace NAMESPACE_ESGF = Namespace.getNamespace("esgf","http://www.esgf.org/");  
    
    /**
     * Method to serialize a list of policy attributes to XML.
     * @param attributes
     * @return
     * @throws JDOMException
     */
    public final static String serialize(List<PolicyAttribute> attributes) throws JDOMException {
        
        final Element rootEl = new Element("policies", NAMESPACE_ESGF);
        
        for (final PolicyAttribute pa : attributes) {
            final Element paEl = new Element("policy", NAMESPACE_ESGF);
            paEl.setAttribute("type", pa.getType());
            paEl.setAttribute("value", pa.getValue());
            rootEl.addContent(paEl);
        }
        
        return Serializer.JDOMtoString(rootEl);
        
    }
    
    /**
     * Method to extract the list of policy attributes from an XML document.
     * @param xml
     * @return
     * @throws IOException
     * @throws JDOMException
     */
    public final static List<PolicyAttribute> deserialize(String xml) throws IOException, JDOMException {
                
        final List<PolicyAttribute> attributes = new ArrayList<PolicyAttribute>();
        
        final Document doc = Parser.StringToJDOM(xml, false);
        final Element root = doc.getRootElement();
        for (Object obj : root.getChildren("policy", NAMESPACE_ESGF) ) {
            Element att = (Element)obj;
            attributes.add(new PolicyAttributeImpl(att.getAttributeValue("type"), att.getAttributeValue("value")));
        }
        
        return attributes;
        
    }

}
