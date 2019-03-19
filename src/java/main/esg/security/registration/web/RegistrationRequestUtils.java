package esg.security.registration.web;

import java.io.IOException;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;

import esg.security.common.SAMLParameters;
import esg.security.utils.xml.Parser;
import esg.security.utils.xml.Serializer;

/**
 * Class to serialize/deserialize a registration request to/from XML.
 * 
 * @author Luca Cinquini
 *
 */
public class RegistrationRequestUtils {
    
    /**
     * Method to encode a registration request into XML.
     * 
     * @return
     * @throws JDOMException
     */
    public static String serialize(String user, String group, String role) throws JDOMException {
        
        final Element rootEl = new Element("registrationRequest", SAMLParameters.NAMESPACE_ESGF);
        
        // <user>....</user>
        final Element userEl = new Element("user",SAMLParameters.NAMESPACE_ESGF);
        userEl.setText(user);
        rootEl.addContent(userEl);
        
        // <group>....</group>
        final Element groupEl = new Element("group",SAMLParameters.NAMESPACE_ESGF);
        groupEl.setText(group);
        rootEl.addContent(groupEl);

        // <role>....</role>
        final Element roleEl = new Element("role",SAMLParameters.NAMESPACE_ESGF);
        roleEl.setText(role);
        rootEl.addContent(roleEl);

        return Serializer.JDOMtoString(rootEl);
        
    }
    
    /**
     * Method to extract information from a registration request encoded as XML.
     * 
     * @param xml
     * @return String[] containing the requested user, group and role (in this order)
     * @throws IOException
     * @throws JDOMException
     */
    public static String[] deserialize(String xml) throws IOException, JDOMException {
        
        final String[] request = new String[3];
        final Document doc = Parser.StringToJDOM(xml, false);
        final Element root = doc.getRootElement();
        
        // <user>....</user>
        final Element userEl = (Element)root.getChild("user", SAMLParameters.NAMESPACE_ESGF);
        request[0] = userEl.getTextTrim();
        
        // <group>....</group>
        final Element groupEl = (Element)root.getChild("group", SAMLParameters.NAMESPACE_ESGF);
        request[1] = groupEl.getTextTrim();
        
        // <role>....</role>
        final Element roleEl = (Element)root.getChild("role", SAMLParameters.NAMESPACE_ESGF);
        request[2] = roleEl.getTextTrim();
       
        return request;
        
    }

}
