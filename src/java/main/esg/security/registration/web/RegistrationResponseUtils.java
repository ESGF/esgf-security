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
public class RegistrationResponseUtils {
    
    /**
     * Method to encode a registration response in XML.
     * 
     * @param outcome
     * @param message
     * @return
     * @throws JDOMException
     */
    public static String serialize(SAMLParameters.RegistrationOutcome outcome, String message) throws JDOMException {
        
        final Element rootEl = new Element("registrationResponse", SAMLParameters.NAMESPACE_ESGF);
        
        final Element resultEl = new Element("result",SAMLParameters.NAMESPACE_ESGF);
        resultEl.setText(outcome.toString());
        rootEl.addContent(resultEl);
        
        final Element messageEl = new Element("message",SAMLParameters.NAMESPACE_ESGF);
        messageEl.setText(message);       
        rootEl.addContent(messageEl);
        
        return Serializer.JDOMtoString(rootEl);
        
    }
    
    /**
     * Method to extract information from a registration response XML.
     * 
     * @param xml
     * @return
     */
    public static String deserialize(String xml) throws IOException, JDOMException {
        
        final Document doc = Parser.StringToJDOM(xml, false);
        final Element root = doc.getRootElement();
        Element result = (Element)root.getChild("result", SAMLParameters.NAMESPACE_ESGF);
        return result.getTextNormalize();
        
    }

}
