package esg.security.policy.web;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;

import esg.security.common.SAMLParameters;
import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.impl.PolicyAttributeImpl;
import esg.security.utils.xml.Parser;
import esg.security.utils.xml.Serializer;

/**
 * Utility class for XML serialization/deserialization of policy attributes.
 * 
 * Example XML documents:
 * 
 * <esgf:policies xmlns:esgf="http://www.esgf.org/">
 *    <esgf:policy type="Test Attribute" value="User">
 *       <esgf:registrationUrl>https://localhost:8443/esgf-security/saml/soap/secure/attributeService.htm</esgf:registrationUrl>
 *    </esgf:policy>
 *    <esgf:policy type="ANY" value="" />
 * </esgf:policies>
 * 
 * <esgf:policies xmlns:esgf="http://www.esgf.org/">
 *    <esgf:policy type="CMIP5 Research" value="User">
 *       <esgf:registrationUrl>https://esg-datanode.jpl.nasa.gov/esgf-security/saml/soap/secure/attributeService.htm</esgf:registrationUrl>
 *       <esgf:registrationUrl>https://esgf-node1.llnl.gov/esgf-security/saml/soap/secure/attributeService.htm</esgf:registrationUrl>
 *    </esgf:policy>
 * </esgf:policies>
 * 
 * @author Luca Cinquini
 *
 */
public class PolicySerializer {
        
    /**
     * Method to serialize a list of policy attributes to XML.
     * @param attributes
     * @return
     * @throws JDOMException
     */
    public final static String serialize(Map<PolicyAttribute, List<URL>> policyAttributeMap) throws JDOMException {
        
        final Element rootEl = new Element("policies", SAMLParameters.NAMESPACE_ESGF);
        
        for (final PolicyAttribute pa : policyAttributeMap.keySet()) {
           
            final Element paEl = new Element("policy", SAMLParameters.NAMESPACE_ESGF);
            paEl.setAttribute("type", pa.getType());
            paEl.setAttribute("value", pa.getValue());
            rootEl.addContent(paEl);
            
            // insert endpoints
            for (final URL url : policyAttributeMap.get(pa)) {
                final Element urlEl = new Element("registrationUrl", SAMLParameters.NAMESPACE_ESGF);
                urlEl.setText(url.toString());
                paEl.addContent(urlEl);
            }
            
        }
        
        return Serializer.JDOMtoString(rootEl);
        
    }
    
    /**
     * Method to extract the list of policy attributes from an XML document,
     * and the corresponding registratio URLs.
     * @param xml
     * @return
     * @throws IOException
     * @throws JDOMException
     */
    public final static Map<PolicyAttribute, List<URL>> deserialize(String xml) throws IOException, JDOMException {
                
        final Map<PolicyAttribute, List<URL>> policyAttributeMap = new LinkedHashMap<PolicyAttribute, List<URL>>();
        
        final Document doc = Parser.StringToJDOM(xml, false);
        final Element root = doc.getRootElement();
        for (Object obj : root.getChildren("policy", SAMLParameters.NAMESPACE_ESGF) ) {
            Element att = (Element)obj;
            final PolicyAttribute pa = new PolicyAttributeImpl(att.getAttributeValue("type"), att.getAttributeValue("value"));
            List<URL> endpoints = new ArrayList<URL>();
            for (final Object cobj : att.getChildren("registrationUrl", SAMLParameters.NAMESPACE_ESGF)) {
                Element urlEl = (Element)cobj;
                endpoints.add( new URL(urlEl.getText()) );
            } 
            policyAttributeMap.put(pa, endpoints);
        }
        
        return policyAttributeMap;
        
    }

}
