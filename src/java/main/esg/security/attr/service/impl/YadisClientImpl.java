package esg.security.attr.service.impl;

import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;

import esg.security.attr.service.api.YadisClient;
import esg.security.utils.http.HttpUtils;
import esg.security.utils.xml.Parser;

public class YadisClientImpl implements YadisClient {
    
    private final Namespace xrins = Namespace.getNamespace("xri://$xrd*($v*2.0)");
    
    private final Log LOG = LogFactory.getLog(this.getClass());

    @Override
    /*
     * Example Yadis document:
         <?xml version="1.0" encoding="UTF-8"?>
            <xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
              <XRD>
                <Service priority="0">
                  <Type>http://specs.openid.net/auth/2.0/signon</Type>
                  <Type>http://openid.net/signon/1.0</Type>
                  <Type>http://openid.net/srv/ax/1.0</Type>
                  <URI>https://esg-datanode.jpl.nasa.gov/esgf-idp/idp/openidServer.htm</URI>
                  <LocalID>https://esg-datanode.jpl.nasa.gov/esgf-idp/openid/lucacinquini</LocalID>
                </Service>
                <Service priority="1">
                  <Type>urn:esg:security:myproxy-service</Type>
                  <URI>socket://esg-datanode.jpl.nasa.gov:7512</URI>
                  <LocalID>https://esg-datanode.jpl.nasa.gov/esgf-idp/openid/lucacinquini</LocalID>
                </Service>
                <Service priority="2">
                  <Type>urn:esg:security:attribute-service</Type>
                  <URI>https://esg-datanode.jpl.nasa.gov/esgf-idp/saml/soap/secure/attributeService.htm</URI>
                  <LocalID>https://esg-datanode.jpl.nasa.gov/esgf-idp/openid/lucacinquini</LocalID>
                </Service>
              </XRD>
         </xrds:XRDS>
    */
    public String getServiceUri(String openid, String serviceType) throws Exception {
        
        String yadisxml = HttpUtils.get(openid, new HashMap<String, String>());
        if (LOG.isDebugEnabled()) LOG.debug("Yadis document: "+yadisxml);
        
        final Document doc = Parser.StringToJDOM(yadisxml, false);
        Element root = doc.getRootElement();
        
        for (Object xrdEl : root.getChildren("XRD", xrins)) {
            
            // loop over service elements
            for (Object serviceEl : ((Element)xrdEl).getChildren("Service", xrins)) {
                Element typeEl = (Element)((Element)serviceEl).getChild("Type", xrins);
                if (typeEl.getTextNormalize().equals(serviceType)) {
                    Element uriEl = (Element)((Element)serviceEl).getChild("URI", xrins);
                    return uriEl.getTextNormalize();
                }
            }
            
        }
        
        return null;
    }

}
