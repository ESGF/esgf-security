package esg.security.attr.main;

import java.util.Map;
import java.util.Set;

import esg.security.attr.service.api.FederatedAttributeService;
import esg.security.attr.service.impl.FederatedAttributeServiceImpl;
import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.impl.RegistryServiceLocalXmlImpl;
import esg.security.utils.ssl.CertUtils;

/**
 * Example client to test a {@link FederatedAttributeService}.
 * @author Luca Cinquini
 *
 */
public class FederatedAttributeServiceClient {

    public final static void main(String[] args) throws Exception {
        
        // set certificates for client-server handshake
        CertUtils.setTruststore("/Users/cinquini/myApplications/apache-tomcat/esg-truststore.ts");
        CertUtils.setKeystore("/Users/cinquini/myApplications/apache-tomcat/esg-datanode-rapidssl.ks");
        
        // initialize service
        final String ESGF_ATS = "/esg/config/esgf_ats.xml";
        final RegistryService registryService = new RegistryServiceLocalXmlImpl(ESGF_ATS);
        final String issuer = "ESGF Attribute Service";
        final FederatedAttributeService self = new FederatedAttributeServiceImpl(issuer, registryService);
                
        // execute invocation
        String identifier = "https://esg-datanode.jpl.nasa.gov/esgf-idp/openid/lucacinquini";
        Map<String, Set<String>> attributes = self.getAttributes(identifier);
        for (String atype : attributes.keySet()) {
            for (String avalue : attributes.get(atype)) {
                System.out.println("ATTRIBUTE TYPE="+atype+" VALUE="+avalue);
            }
        }
        
    }

}
