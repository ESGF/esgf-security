package esg.security.attr.service.impl;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

import esg.security.attr.service.api.AttributeServiceClient;
import esg.security.attr.service.api.FederatedAttributeService;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.registry.service.api.RegistryService;

public class FederatedAttributeServiceImpl implements FederatedAttributeService {
    
    private final Log LOG = LogFactory.getLog(this.getClass());
    
    /**
     * Service responsible for locating all Attribute Services across the federation.
     */
    private final RegistryService registryService;
    
    /**
     * Client responsible for querying the remote Attribute Services.
     */
    private final AttributeServiceClient client;

    public FederatedAttributeServiceImpl(final String issuer, final RegistryService registryService) {
        
        this.registryService = registryService;
        
        this.client = new AttributeServiceClientImpl(issuer);

    }

    @Override
    public Map<String, Set<String>> getAttributes(String identifier) throws Exception {
        
        if (LOG.isInfoEnabled()) LOG.info("Retrieving attributes for user="+identifier);
                
        // all attributes (name, description) retrieved from esg_ats.xml and esgf_ats_static.xml
        final Map<String, String> attributes = registryService.getAttributes();
        // always request no attributes - i.e. ALL attributes
        final Set<String> requestedAttributeTypes = new HashSet<String>();
        // global list used to avoid double invocations (if more than one attribute is served by the same attribute service)
        final List<String> _urls = new ArrayList<String>();
        // list of client threads, one for each remote attribute service to be queried
        List<ClientThread> threads = new ArrayList<ClientThread>();
        
        // loop over attribute types
        for (final String atype : attributes.keySet()) {
            
            final List<URL> aservices = registryService.getAttributeServices(atype);
            
            // loop over attribute services for that type
            for (final URL url : aservices) {
                String _url = url.toString();
                // don't query the same URL twice
                if (!_urls.contains(_url)) {
                    _urls.add(_url);
                    
                    ClientThread clientThread = new ClientThread(url, identifier, requestedAttributeTypes);
                    clientThread.start();
                    threads.add(clientThread);
                                        
                }
            }
            
        }
        
        // wait for all threads to finish
        for (Thread thread : threads) {
            thread.join();
        }
        
        // global user attributes map
        final Map<String, Set<String>> map = new HashMap<String, Set<String>>();

        // combine all retrieved SAML attributes
        for (ClientThread thread : threads) {            
            final SAMLAttributes samlAttributes = thread.getSAMLAttributes();
            final Map<String,Set<String>> _map = samlAttributes.getAttributes();
            for (String key : _map.keySet()) {
                for (String value : _map.get(key)) {
                    if (StringUtils.hasText(value)) {
                        if (!map.containsKey(key)) {
                            map.put(key, new HashSet<String>());
                        }
                        map.get(key).add(value);
                    }
                }
            }
        }
        
        return map;
    }
    
    /**
     * Helper class that queries a remote Attribute Service in a separate thread,
     * and stores the resulting SAML attributes for further access.
     * 
     * @author Luca Cinquini
     *
     */
    private class ClientThread extends Thread {
        
        private final URL url;
        private final String identifier;
        private final Set<String> requestedAttributeTypes;
        
        private SAMLAttributes samlAttributes = null;
        
        
        public ClientThread(final URL url, final String identifier, final Set<String> requestedAttributeTypes) {
            this.url = url;
            this.identifier = identifier;
            this.requestedAttributeTypes = requestedAttributeTypes;
        }
        
        public void run() {
            this.samlAttributes = client.getAttributes(url, identifier, requestedAttributeTypes);
        }

        public SAMLAttributes getSAMLAttributes() {
            return samlAttributes;
        }  
        
    }

}
