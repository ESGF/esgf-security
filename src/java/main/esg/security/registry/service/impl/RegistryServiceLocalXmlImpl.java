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
package esg.security.registry.service.impl;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.Namespace;
import org.springframework.util.StringUtils;

import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.api.ReloadableFileSetObserver;
import esg.security.registry.service.api.UnknownPolicyAttributeTypeException;
import esg.security.utils.xml.Parser;

/**
 * Implementation of {@link RegistryService} backed up by one or more local XML configuration files.
 * This implementation automatically reloads its data if any of the underlying files have been updated.
 * 
 * @author luca.cinquini
 */
public class RegistryServiceLocalXmlImpl implements RegistryService, ReloadableFileSetObserver {
	
	// local storage of attribute type to attribute services mapping (one-to-many)
	private Map<String, List<URL>> attributeServices = new HashMap<String, List<URL>>();
	
	// local storage of attribute type to registration services mapping (one-to-many)
	private Map<String, List<URL>> registrationServices = new HashMap<String, List<URL>>();
	
	// local storage for identity provider endpoints
	private List<URL> identityProviders = new ArrayList<URL>();
	
    // local storage for authorization service endpoints
    private List<URL> authorizationServices = new ArrayList<URL>();
    
    // local storage for LAS servers IP addresses
    private List<String> lasServers = new ArrayList<String>();
    
    // local storage for Solr 
    // NOTE: preserve shards order!
    private LinkedHashSet<String> shards = new LinkedHashSet<String>();

	private final static Namespace NS = Namespace.getNamespace("http://www.esgf.org/whitelist");
	private final static Namespace NS2 = Namespace.getNamespace("http://www.esgf.org/registry");
	
	// Utility class that watches the set of local XML configuration files for changes.
	private ReloadableFileSet watcher;
	
	private final Log LOG = LogFactory.getLog(this.getClass());

	/**
	 * Constructor executes the first loading of the data into memory.
	 * @param xmlFilePath
	 * @throws Exception
	 */
	public RegistryServiceLocalXmlImpl(final String xmlFilePaths) throws Exception {
	    
	    // instantiate files watcher
	    watcher = new ReloadableFileSet(xmlFilePaths);
	    watcher.setObserver(this);
	    
	    // trigger first loading of configuration files
		watcher.reload();
	
	}

	/**
     * {@inheritDoc}
     */
    @Override
	public List<URL> getAttributeServices(final String attributeType) throws UnknownPolicyAttributeTypeException {
	    
	    // reload registry if needed
	    watcher.reload();        
	    
	    // look up the attribute type 
		if (attributeServices.containsKey(attributeType)) {
			return attributeServices.get(attributeType);
		} else {
			throw new UnknownPolicyAttributeTypeException("Cannot resolve attribute type="+attributeType);
		}
		
	}
    
    /**
     * {@inheritDoc}
     */
    @Override
    public List<URL> getRegistrationServices(final String attributeType) throws UnknownPolicyAttributeTypeException {
        
        // reload registry if needed
        watcher.reload();        
        
        // look up the attribute type 
        if (registrationServices.containsKey(attributeType)) {
            return registrationServices.get(attributeType);
        } else {
            throw new UnknownPolicyAttributeTypeException("Cannot resolve attribute type="+attributeType);
        }
        
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public List<URL> getAuthorizationServices()  {
        
        // reload registry if needed
        watcher.reload();        
        
        // return white list
        return Collections.unmodifiableList(authorizationServices);
        
    }
    
    
    /**
     * {@inheritDoc}
     */
	@Override
    public List<URL> getIdentityProviders() {
	    
        // reload registry if needed
        watcher.reload();        
        
        // return white list
        return Collections.unmodifiableList(identityProviders);
        
    }
	
    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getLasServers() {
        
        // reload registry if needed
        watcher.reload();        
        
        // return white list
        return Collections.unmodifiableList(lasServers);
        
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public LinkedHashSet<String> getShards() {
        
        // reload registry if needed
        watcher.reload();        
        
        // return white list
        return shards;
        
    }

    /**
	 * Method to parse the XML registry files into the local map of services.
	 * 
	 * This method prints a warning but does not stop or crashes if any of the files cannot be parsed,
	 * using the service endpoints from all the other files.
	 * 
	 * @param file
	 */
	public void parse(final List<File> registryFiles) {
	    
	    final Map<String, List<String>> _registrationServices = new HashMap<String, List<String>>();
	    boolean reloadRegistrationServices = false;
	    final Map<String, List<String>> _attributeServices = new HashMap<String, List<String>>();
	    boolean reloadAttributeServices = false;
	    final List<String> _identityProviders = new ArrayList<String>();
	    boolean reloadIdentityProviders = false;
	    final List<String> _authorizationServices = new ArrayList<String>();
	    boolean reloadAuthorizationServices = false;
	    final List<String> _lasServers = new ArrayList<String>();
	    boolean reloadLasServers = false;
	    final LinkedHashSet<String> _shards = new LinkedHashSet<String>();
	    boolean reloadShards = false;
	    
	    // loop over registry files
	    for (final File registryFile : registryFiles) {   
	        
	        if (LOG.isInfoEnabled()) LOG.info("Loading information from registry file="+registryFile.getAbsolutePath()); 
		        
	        try {
		
        		final Document doc = Parser.toJDOM(registryFile.getAbsolutePath(), false);
        		final Element root = doc.getRootElement();
        		    		
        		// parse Attribute Services section
        		if (root.getName().equals("ats_whitelist")) {
        		    reloadAttributeServices = true;
        		    reloadRegistrationServices = true;
        		        		    
            		for (final Object attr : root.getChildren("attribute", NS)) {
            			final Element _attr = (Element)attr;
            			final String aType = _attr.getAttributeValue("type");
            			
            			// attribute service
            			if (StringUtils.hasText(_attr.getAttributeValue("attributeService"))) {
                            if (_attributeServices.get(aType) == null) {
                                _attributeServices.put(aType, new ArrayList<String>());
                            }
                            this.addIfUnique(_attributeServices.get(aType), _attr.getAttributeValue("attributeService"));
            			    LOG.info("Added attribute service: "+_attr.getAttributeValue("attributeService"));
            			}
            			
            			// registration service
            			if (StringUtils.hasText(_attr.getAttributeValue("registrationService"))) {
                            if (_registrationServices.get(aType) == null) {
                                _registrationServices.put(aType, new ArrayList<String>());
                            }
                            this.addIfUnique(_registrationServices.get(aType), _attr.getAttributeValue("registrationService"));
            			    LOG.info("Added registration service: "+_attr.getAttributeValue("registrationService"));
            			}
            			
            		}
            		
            	// parse Identity Providers section
        		} else if (root.getName().equals("idp_whitelist")) {
        		    reloadIdentityProviders = true;
        		    
        		    for (final Object value : root.getChildren("value", NS)) {
        		        final Element element = (Element)value;       		        
        		        this.addIfUnique(_identityProviders, element.getText());
        		        LOG.info( "Added identity provider: "+ element.getText());
        		    }
        		    
        		// parse Authorization Services section
        		} else if (root.getName().equals("azs_whitelist")) {
        		    reloadAuthorizationServices = true;
        		    
                    for (final Object value : root.getChildren("value", NS)) {
                        final Element element = (Element)value;
                        this.addIfUnique(_authorizationServices, element.getText() );
                        LOG.info( "Added authorization service: "+ element.getText());
                    }
        		    
                // parse LAS servers section
        		} else if (root.getName().equals("las_servers")) {
        		    reloadLasServers = true;
        		    
                    for (final Object obj : root.getChildren("las_server", NS2)) {
                        final Element element = (Element)obj;                        
                        this.addIfUnique(_lasServers, element.getAttributeValue("ip"));
                        LOG.info("Added IP: "+  element.getAttributeValue("ip") );
                    }
        		    
                // parse Solr shards section
                } else if (root.getName().equals("shards")) {
                    reloadShards = true;
                    
                    for (final Object obj : root.getChildren("value", NS)) {
                        final Element element = (Element)obj;
                        _shards.add( element.getText() );
                        LOG.info("Added shard: "+  element.getText());
                    }
                    
                }
        		
                if (LOG.isInfoEnabled()) LOG.info("Loaded information from registry file="+registryFile.getAbsolutePath());    
	        
          } catch(Exception e) {
                LOG.warn("Error parsing registry XML file: "+e.getMessage());
          }
          
	    }
   		
        // update local data storage
	    if (reloadAttributeServices) {
	        synchronized (attributeServices) {
	            attributeServices = toURLs(_attributeServices);
	        }
	    }
	    if (reloadRegistrationServices) {
            synchronized (registrationServices) {
                registrationServices = toURLs(_registrationServices);
	            }
	    }
	    if (reloadIdentityProviders) {
    	    synchronized (identityProviders) {
                identityProviders = toURLs(_identityProviders);             
            }
	    }
	    if (reloadAuthorizationServices) {
            synchronized (authorizationServices) {
                authorizationServices = toURLs(_authorizationServices);             
            }
	    }
	    if (reloadLasServers) {
            synchronized (lasServers) {
                lasServers = _lasServers;             
            }
	    }
	    if (reloadShards) {
            synchronized (shards) {
                shards = _shards;             
            }               
	    }
        
		// print content
		this.print();
		
	}
	
	/**
	 * Method to add a URL only if it is not in the list already.
	 * Note that the comparison MUST be executed on String objects, not URLs:
	 * a URL comparison involves a live check of the URL itself, and takes forever...!
	 * 
	 * @param values
	 * @param value
	 */
	private void addIfUnique(final List<String> values, final String value) {
	    if (!values.contains(value)) values.add(value);
	}
	
	/**
	 * Utility method to convert a list of strings into a list of URLs.
	 * @param values
	 * @return
	 */
	private List<URL> toURLs(final List<String> values) {
	    final List<URL> urls = new ArrayList<URL>();
	    for (final String value : values) {
	        try {
	            urls.add(new URL(value));
	        } catch(MalformedURLException e) {
	            // skip this URL
	            LOG.warn(e.getMessage());
	        }
	    }
	    return urls;
	}
	
	/**
	 * Utility method to convert a map of strings into a map of URLs.
	 * @param map
	 * @return
	 */
	private Map<String, List<URL>> toURLs(final Map<String, List<String>> map) {
	    
	    final Map<String, List<URL>> urls = new HashMap<String, List<URL>>();
	    for (final String key : map.keySet()) {
	         urls.put(key, toURLs(map.get(key)) );
	    }
	    return urls;
	    
	}
		
	/**
	 * Method to dump the registry content to standard output
	 */
	void print() {
	    
	    // attribute services
	    for (final String aType : attributeServices.keySet()) {
	        if (LOG.isDebugEnabled()) LOG.debug("Attribute type="+aType+" Service URL="+attributeServices.get(aType));
	    }
	    
	    // identity providers
	    for (final URL idp : identityProviders) {
	        if (LOG.isDebugEnabled()) LOG.debug("Identity provider="+idp.toString());
	    }
	    
	}
	
}
