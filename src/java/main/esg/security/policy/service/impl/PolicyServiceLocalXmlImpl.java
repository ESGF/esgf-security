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
package esg.security.policy.service.impl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;
import esg.security.policy.service.api.PolicyStatement;
import esg.security.utils.xml.Parser;

/**
 * Implementation of {@link esg.security.policy.service.api.PolicyService} backed up by one or more local XML configuration files.
 * The XML files contain regular expressions matching the resource identifiers, and this service implementation will return
 * the policy statements for the first match found, for the given action. The local policy files are automatically reloaded if changed.
 * 
 * Note that this implementation disregards the case of the "action" parameter (i.e. "Read" and "read" are considered identical).
 * 
 * @author luca.cinquini
 *
 */
public class PolicyServiceLocalXmlImpl implements PolicyService {
	
	LinkedHashMap<Pattern, List<PolicyStatement>> policies = new LinkedHashMap<Pattern, List<PolicyStatement>>();
	
	// local XML files holding policy statements
    private final List<File> policyFiles = new ArrayList<File>();
    
    // latest modification time of all policy files
    long policyFilesLastModTime = 0L; // Unix Epoch
    
    private final Log LOG = LogFactory.getLog(this.getClass());
	
    /**
     * Constructor accepts a comma-separated list of one or more files.
     * Files can be specified with an absolute path (if starting with '/') or with a relative classpath (if not starting with '/').
     * 
     * @param xmlFilePaths
     * @throws Exception
     */
	public PolicyServiceLocalXmlImpl(final String xmlFilePaths) throws Exception {
		
	    // loop over all configured local XML files
        for (final String xmlFilePath : xmlFilePaths.split("\\s*,\\s*")) {
            if (LOG.isInfoEnabled()) LOG.info("Parsing XML file:"+xmlFilePath);
            // absolute path
            if (xmlFilePath.startsWith("/")) {
                policyFiles.add( new File(xmlFilePath) );
            // classpath relative path
            } else {
                policyFiles.add( new ClassPathResource(xmlFilePath).getFile() );
            }
        }
        update();

		
	}
	
	/** Method to update the local policy map by re-parsing the configured XML files.
	 *  This method disregards parsing errors from any single file, and moves on to parsing the next file.
	 */
    public void update() {
        
        // update only if files have changed
        long lastMod = this.getLastModified();
        if (lastMod > policyFilesLastModTime) {
            policyFilesLastModTime = lastMod;
                        
            // temporary storage for policy statements
            final LinkedHashMap<Pattern, List<PolicyStatement>> _policies = new LinkedHashMap<Pattern, List<PolicyStatement>>();
            
            // loop over policy files
            for (final File policyFile : policyFiles) {   

                try {
                    parseXml(policyFile, _policies);
                    if (LOG.isInfoEnabled()) LOG.info("Loaded information from policy file="+policyFile.getAbsolutePath()); 
                } catch(Exception e) {
                    LOG.warn("Error pasring XML policy file: "+policyFile.getAbsolutePath()+": "+e.getMessage());
                }
                
            }
            
            // update local data storage
            synchronized (policies) {
                policies = _policies;
            }
            print();
            
        }
                
    }

	@Override
	public List<PolicyAttribute> getRequiredAttributes(String resource, String action) {
	    
        // reload policies if needed
        update();        

		final List<PolicyAttribute> attributes = new ArrayList<PolicyAttribute>();
		
		for (final Pattern pattern : policies.keySet()) {
			Matcher matcher = pattern.matcher(resource);
			if (matcher.matches()) {
				for (final PolicyStatement pstmt : policies.get(pattern)) {
					if (pstmt.getAction().toString().equalsIgnoreCase(action)) {
						attributes.add(pstmt.getAttribute());
					}
				}
			}
		}
		
		return attributes;

	}
	
	/**
	 * Method to parse a single XML file containing policy statements into the given policy map.
	 * 
	 * @param file
	 * @param _policies
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws JDOMException
	 */
	void parseXml(final File file, final LinkedHashMap<Pattern, List<PolicyStatement>> _policies) throws MalformedURLException, IOException, JDOMException {
			    	    
		final Document doc = Parser.toJDOM(file.getAbsolutePath(), false);
		final Element root = doc.getRootElement();
		
		// must store additional map because Pattern does not re-implement hashCode()
		final Map<String, Pattern> patterns = new HashMap<String, Pattern>();
		
		for (final Object pol : root.getChildren("policy")) {
			final Element policy = (Element)pol;
			final String resource = policy.getAttributeValue("resource");
			final Pattern pattern = Pattern.compile(resource);
			if (patterns.get(resource)==null) {
				patterns.put(resource, pattern);
				_policies.put(pattern, new ArrayList<PolicyStatement>());
			}
			_policies.get(patterns.get(resource)).add(
			  		      new PolicyStatementImpl(policy.getAttributeValue("resource"), 
					    	 	                  policy.getAttributeValue("attribute_type"), 
					    		                  policy.getAttributeValue("attribute_value"),
					    		                  policy.getAttributeValue("action")) 
			);
		}
		
	}
	
	// debug method
	public void print() {
		
		for (final Pattern p : policies.keySet()) {
			System.out.println("Resource Pattern="+p.toString());
			for (final PolicyStatement pstmt : policies.get(p)) {
				System.out.println("\t"+pstmt);
			}
		}
	}

	/**
     * Method to return the last update time of all policy files
     * @return
     */
    private long getLastModified() {
        
        long lastModified = 0;
        for (final File file : policyFiles) {
            if (file.exists() && file.lastModified()>lastModified) {
                lastModified = file.lastModified();
            }
        }       
        return lastModified;
    }
    
}
