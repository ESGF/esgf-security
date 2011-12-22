/***************************************************************************
*                                                                          *
*  Organization: Earth System Grid Federation                              *
*                                                                          *
****************************************************************************
*                                                                          *
*   Copyright (c) 2009, Lawrence Livermore National Security, LLC.         *
*   Produced at the Lawrence Livermore National Laboratory                 *
*   LLNL-CODE-420962                                                       *
*                                                                          *
*   All rights reserved. This file is part of the:                         *
*   Earth System Grid (ESG) Data Node Software Stack, Version 1.0          *
*                                                                          *
*   For details, see http://esg-repo.llnl.gov/esg-node/                    *
*   Please also read this link                                             *
*    http://esg-repo.llnl.gov/LICENSE                                      *
*                                                                          *
*   * Redistribution and use in source and binary forms, with or           *
*   without modification, are permitted provided that the following        *
*   conditions are met:                                                    *
*                                                                          *
*   * Redistributions of source code must retain the above copyright       *
*   notice, this list of conditions and the disclaimer below.              *
*                                                                          *
*   * Redistributions in binary form must reproduce the above copyright    *
*   notice, this list of conditions and the disclaimer (as noted below)    *
*   in the documentation and/or other materials provided with the          *
*   distribution.                                                          *
*                                                                          *
*   Neither the name of the LLNS/LLNL nor the names of its contributors    *
*   may be used to endorse or promote products derived from this           *
*   software without specific prior written permission.                    *
*                                                                          *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS    *
*   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT      *
*   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS      *
*   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL LAWRENCE    *
*   LIVERMORE NATIONAL SECURITY, LLC, THE U.S. DEPARTMENT OF ENERGY OR     *
*   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,           *
*   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT       *
*   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF       *
*   USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND    *
*   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,     *
*   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT     *
*   OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     *
*   SUCH DAMAGE.                                                           *
*                                                                          *
***************************************************************************/
package esg.common.security;

import esg.common.generated.security.*;
import esg.common.util.ESGFProperties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;
import java.util.Properties;
import java.util.Set;
import java.util.HashSet;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

/**
   Description:

   Object used to load policy xml descriptor files, manipulate policy
   information and save the policy information back to descriptor
   file.

**/
public class PolicyGleaner {

    private static final Log log = LogFactory.getLog(PolicyGleaner.class);
    private static final String policyFile = "esgf_policies.xml";
    private String policyPath = null;
    private Properties props = null;
    private String stringOutput = "<oops>";

    private Set<PolicyWrapper> policySet = null;
    private Policies myPolicy = null;
    private boolean dirty = false;


    public PolicyGleaner() { this(null); }
    public PolicyGleaner(Properties props) {
        this.props = props;
        this.init();
    }

    public void init() {
        try {
            if(props == null) this.props = new ESGFProperties();
        } catch(Exception e) {
            log.error(e);
        }
        // /usr/local/tomcat/webapps/esgf-security/WEB-INF/classes/esg/security/config/
        policyPath = props.getProperty("security.app.home",".")+File.separator+"WEB-INF"+File.separator+"classes"+File.separator+"esg"+File.separator+"security"+File.separator+"config"+File.separator;

        policySet = new HashSet<PolicyWrapper>();
    }


    public Policies getMyPolicy() { return myPolicy; }

    public synchronized PolicyGleaner loadMyPolicy() { return this.loadMyPolicy(policyPath+policyFile); }
    public synchronized PolicyGleaner loadMyPolicy(String filename) {
        log.info("Loading my policy info from "+filename);
        try{
            JAXBContext jc = JAXBContext.newInstance(Policies.class);
            Unmarshaller u = jc.createUnmarshaller();
            JAXBElement<Policies> root = u.unmarshal(new StreamSource(new File(filename)),Policies.class);
            myPolicy = root.getValue();
            int count = 0;
            for(Policy policy : myPolicy.getPolicy()) { policySet.add(new PolicyWrapper(policy)); count++; } //dedup
            log.trace("Unmarshalled ["+myPolicy.getPolicy().size()+"] policies - Inspected ["+count+"] polices - resulted in ["+policySet.size()+"] policies");
            dirty=true;
        }catch(Exception e) {
            throw new ESGFPolicyException("Unable to properly load local policy from ["+filename+"]", e);
        }
        return this;
    }

    public synchronized boolean savePolicy() { return savePolicyAs(myPolicy,policyPath+policyFile); }
    public synchronized boolean savePolicy(Policies policy)   { return savePolicyAs(policy, policyPath+policyFile); }
    public synchronized boolean savePolicyAs(String location) { return savePolicyAs(myPolicy, location); }
    public synchronized boolean savePolicyAs(Policies policy, String policyFileLocation) {
        boolean success = false;
        if (policy == null) {
            log.error("Sorry internal policy representation is null ? ["+policy+"] perhaps you need to load policy file first?");
            return success;
        }
        log.info("Saving policy information to "+policyFileLocation);
        try{
            JAXBContext jc = JAXBContext.newInstance(Policies.class);
            Marshaller m = jc.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            m.marshal(policy, new FileOutputStream(policyFileLocation));
            success = true;
            dirty=false;
        }catch(Exception e) {
            log.error(e);
        }
        return success;
    }

    //--------------------------
    //Policy manipulation methods
    //--------------------------

    public PolicyGleaner addPolicy(String resource, String groupName, String roleName, String action) {
        dirty=true;
        Policy p = new Policy();
        p.setResource(resource);
        p.setAttributeType(groupName);
        p.setAttributeValue(roleName);
        p.setAction(action);
        policySet.add(new PolicyWrapper(p));
        return this;
    }

    public PolicyGleaner removePolicy(String resource, String groupName, String roleName, String action) {
        dirty=true;
        Policy p = new Policy();
        p.setResource(resource);
        p.setAttributeType(groupName);
        p.setAttributeValue(roleName);
        p.setAction(action);
        policySet.remove(new PolicyWrapper(p));
        return this;
    }

    public PolicyGleaner removeAllForGroup(String groupName) {
        dirty=true;
        log.trace("Removing all policies with group = "+groupName);
        Set<PolicyWrapper> delSet = new HashSet<PolicyWrapper>();
        for(PolicyWrapper policyWrapper : policySet) {
            if(policyWrapper.getPolicy().getAttributeType().equals(groupName)) {
                delSet.add(policyWrapper);
                log.trace("Removing policy: "+policyWrapper);
            }
        }
        if(policySet.removeAll(delSet)) { log.trace("ok"); } else { log.trace("nope"); }
        return this;
    }

    public PolicyGleaner remoteAllForRole(String roleName) {
        dirty=true;
        log.trace("Removing all policies with role = "+roleName);
        Set<PolicyWrapper> delSet = new HashSet<PolicyWrapper>();
        for(PolicyWrapper policyWrapper : policySet) {
            if(policyWrapper.getPolicy().getAttributeValue().equals(roleName)) {
                delSet.add(policyWrapper);
                log.trace("Removing policy: "+policyWrapper);
            }
        }
        if(policySet.removeAll(delSet)) { log.trace("ok"); } else { log.trace("nope"); }
        return this;
    }

    public PolicyGleaner removeAllForAction(String action) {
        dirty=true;
        log.trace("Removing all policies with action = "+action);
        Set<PolicyWrapper> delSet = new HashSet<PolicyWrapper>();
        for(PolicyWrapper policyWrapper : policySet) {
            if(policyWrapper.getPolicy().getAction().equals(action)) {
                delSet.add(policyWrapper);
                log.trace("Removing policy: "+policyWrapper);
            }
        }
        if(policySet.removeAll(delSet)) { log.trace("ok"); } else { log.trace("nope"); }
        return this;
    }

    public PolicyGleaner commit() {
        dirty=true;
        myPolicy.getPolicy().clear();
        for(PolicyWrapper policyWrapper : policySet) {
            log.trace("preparing to commit: \n"+policyWrapper);
            myPolicy.getPolicy().add(policyWrapper.getPolicy());
        }
        log.trace("commit done");
        return this;
    }
    
    public int size() { return policySet.size(); }
    public PolicyGleaner clear() { policySet.clear(); myPolicy.getPolicy().clear(); return this; }

    public String toString() { return this.toString(false); }
    public String toString(boolean force) {
        if(dirty || force) {
            StringBuffer sb = new StringBuffer("Policies: ");
            for(PolicyWrapper policyWrapper : policySet) {
                sb.append(policyWrapper.toString());
            }
            stringOutput = sb.toString();
        }
        dirty=false;
        return stringOutput;
    }
    
    class PolicyWrapper {
        Policy policy = null;
        final String outputString;
        PolicyWrapper(Policy policy) {
            this.policy = policy;
            StringBuffer sb = new StringBuffer("policy: ");
            sb.append("["+policy.getResource()+"] [");
            sb.append("g["+policy.getAttributeType()+"] [");
            sb.append("r["+policy.getAttributeValue()+"] [");
            sb.append("a["+policy.getAction()+"]");
            outputString = sb.toString();
        }

        Policy getPolicy() { return policy; }
        
        public boolean equals(Object o) {
            if(!(o instanceof PolicyWrapper)) return false;
            return outputString.equals(o.toString());
        }
        public int hashCode() {
            return outputString.hashCode();
        }
        public String toString() {
            return outputString;
        }
    }

    //--------------------------
    //Main: For quick testing...
    //--------------------------
    public static void main(String[] args) {
        PolicyGleaner pGleaner = null;

        //pGleaner.add(".*test.*", "superGroup", "boss", "Write");
        //pGleaner.commit().savePolicyAs("test_policy.out");

        if(args.length > 0) {
            if(args[0].equals("load")) {
                System.out.println(args[0]+"ing...");
                pGleaner = new PolicyGleaner();
                if(args.length == 2) {
                    if(args[1].equals("default")) {
                        System.out.println(pGleaner.loadMyPolicy());
                    }else {
                        System.out.println(pGleaner.loadMyPolicy(args[1]));
                    }
                    //Do some manipulation here...
                    //And show it...
                }
                if(args.length == 3) {
                    pGleaner.savePolicyAs(args[2]);
                }else{
                    pGleaner.savePolicy();
                }
            }else {
                System.out.println("illegal arg: "+args[0]);
            }
        }
    }

}