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
/**
 * Class adapted from org.openid4java
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: Apache License 2.0
 * 
 * $Id: XrdsServiceElem.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.yadis;

import java.util.Set;


/**
 * Encapsulates the (OpenID-related) information extracted in
 * service elements discovered through Yadis.
 *
 * Note: this class has a natural ordering that is inconsistent with equals.
 * Only the URI priority and Service priority fields are used for comparison.
 *
 * @author jbufu
 */
public class XrdsServiceElem implements Comparable<Object> {

	    private int servicePriority;
	    private int uriPriority;
	    private Set<String> types;
	    private String uri;
	    private String localId;
	    private String delegate;
	    public static final int LOWEST_PRIORITY = -1;
	    private String canonicalId;

	    public XrdsServiceElem(String uri, Set<String> types,
	                       int servicePriority, int uriPriority, String localId, 
	                       String delegate, String canonicalId)
	    {
	        this.servicePriority = servicePriority;
	        this.uriPriority = uriPriority;
	        this.types = types;
	        this.uri = uri;
	        this.localId = localId;
	        this.delegate = delegate;
	        this.canonicalId = canonicalId;
	    }

	    public int getServicePriority() {
	        return servicePriority;
	    }

	    public void setServicePriority(int servicePriority) {
	        this.servicePriority = servicePriority;
	    }

	    public int getUriPriority() {
	        return uriPriority;
	    }

	    public void setUriPriority(int uriPriority) {
	        this.uriPriority = uriPriority;
	    }

	    public Set<String> getTypes() {
	        return types;
	    }

	    public void setTypes(Set<String> types) {
	        this.types = types;
	    }

	    public boolean matchesType(String type) {
	        return types != null && types.contains(type);
	    }

	    public String getUri() {
	        return uri;
	    }

	    public void setUri(String uri) {
	        this.uri = uri;
	    }

	    public String getLocalId() {
	        return localId;
	    }

	    public void setLocalId(String localId) {
	        this.localId = localId;
	    }

	    public String getDelegate() {
	        return delegate;
	    }

	    public void setDelegate(String delegate) {
	        this.delegate = delegate;
	    }

	    public String getCanonicalId() {
	        return canonicalId;
	    }

	    public void setCanonicalId(String canonicalId) {
	        this.canonicalId = canonicalId;
	    }

	    public int compareTo(Object o) {
	        XrdsServiceElem other = (XrdsServiceElem) o;

	        if (servicePriority == LOWEST_PRIORITY && 
	        	other.servicePriority != LOWEST_PRIORITY)
	            return 1;
	        if (other.servicePriority == LOWEST_PRIORITY && 
	        	servicePriority != LOWEST_PRIORITY)
	            return -1;
	        if (servicePriority < other.servicePriority) return -1;
	        if (servicePriority > other.servicePriority) return 1;

	        if (uriPriority == LOWEST_PRIORITY && 
	        	other.uriPriority != LOWEST_PRIORITY)
	            return 1;
	        if (other.uriPriority == LOWEST_PRIORITY && 
	        	uriPriority != LOWEST_PRIORITY)
	            return -1;
	        if (uriPriority < other.uriPriority) return -1;
	        if (uriPriority > other.uriPriority) return 1;

	        // XRI spec says the consumer should pick at random here
	        return 0;
	    }

	    public String toString() {
	        StringBuffer sb = new StringBuffer();
	        sb.append("Service priority: ").append(servicePriority);
	        sb.append("\nType: ").append(types.toString());
	        sb.append("\nURI: ").append(uri);
	        sb.append("\nURI Priority: ").append(uriPriority);
	        sb.append("\nLocalID: ").append(localId);
	        return sb.toString();
	    }
	}
