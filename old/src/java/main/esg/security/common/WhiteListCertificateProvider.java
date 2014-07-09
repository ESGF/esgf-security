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
package esg.security.common;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Class that can be used to enforce server-side white-listing
 * in any HTTPS communication that requires client authentication.
 * 
 * @author luca.cinquini
 */
public class WhiteListCertificateProvider {
	
	/**
	 * The configured white list of acceptable certificate subjects.
	 */
	private List<String> subjects;
	
	private final static String X509_ATTRIBUTE = "javax.servlet.request.X509Certificate";
	
	private final Log LOG = LogFactory.getLog(this.getClass());
	
	public WhiteListCertificateProvider(final List<String> subjects) {
		this.subjects = subjects;
	}
	
	/**
	 * Method to validate an HTTPS request containing a client certificate
	 * versus the configured white list of acceptable subjects.
	 * 
	 * @param subject
	 */
	public boolean validate(final HttpServletRequest request) {
		
		final X509Certificate[] certs = (X509Certificate[])request.getAttribute(X509_ATTRIBUTE);
		
		if (certs!=null && certs.length>0) {
			
			// set authentication attribute
			final X509Certificate cert = certs[0];
			final String principal = cert.getSubjectDN().getName();
			if (LOG.isInfoEnabled()) LOG.info("X509 client certificate="+cert+" principal="+principal);
			
			// subject contained in white list
			if (subjects.contains(principal)) return true;
						
		}

		return false;
		
	}
	

}
