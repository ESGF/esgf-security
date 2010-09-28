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
