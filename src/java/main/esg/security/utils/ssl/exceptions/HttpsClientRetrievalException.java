/**
 * Initialisation exception for HTTPS Client class
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 22/09/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id$
 * 
 * @author pjkersha
 * @version $Revision$
 */
package esg.security.utils.ssl.exceptions;

public class HttpsClientRetrievalException extends Exception {

	private static final long serialVersionUID = 4944292011775810065L;

	public HttpsClientRetrievalException(String message) {
		super(message);
	}
	
	public HttpsClientRetrievalException(String message, Exception e) {
		super(message, e);
	}
}
