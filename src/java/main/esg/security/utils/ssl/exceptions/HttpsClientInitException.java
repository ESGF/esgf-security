/**
 * Initialisation exception for HTTPS Client class
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 21/09/10
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

public class HttpsClientInitException extends Exception {

	private static final long serialVersionUID = -2738340709577351942L;

	public HttpsClientInitException(String message) {
		super(message);
	}
	
	public HttpsClientInitException(String message, Exception e) {
		super(message, e);
	}
}
