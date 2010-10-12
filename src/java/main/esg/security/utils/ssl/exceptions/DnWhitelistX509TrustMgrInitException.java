/**
 * Initialisation exception for Certificate DN Whitelist based X.509 Trust 
 * Manager
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: DnWhitelistX509TrustMgrInitException.java 7493 2010-09-21 15:42:53Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7493 $
 */
package esg.security.utils.ssl.exceptions;


public class DnWhitelistX509TrustMgrInitException extends Exception {
	public DnWhitelistX509TrustMgrInitException(String message) {
		super(message);
	}
	
	public DnWhitelistX509TrustMgrInitException(String message, Exception e) {
		super(message, e);
	}
}
