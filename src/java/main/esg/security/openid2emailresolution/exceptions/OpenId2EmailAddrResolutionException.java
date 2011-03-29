/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: OpenId2EmailAddrResolutionException.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.openid2emailresolution.exceptions;

public class OpenId2EmailAddrResolutionException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -956045359556836570L;

	public OpenId2EmailAddrResolutionException(String message, Exception e) {
		super(message, e);
	}

	public OpenId2EmailAddrResolutionException(String message) {
		super(message);
	}
}
