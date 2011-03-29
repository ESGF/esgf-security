/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: NoMatchingXrdsServiceException.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.openid2emailresolution.exceptions;

public class NoMatchingXrdsServiceException extends OpenId2EmailAddrResolutionException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1659060071820999242L;

	public NoMatchingXrdsServiceException(String message, Exception e) {
		super(message, e);
	}

	public NoMatchingXrdsServiceException(String message) {
		super(message);
	}

}
