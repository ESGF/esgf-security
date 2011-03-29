/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: AttributeServiceQueryException.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.openid2emailresolution.exceptions;

public class AttributeServiceQueryException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1276530056097455351L;

	public AttributeServiceQueryException(String message) {
		super(message);
	}
	
	public AttributeServiceQueryException(String message, Exception e) {
		super(message, e);
	}
}
