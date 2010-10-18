/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: XrdsException.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.yadis.exceptions;

public class XrdsException extends Exception {

	private static final long serialVersionUID = 2806533159657546936L;

	public XrdsException(String message, Exception e) {
		super(message, e);
	}

	public XrdsException(String message) {
		super(message);
	}

}
