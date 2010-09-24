/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: XrdsParseException.java 7462 2010-09-08 15:21:10Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7462 $
 */
package esg.security.yadis.exception;

import javax.xml.parsers.ParserConfigurationException;


public class XrdsParseException extends XrdsException {

	public XrdsParseException(String message, Exception e) {
		super(message, e);
	}

	public XrdsParseException(String message) {
		super(message);
	}

}
