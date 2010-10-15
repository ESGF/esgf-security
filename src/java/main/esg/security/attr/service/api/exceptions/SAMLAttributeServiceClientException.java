/**
 * Earth System Grid/CMIP5
 *
 * Date: 15/10/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * @author pjkersha
 */
package esg.security.attr.service.api.exceptions;

public class SAMLAttributeServiceClientException extends Exception {

	/**
	 * Exception type for SAMLAttributeServiceClient interface
	 */
	private static final long serialVersionUID = -5202255233461601883L;

	public SAMLAttributeServiceClientException(String message, 
			Exception e) {
		super(message, e);
	}

	public SAMLAttributeServiceClientException(String message) {
		super(message);
	}		
}
