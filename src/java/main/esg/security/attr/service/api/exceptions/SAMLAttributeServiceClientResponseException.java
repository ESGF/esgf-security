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

public class SAMLAttributeServiceClientResponseException extends 
	SAMLAttributeServiceClientException {

	/**
	 * Errors from SAML Query response
	 */
	
	private static final long serialVersionUID = 5623425006691539383L;
	public SAMLAttributeServiceClientResponseException(
			String message) {
		super(message);
	}

	public SAMLAttributeServiceClientResponseException(
			String message, Exception e) {
		super(message, e);
	}
	
}

