package esg.security.registry.service.api;


public class UnknownPolicyAttributeTypeException extends Exception {
	
	private static final long serialVersionUID = 1L;

	public UnknownPolicyAttributeTypeException(final String message, final Throwable throwable) {

		super(message, throwable);
	}

	public UnknownPolicyAttributeTypeException(final String message) {

		super(message);
	}

	public UnknownPolicyAttributeTypeException(final Throwable throwable) {

		super(throwable);
	}
	
}