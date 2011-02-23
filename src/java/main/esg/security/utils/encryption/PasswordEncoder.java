package esg.security.utils.encryption;

public interface PasswordEncoder {
	
	/**
	 * Method to encrypt a clear text password.
	 * @param clearTextPassword
	 * @return
	 */
	public String encrypt(String clearTextPassword);

	/**
	 * Method to check that a given clear text password is equal, after encryption, to a given encrypted password.
	 * @param clearTextPassword
	 * @param encryptedPassword
	 */
	public boolean equals(String clearTextPassword, String encryptedPassword);
	
}
