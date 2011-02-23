package esg.security.utils.encryption;



public class MD5CryptPasswordEncoder implements PasswordEncoder {
	
	/** Start of the salt string. */
	private final static int START_SALT = 3;
	
	/** End of the salt string. */
	private final static int STOP_SALT = 11;

	@Override
	public String encrypt(String clearTextPassword) {
		return MD5Crypt.crypt(clearTextPassword);
	}
	
	public boolean equals(final String clearTextPassword, final String encryptedPassword) {

		// retrieve salt from encrypted password
		// example format: $1$LvwVZUS8$FvU.yQWntcwpRiD6CLrQR1
		final String salt = encryptedPassword.substring(START_SALT, STOP_SALT);

		// use salt to encrypt the decrypted password
		final String newEncryptedPassword = MD5Crypt.crypt(clearTextPassword, salt);

		return newEncryptedPassword.equals(encryptedPassword);

	}
	

}
