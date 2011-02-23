package esg.security.utils.encryption;

/**
 * Main class to invoke a {@link PasswordEncoder}.
 * @author Luca Cinquini
 *
 */
public class PasswordEncoderMain {

	private static PasswordEncoder encoder = new MD5CryptPasswordEncoder();
	
	public final static void main(String[] args) {
		
		final String clearTextPassword = args[0];
		System.out.println("Encrypted Password="+encoder.encrypt(clearTextPassword));
		
	}

}
