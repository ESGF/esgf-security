package esg.security.utils.encryption;

import junit.framework.Assert;

import org.junit.Test;

/**
 * Test class for {@link MD5CryptPasswordEncoder}.
 * @author Luca Cinquini
 *
 */
public class MD5CryptPasswordEncoderTest {
	
	PasswordEncoder encoder = new MD5CryptPasswordEncoder();

	@Test
	public void testEquals() {
		
		final String clearTextPassword = "pwd";
		final String encryptedPassword = "$1$ICvEa9tz$jPGAVZQXVaAFL8ED66Nr61";
		Assert.assertTrue( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}
	
	@Test
	public void testNotEquals1() {
		
		final String clearTextPassword = "pwd1";
		final String encryptedPassword = "$1$ICvEa9tz$jPGAVZQXVaAFL8ED66Nr61";
		Assert.assertFalse( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}
	
	@Test
	public void testNotEquals2() {
		
		final String clearTextPassword = "pwd";
		final String encryptedPassword = "$1$ICvEa9tz$jPGAVZQXVaAFL8ED66Nr62";
		Assert.assertFalse( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}

}
