package esg.security.utils.encryption;

import junit.framework.Assert;

import org.junit.Test;

/**
 * Test class for {@link MD5HexPasswordEncoder}.
 * @author Luca Cinquini
 *
 */
public class MD5HexPasswordEncoderTest {
	
	PasswordEncoder encoder = new MD5HexPasswordEncoder();

	@Test
	public void testEquals() {
		
		final String clearTextPassword = "pwd";
		final String encryptedPassword = "9003d1df22eb4d3820015070385194c8";
		Assert.assertTrue( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}
	
	@Test
	public void testNotEquals1() {
		
		final String clearTextPassword = "pwd1";
		final String encryptedPassword = "9003d1df22eb4d3820015070385194c8";
		Assert.assertFalse( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}
	
	@Test
	public void testNotEquals2() {
		
		final String clearTextPassword = "pwd";
		final String encryptedPassword = "9003d1df22eb4d3820015070385194c8x";
		Assert.assertFalse( encoder.equals(clearTextPassword, encryptedPassword) );
		
	}

}
