package esg.security.utils.encryption;

import static org.apache.commons.codec.digest.DigestUtils.md5Hex;

public class MD5HexPasswordEncoder implements PasswordEncoder {

	@Override
	public String encrypt(String clearTextPassword) {
		return md5Hex(clearTextPassword);
	}

	@Override
	public boolean equals(String clearTextPassword, String encryptedPassword) {
		return encrypt(clearTextPassword).equals(encryptedPassword);
	}

}
