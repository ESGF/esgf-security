/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
/**
   Description:

**/
package esg.security.utils.encryption;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;



public class MD5CryptPasswordEncoder implements PasswordEncoder {

    private static final Log log = LogFactory.getLog(MD5CryptPasswordEncoder.class);
	
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
