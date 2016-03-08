/**
 * 
 */
package org.cryptokitty.authenticator;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * Server public encryption and signing keys.
 */
public class ServerKeys {

	/*
	 * Encryption key.
	 */
	public RSAPublicKey encrypt;

	/*
	 * Signing key.
	 */
	public RSAPublicKey sign;

	/**
	 * 
	 */
	public ServerKeys() {
		// TODO Auto-generated constructor stub
	}

}
