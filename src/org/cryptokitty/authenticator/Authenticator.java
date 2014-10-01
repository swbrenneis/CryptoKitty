/**
 * 
 */
package org.cryptokitty.authenticator;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Steve Brenneis
 *
 */
public interface Authenticator {

	/*
	 * Register signing and encryption keys and a passphrase.
	 * The server returns its public signing and encryption
	 * keys.
	 */
	public ServerKeys register(RSAPublicKey encrypt, RSAPublicKey sign,
									String passphrase);

	/*
	 * Begin the authentication protocol.
	 * 
	 * The client sends the signed public encryption key that
	 * it provided during the registration process. The server
	 * validates the signature and returns the iteration count,
	 * salt, and signature in the AuthenticatorWork POD.
	 */
	public AuthenticatorWork startAuth(RSAPublicKey key, byte[] sig);

	/*
	 * Exchange the authentication answer.
	 * 
	 * The passphrase and salt are iteratively hashed using the SHA512 digest.
	 * The number of iterations is determined in the iteration count returned
	 * by the startAuth method. It is recommended that the iteration count
	 * should be greater than 2**32.
	 * 
	 * The client sends the encrypted digest result, and the server, upon
	 * successful authentication, returns its encrypted digest result. If
	 * authentication fails on the server, the returned byte array will be
	 * a single zero byte (byte[0] = 0).
	 * 
	 */
	public byte[] authenticate(byte[] answer);

}
