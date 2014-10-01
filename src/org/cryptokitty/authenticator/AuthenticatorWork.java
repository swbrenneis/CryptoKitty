/**
 * 
 */
package org.cryptokitty.authenticator;

/**
 * @author Steve Brenneis
 *
 * Authentication protocol proof-of-work POD
 */
public class AuthenticatorWork {

	/*
	 * The iteration count.
	 */
	public long iterations;

	/*
	 * Iteration salt.
	 */
	public byte[] salt;

	/*
	 * Server signature
	 */
	public byte[] signature;

	/**
	 * 
	 */
	public AuthenticatorWork() {
		// TODO Auto-generated constructor stub
	}

}
