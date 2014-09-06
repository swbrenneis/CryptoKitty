/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;

/**
 * @author Steve Brenneis
 *
 */
public class DSA {

	/*
	 * The message digest.
	 */
	private Digest digest;

	/**
	 * @throws UnsupportedAlgorithmException 
	 * 
	 */
	public DSA(String algorithm) throws UnsupportedAlgorithmException {
		digest = Digest.getInstance(algorithm);
	}

	/*
	 * Sign a message.
	 */
	public byte[] sign(DSAPrivateKey key, byte[] M) {
		return null;
	}

	/*
	 * Verify a signature.
	 */
	public boolean verify(DSAPublicKey key, byte[] M, byte[] S) {
		return false;
	}

}
