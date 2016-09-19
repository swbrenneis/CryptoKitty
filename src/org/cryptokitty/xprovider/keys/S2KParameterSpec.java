package org.cryptokitty.xprovider.keys;

import java.security.spec.AlgorithmParameterSpec;

import org.cryptokitty.pgp.keys.IteratedS2K;
import org.cryptokitty.pgp.keys.KeyAlgorithms;
import org.cryptokitty.pgp.keys.SaltedS2K;
import org.cryptokitty.pgp.keys.String2Key;
import org.cryptokitty.xprovider.UnsupportedAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * String-to-key algorithm spec. Provides string-to-key parameters
 * for the S2KKeyGenerator implementation. See RFC 4880 for details
 * on the string-to-key mechanism.
 */
public class S2KParameterSpec implements AlgorithmParameterSpec {

	/*
	 * Key algorithm. Defaults to AES 128.
	 */
	private int keyAlgorithm;

	/*
	 * Key size in bits.
	 */
	private int keysize;

	/*
	 * String2Key key generator.
	 */
	private String2Key s2k;

	/**
	 * Used when a String2Key object is available. The default key algorithm is AES128. Use
	 * the setKeyAlgorithm method to change the key algorithm.
	 * 
	 * @param passPhrase - UTF-8 encoded password string.
	 * @param s2k - String2Key object
	 */
	public S2KParameterSpec(String passPhrase, String2Key s2k) {
		this.s2k = s2k;
		keyAlgorithm = KeyAlgorithms.AES128;
		keysize = 128;
	}

	/**
	 * Used for a salted key. The default key algorithm is AES128. Use
	 * the setKeyAlgorithm method to change the key algorithm.
	 * 
	 * @param passPhrase - UTF-8 encoded password string.
	 * @param algorithm - Hashing algorithm. See org.cryptokitty.digest.HashFactory
	 * 						for values.
	 * @param salt - Random data for salting.
	 * @throws UnsupportedAlgorithmException 
	 */
	public S2KParameterSpec(String passPhrase, int algorithm, byte[] salt)
					throws UnsupportedAlgorithmException {
		s2k = new SaltedS2K(passPhrase, algorithm, salt);
		keyAlgorithm = KeyAlgorithms.AES128;
		keysize = 128;
	}

	/**
	 * Used for a salted, iterated key. The default key algorithm is AES128. Use
	 * the setKeyAlgorithm method to change the key algorithm.
	 * 
	 * @param passPhrase - UTF-8 encoded password string.
	 * @param algorithm - Hashing algorithm. See org.cryptokitty.digest.HashFactory for values.
	 * @param salt - Random data for salting.
	 * @param c - Derived iteration count. See RFC 4880 for details.
	 * @throws UnsupportedAlgorithmException 
	 */
	public S2KParameterSpec(String passPhrase, int algorithm, byte[] salt, int c)
					throws UnsupportedAlgorithmException {
		s2k = new IteratedS2K(passPhrase, algorithm, salt, c);
		keyAlgorithm = KeyAlgorithms.AES128;
		keysize = 128;
	}

	/**
	 * Get the key algorithm. The value has already been vetted.
	 */
	public int getKeyAlgorithm() {
		return keyAlgorithm;
	}

	/*
	 * Get the key size.
	 */
	public int getKeySize() {
		return keysize;
	}

	/**
	 * Return the created instance of the String2Key class.
	 * 
	 * @return String2Key object.
	 */
	public String2Key getS2K() {
		return s2k;
	}

	/**
	 * Set the key algorithm. The default algorithm is AES128.
	 * 
	 * @param keyAlgorithm - Must be one of the algorithms defined in KeyAlgorithms
	 * @throws UnsupportedAlgorithmException on invalid key algorithm.
	 */
	public void setKeyAlgorithm(int keyAlgorithm)
			throws UnsupportedAlgorithmException {
		if (!KeyAlgorithms.validKeyAlgorithm(keyAlgorithm)) {
			throw new UnsupportedAlgorithmException("Illegal algorithm value");
		}
		
		this.keyAlgorithm = keyAlgorithm;
	}

	/**
	 * Set the key size in bits. The default is 128.
	 * 
	 * @param keysize - The key size in bits.
	 */
	public void setKeySize(int keysize) {
		this.keysize = keysize;
	}

}
