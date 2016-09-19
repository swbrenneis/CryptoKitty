/**
 * 
 */
package org.cryptokitty.cipher;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;

import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidPaddingException;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * Implementation of the RSA cipher. See RFC 3447 for details.
 * 
 * Some of the variable names and method names are a bit opaque.
 * This is to more easily relate them to the RFC. Comments are
 * provided so the function won't be a mystery.
 * 
 * The inheritance tree of the RSA key and cipher classes is such
 * a mess because Java doesn't provide a sensible differentiation
 * between RSA modulus private key and RSA Chinese Remainder Theorem
 * private keys.
 */
public abstract class RSACipher {


	/**
	 * Digest algorithm enumeration.
	 */
	public enum DigestTypes { SHA224, SHA256, SHA384, SHA512 };
	protected DigestTypes digestType;

	/***
	 * BigInteger byte mask.
	 */
	private static final BigInteger MASK = BigInteger.valueOf(0xff);
	
	/*
	 * Hash algorithm.
	 */
	//protected String hashAlgorithm;

	/*
	 * The maximum size of an input octet string for the associated
	 * hash function. This is here purely for extensibility and isn't
	 * currently practical. Java cannot create a string or array longer
	 * than 2^64 - 1 bytes;
	 */
	//protected BigInteger maxHash;

	/**
	 * Default constructor. The class must be subclassed.
	 */
	protected RSACipher() {
	}

	/*
	 * General decryption method.
	 */
	public abstract byte[] decrypt(RSAPrivateKey K, byte[] C)
				throws IllegalBlockSizeException;

	/*
	 * General encryption method.
	 */
	public abstract byte[] encrypt(RSAPublicKey K, byte[] C)
				throws IllegalBlockSizeException, BadParameterException, InvalidPaddingException;

	/*
	 * Convert an integer representation to an octet string.
	 */
	protected byte[] i2osp(BigInteger x, int xLen)
							throws IllegalBlockSizeException {
		
		if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) > 0) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		BigInteger work = new BigInteger(x.toString());
		byte[] xBytes = new byte[xLen];
		Arrays.fill(xBytes, (byte)0x00);
		int index = xLen - 1;
		while (index >= 0) {
			xBytes[index--] = work.and(MASK).byteValue();
			work = work.shiftRight(8);
		}
		return xBytes;

	}

	/*
	 * Convert an octet string to an integer. Just using the constructor gives
	 * unreliable results, so we'll do it the hard way.
	 */
	protected BigInteger os2ip(byte[] X) {
		BigInteger bi = BigInteger.valueOf(X[0] & 0xff);
		for (int i = 1; i < X.length; ++i) {
			bi = bi.shiftLeft(8).or(BigInteger.valueOf((X[i] & 0xff)));
		}
		return bi;
	}

	/**
	 * RSA encryption primitive
	 * 
	 * @param m - Message representative.
	 * @param publicKey - The public key
	 * 
	 * @throws BadParameterException 
	 */
	protected BigInteger rsaep(RSAPublicKey K, BigInteger m)
								throws IllegalBlockSizeException {

		// 1. If the message representative m is not between 0 and n - 1, output
		//  "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(K.getModulus().subtract(BigInteger.ONE)) > 0) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		// 2. Let c = m^e mod n.
		BigInteger c = m.modPow(K.getPublicExponent(), K.getModulus());

		return c;

	}

	/**
	 * Signature verification primitive.
	 * 
	 * @param K - Public key.
	 * @param s - Signature representative.
	 * 
	 * @return The message representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	protected BigInteger rsavp1(RSAPublicKey K, BigInteger s)
											throws SignatureException {

		// 1. If the signature representative m is not between 0 and n - 1, output
		//  "signature representative out of range" and stop.
		if (s.compareTo(BigInteger.ZERO) < 1 
				|| s.compareTo(K.getModulus().subtract(BigInteger.ONE)) > 0) {
			throw new SignatureException("Invalid signature");
		}

		// 2. Let m = s^e mod n.
		BigInteger m = s.modPow(K.getPublicExponent(), K.getModulus());

		return m;

	}

	//public abstract void setHashAlgorithm(String hashAlgorithm)
	//					throws NoSuchAlgorithmException, NoSuchProviderException;

	/*
	 * Byte array bitwise exclusive or.
	 */
	protected byte[] xor(byte[] a, byte[] b)
							throws IllegalBlockSizeException {

		if (a.length != b.length) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; ++i) {
			result[i] = (byte)((a[i] ^ b[i]) & 0xff);
		}
		return result;
	}

}
