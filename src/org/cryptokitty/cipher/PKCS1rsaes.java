/**
 * 
 */
package org.cryptokitty.cipher;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidPaddingException;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPublicKey;
import org.cryptokitty.xprovider.random.BBSSecureRandom;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA PKCS1 v1.5 encryption scheme
 */
public class PKCS1rsaes extends RSACipher {

	/*
	 * Random seed.
	 */
	private byte[] seed;

	/**
	 *
	 */
	public PKCS1rsaes() {
	}

	/**
	 * Decrypt a ciphertext octet string using PKCS1 v 1.5 encoding.
	 * 
	 * @param K - The private key.
	 * @param C - The ciphertext octet string.
	 * 
	 * @returns Plaintext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	@Override
	public byte[] decrypt(RSAPrivateKey K, byte[] C) throws IllegalBlockSizeException {

		// 1. Length checking: If the length of the ciphertext C is not k octets
		//    (or if k < 11), output "decryption error" and stop.
		int k = K.getBitsize() / 8;
		if (C.length != k || k < 11) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		// RSA decryption.
		// a. Convert the ciphertext C to an integer ciphertext
		//    representative c (see Section 4.2):
		//
		//      c = OS2IP (C).
		//
		// b. Apply the RSADP decryption primitive (Section 5.1.2) to the RSA
		//    private key (n, d) and the ciphertext representative c to
		//    produce an integer message representative m:
		//
		//       m = RSADP ((n, d), c).
		BigInteger m = K.rsadp(os2ip(C));

		// If RSADP outputs "ciphertext representative out of range"
		// (meaning that c >= n), output "decryption error" and stop.
		//
		// c. Convert the message representative m to an encoded message EM
		//    of length k octets (see Section 4.1):
		//
		//       EM = I2OSP (m, k).
		byte[] EM = i2osp(m, k);

		// 3. EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an
		//    octet string PS consisting of nonzero octets and a message M as
		//
		//      EM = 0x00 || 0x02 || PS || 0x00 || M.
		//
		// If the first octet of EM does not have hexadecimal value 0x00, if
		// the second octet of EM does not have hexadecimal value 0x02, if
		// there is no octet with hexadecimal value 0x00 to separate PS from
		// M, or if the length of PS is less than 8 octets, output
		// "decryption error" and stop.
		if (EM[0] != 0x00 || EM[1] != 0x02) {
			// Fail silently
			return null;
		}
		// No easy way to do this.
		int found = -1;
		int index = 2;
		while (found < 0 && index < EM.length) {
			if (EM[index] == 0x00) {
				found = index;
			}
			index++;
		}
		if (found < 0) {
			// Fail silently
			return null;
		}
		byte[] PS = Arrays.copyOfRange(EM, 2, found);
		if (PS.length < 8) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		return Arrays.copyOfRange(EM, found + 1, EM.length);

	}

	/**
	 * Encrypt a plaintext octet string using PKCS1 v 1.5 encoding.
	 * 
	 * @param K - The public key in the form of (n,e).
	 * @param M - The plaintext octet string.
	 * 
	 * @returns Ciphertext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	@Override
	public byte[] encrypt(RSAPublicKey K, byte[] M)
				throws IllegalBlockSizeException, InvalidPaddingException {

		// 1. Length checking: If mLen > k - 11, output "message too long" and
		//    stop.
		int k = K.getBitsize() / 8;
		int mLen = M.length;
		if (mLen > k - 11) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		// EME-PKCS1_v1_5 encoding.
		// a. Generate an octet string PS of length k - mLen - 3 consisting
		//    of pseudo-randomly generated nonzero octets.  The length of PS
		//    will be at least eight octets.
		byte[] PS;
		if (seed == null) {
			SecureRandom rnd = new BBSSecureRandom();
			PS = new byte[k - mLen - 3];
			rnd.nextBytes(PS);
			for (int i = 0; i < PS.length; ++i) {
				if (PS[i] == 0x00) {
					while (PS[i] == 0x00) {
						PS[i] = (byte)rnd.nextInt(0xff);
					}
				}
			}
		}
		else {
			if (seed.length != (k - mLen - 3)) {
				throw new IllegalBlockSizeException("Illegal block size");
			}
			PS = seed;
		}

		// b. Concatenate PS, the message M, and other padding to form an
		//    encoded message EM of length k octets as
		//
		//      EM = 0x00 || 0x02 || PS || 0x00 || M.
		byte[] EM = new byte[PS.length + M.length + 3];
		EM[0] = 0x00;
		EM[1] = 0x02;
		System.arraycopy(PS, 0, EM, 2, PS.length);
		EM[PS.length + 2] = 0x00;
		System.arraycopy(M, 0, EM, PS.length + 3, M.length);

		// RSA encryption.
		// a. Convert the encoded message EM to an integer message
		//    representative m.
		//
		// b. Apply the RSAEP encryption primitive (Section 5.1.1) to the RSA
		//    public key (n, e) and the message representative m to produce
		//    an integer ciphertext representative c:
		//
		//       c = RSAEP ((n, e), m).
		BigInteger c = rsaep(K, os2ip(EM));

		// c. Convert the ciphertext representative c to a ciphertext C of
		//    length k octets:
		return i2osp(c, k);

	}

	/**
	 * @param seed - Random bytes for encryption padding. May be null.
	 */
	public void setSeed(byte[] seed) {

		this.seed = seed;

	}

}
