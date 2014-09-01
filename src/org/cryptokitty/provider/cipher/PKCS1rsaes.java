/**
 * 
 */
package org.cryptokitty.provider.cipher;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.DecryptionException;
import org.cryptokitty.provider.IllegalMessageSizeException;
import org.cryptokitty.provider.ProviderException;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA PKCS1 v1.5 encryption scheme
 */
public class PKCS1rsaes extends RSA {

	/**
	 * 
	 */
	public PKCS1rsaes() {
		// Nothing to do here.
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
	public byte[] decrypt(PrivateKey K, byte[] C)
			throws DecryptionException {

		// 1. Length checking: If the length of the ciphertext C is not k octets
		//    (or if k < 11), output "decryption error" and stop.
		int k = K.bitsize / 8;
		if (C.length != k || k < 11) {
			throw new DecryptionException();
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
		try {
			BigInteger m = null;
			if (K instanceof ModulusPrivateKey) {
				m = rsadp((ModulusPrivateKey)K, os2ip(C));
			}
			else if (K instanceof CRTPrivateKey) {
				m = rsadp((CRTPrivateKey)K, os2ip(C));
			}
			else {
				throw new DecryptionException();
			}

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
				throw new DecryptionException();
			}
			int found = Arrays.binarySearch(EM, 2, EM.length, (byte)0x00);
			if (found < 0) {
				throw new DecryptionException();
			}
			byte[] PS = Arrays.copyOfRange(EM, 2, found);
			if (PS.length < 8) {
				throw new DecryptionException();
			}

			return Arrays.copyOfRange(EM, found + 1, EM.length);

		}
		catch (BadParameterException e) {
			// Catching for debug only.
			// Fail silently.
			throw new DecryptionException();
		}

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
	public byte[] encrypt(PublicKey K, byte[] M)
			throws IllegalMessageSizeException, BadParameterException {

		// 1. Length checking: If mLen > k - 11, output "message too long" and
		//    stop.
		int k = K.bitsize / 8;
		int mLen = M.length;
		if (mLen > k - 11) {
			throw new BadParameterException("Message too long");
		}

		// EME-PKCS1_v1_5 encoding.
		// a. Generate an octet string PS of length k - mLen - 3 consisting
		//    of pseudo-randomly generated nonzero octets.  The length of PS
		//    will be at least eight octets.
		SecureRandom rnd = new SecureRandom();
		byte[] PS = new byte[k - mLen - 3];
		PS[0] = 0;
		while (Arrays.binarySearch(PS, (byte)0x00) >= 0) {
			rnd.nextBytes(PS);
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

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#sign(org.cryptokitty.provider.RSA.PrivateKey, byte[])
	 */
	@Override
	public byte[] sign(PrivateKey K, byte[] M)
			throws ProviderException {
		throw new ProviderException("Illegal operation");
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#verify(org.cryptokitty.provider.RSA.PublicKey, byte[], byte[])
	 */
	@Override
	public boolean verify(PublicKey K, byte[] M, byte[] S) {
		// Unsupported operation. Fail silently.
		return false;
	}

}
