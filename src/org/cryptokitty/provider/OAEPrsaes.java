/**
 * 
 */
package org.cryptokitty.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA-OAEP encryption scheme.
 */
public class OAEPrsaes extends RSA {

	/**
	 * @param hashAlgorithm
	 * @throws UnsupportedAlgorithmException
	 */
	public OAEPrsaes(int hashAlgorithm)
			throws UnsupportedAlgorithmException {

		this.hashAlgorithm = hashAlgorithm;
		switch(hashAlgorithm) {
		case HashFactory.SHA1:
			emptyHash = SHA1_EMPTY;
			maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
			break;
		case HashFactory.SHA256:
			emptyHash = SHA256_EMPTY;
			maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
			break;
		case HashFactory.SHA384:
			emptyHash = SHA384_EMPTY;
			maxHash = BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);
			break;
		case HashFactory.SHA512:
			emptyHash = SHA512_EMPTY;
			maxHash = BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);
			break;
		default:
			throw new UnsupportedAlgorithmException("Invalid hash algorithm");
		}

	}

	/**
	 * Decrypt a ciphertext octet string using OAEP encoding with hash function
	 * and MGF padding.
	 * 
	 * @param K - The private key.
	 * @param C - The ciphertext message octet string.
	 * @param L - Optional label. Can be empty, must not be null.
	 * 
	 * @returns Plaintext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	public byte[] decrypt(PrivateKey K, byte[] C, String L)
			throws DecryptionException {

		// Length checking.

		// We're supposed to check L to make sure it's not larger than
		// the hash limitation. That is 2^64 - 1 for SHA1 and SHA256, and
		// 2^128 - 1 for SHA384 and SHA512. Java can only create a string
		// that is 2^63 - 1 bytes long. The test would be pointless and
		// technically infeasible.

		// b. If the length of the ciphertext C is not k octets, output
		//    "decryption error" and stop.
		int k = K.bitsize / 8;
		if (C.length != k) {
			throw new DecryptionException();
		}

		// c. If k < 2hLen + 2, output "decryption error" and stop.
		int hLen = 0;
		try {
			hLen = HashFactory.getDigest(hashAlgorithm).getDigestLength();
		}
		catch (UnsupportedAlgorithmException e) {
			// Not happening. Algorithm was verified in the constructor.
		}
		if (k < (2 * hLen) + 2) {
			throw new DecryptionException();
		}

		try {
			BigInteger c = null;
			if (K instanceof ModulusPrivateKey) {
				// Do decryption primitive
				c = rsadp((ModulusPrivateKey)K, os2ip(C));
			}
			else if (K instanceof CRTPrivateKey) {
				c = rsadp((CRTPrivateKey)K, os2ip(C));
			}
			else {
				throw new DecryptionException();
			}

			// Do decoding.
			return emeOAEPDecode(k, i2osp(c, k),  L);
		}
		catch (BadParameterException e) {
			// Catching for debug purposes only.
			// Fail silently.
			throw new DecryptionException();
		}

	}

	/**
	 * RSA EME-OEAP decoding method.
	 * 
	 * @param k - Private key size in bytes;
	 * @param EM - Encoded message octet string
	 * @param L - Optional output label. Can be empty, must not be null.
	 * 
	 */
	private byte[] emeOAEPDecode(int k, byte[] EM, String L)
			throws DecryptionException {
		
		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen. Hash algorithm was verified in the constructor.
		}
		// a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		byte[] lHash = emptyHash;
		if (L.length() > 0) {
			lHash = hash.digest(L.getBytes(Charset.forName("UTF-8")));
		}
		int hLen = lHash.length;

		// b. Separate the encoded message EM into a single octet Y, an octet
		//    string maskedSeed of length hLen, and an octet string maskedDB
		//    of length k - hLen - 1 as
		//
		//     EM = Y || maskedSeed || maskedDB.
		byte Y = EM[0];
		byte[] maskedSeed = new byte[hLen];
		byte[] maskedDB = new byte[k - hLen - 1];
		System.arraycopy(EM, 1, maskedSeed, 0, hLen);
		System.arraycopy(EM, hLen + 1, maskedDB, 0, maskedDB.length);

		try {
			// c. Let seedMask = MGF(maskedDB, hLen).
			MGF1 mdmgf = new MGF1(hashAlgorithm);
			byte[] seedMask = mdmgf.generateMask(maskedDB, hLen);

			// d. Let seed = maskedSeed \xor seedMask.
			byte[] seed = xor(maskedSeed, seedMask);

			// e. Let dbMask = MGF(seed, k - hLen - 1).
			MGF1 dbmgf = new MGF1(hashAlgorithm);
			byte[] dbMask = dbmgf.generateMask(seed, k - hLen - 1);

			// f. Let DB = maskedDB \xor dbMask.
			byte[] DB = xor(maskedDB, dbMask);

			// g. Separate DB into an octet string lHash' of length hLen, a
			//    (possibly empty) padding string PS consisting of octets with
			//    hexadecimal value 0x00, and a message M as
			//
			//      DB = lHash' || PS || 0x01 || M.
			//
			// If there is no octet with hexadecimal value 0x01 to separate PS
			// from M, if lHash does not equal lHash', or if Y is nonzero,
			// output "decryption error" and stop.
			if (Y != 0) {
				throw new DecryptionException();
			}
			byte[] lHashPrime = Arrays.copyOf(DB, hLen);
			if (!Arrays.equals(lHash, lHashPrime)) {
				throw new DecryptionException();				
			}
			int found = Arrays.binarySearch(DB, hLen, DB.length, (byte)0x01);
			if (found == -1) {
				throw new DecryptionException();				
			}
			byte[] PS = Arrays.copyOfRange(DB, hLen, found);
			for (byte p : PS) {
				if (p != 0) {
					throw new DecryptionException();				
				}
			}

			return Arrays.copyOfRange(DB, found + 1, DB.length);

		}
		catch (BadParameterException e) {
			// Caught for debug only.
			// Fail silently.
			throw new DecryptionException();
		}

	}

	/**
	 * RSA EME-OEAP encoding method.
	 * 
	 * @param k - Public key size in bytes.
	 * @param M - Plaintext octet string.
	 * @param L - Optional output label. Can be empty, must not be null.
	 * 
	 * @throws UnsupportedAlgorithmException if the wrong constructor was used.
	 */
	private byte[] emeOAEPEncode(int k, byte[] M, String L)
			throws BadParameterException {

		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e1) {
			// Won't happen. Hash algorithm was verified in the constructor.
		}

		// a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		byte[] lHash = emptyHash;
		if (L.length() > 0) {
			lHash = hash.digest(L.getBytes(Charset.forName("UTF-8")));
		}

		// b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
        // zero octets.  The length of PS may be zero.
		int hLen = hash.getDigestLength();
		int mLen = M.length;
		byte[] PS = new byte[k - mLen - (2 * hLen) - 2];
		Arrays.fill(PS, (byte)0);

		// c. Concatenate lHash, PS, a single octet with hexadecimal value
        //    0x01, and the message M to form a data block DB of length k -
        //    hLen - 1 octets as
		//
        //      DB = lHash || PS || 0x01 || M.
		ByteArrayOutputStream DB = new ByteArrayOutputStream();
		try {
			DB.write(lHash);
			DB.write(PS);
			DB.write(0x01);
			DB.write(M);
		}
		catch (IOException e) {
			// Not going to happen.
		}

		// d. Generate a random octet string seed of length hLen.
		byte[] seed = new byte[hLen];
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(seed);

		// e. Let dbMask = MGF(seed, k - hLen - 1).
		MGF1 dmgf = new MGF1(hashAlgorithm);
		byte[] dbMask = dmgf.generateMask(seed, k - hLen - 1);

		// f. Let maskedDB = DB \xor dbMask.
		byte[] maskedDB = xor(DB.toByteArray(), dbMask);

		// g. Let seedMask = MGF(maskedDB, hLen).
		MGF1 smgf = new MGF1(hashAlgorithm);
		byte[] seedMask = smgf.generateMask(maskedDB, hLen);

		// h. Let maskedSeed = seed \xor seedMask.
		byte[] maskedSeed = xor(seed, seedMask);

		// i. Concatenate a single octet with hexadecimal value 0x00,
        //    maskedSeed, and maskedDB to form an encoded message EM of
        //    length k octets as
		//
        //       EM = 0x00 || maskedSeed || maskedDB.
		ByteArrayOutputStream EM = new ByteArrayOutputStream();
		try {
			EM.write(0x00);
			EM.write(maskedSeed);
			EM.write(maskedDB);
		}
		catch (IOException e) {
			// Not happening
		}

		return EM.toByteArray();

	}

	/**
	 * Encrypt a plaintext octet string using OAEP encoding with hash function
	 * and MGF padding.
	 * 
	 * @param K - The public key in the form of (n,e).
	 * @param M - The plaintext octet string.
	 * @param L - Optional label. Can be empty, must not be null.
	 * 
	 * @returns Ciphertext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	public byte[] encrypt(PublicKey K, byte[] M, String L)
			throws BadParameterException {

		// Length checking.

		// We're supposed to check L to make sure it's not larger than
		// the hash limitation. That is 2^64 - 1for SHA1 and SHA256, and
		// 2^128 - 1 for SHA384 and SHA512. Java can only create a string
		// that is 2^63 - 1 bytes long. The test would be pointless and
		// technically infeasible.

		int hLen = 0;
		try {
			hLen = HashFactory.getDigest(hashAlgorithm).getDigestLength();
		}
		catch (UnsupportedAlgorithmException e) {
			// Not happening. Algorithm was verified in the constructor.
		}
		int k = K.bitsize / 8;
		int mLen = M.length;
		if (mLen > k - (2 * hLen) - 2) {
			throw new BadParameterException("Message too long");
		}
		// We're supposed to check L to make sure it's not larger than
		// the hash limitation, which is ginormous for SHA-1 and above
		// (~= 2 exabytes). Not going to worry about it.

		// Do encoding first.
		byte[] EM = emeOAEPEncode(k, M,  L);
		// Do encryption primitive
		BigInteger c = rsaep(K, os2ip(EM));
		// Return octet string.
		return i2osp(c, k);

	}

}
