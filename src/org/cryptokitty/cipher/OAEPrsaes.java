/**
 * 
 */
package org.cryptokitty.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.digest.Digest;
import org.cryptokitty.digest.SHA224;
import org.cryptokitty.digest.SHA256;
import org.cryptokitty.digest.SHA384;
import org.cryptokitty.digest.SHA512;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidPaddingException;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPublicKey;
import org.cryptokitty.random.FortunaSecureRandom;
import org.cryptokitty.jni.BigInteger;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA-OAEP encryption scheme.
 */
public class OAEPrsaes extends RSACipher {

	/**
	 * P Source (L label).
	 */
	private byte[] pSource;

	/**
	 * Encoding seed.
	 */
	private byte[] seed;

	/**
	 * Message digest.
	 */
	private Digest digest;

	/**
	 * Digest length.
	 */
	private int digestLength;

	/**
	 * This constructor is used for the provider interface only.
	 */
	public OAEPrsaes() {
	}

	/**
	 * This is the standalone constructor.
	 */
	public OAEPrsaes(DigestTypes type) {

		this.digestType = type;
		switch (type) {
		case SHA224:
			digest = new SHA224();
			break;
		case SHA256:
			digest = new SHA256();
			break;
		case SHA384:
			digest = new SHA384();
			break;
		case SHA512:
			digest = new SHA512();
			break;
		}
		digestLength = digest.getDigestLength();
		// See emeOAEPencode a.
		pSource = new byte[0];

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
	@Override
	public byte[] decrypt(RSAPrivateKey K, byte[] C)
							throws IllegalBlockSizeException {

		// Length checking.

		// We're supposed to check L to make sure it's not larger than
		// the hash limitation. That is 2^64 - 1 for SHA1 and SHA256, and
		// 2^128 - 1 for SHA384 and SHA512. Java can only create a string
		// that is 2^63 - 1 bytes long. The test would be pointless and
		// technically infeasible.

		// b. If the length of the ciphertext C is not k octets, output
		//    "decryption error" and stop.
		int k = K.getBitsize() / 8;
		if (C.length != k) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		// c. If k < 2hLen + 2, output "decryption error" and stop.
		int hLen = 0;
		hLen = digestLength;
		if (k < (2 * hLen) + 2) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		BigInteger c = K.rsadp(os2ip(C));
		// Do decoding.
		try {
			return emeOAEPDecode(k, i2osp(c, k));
		}
		catch (BadParameterException | InvalidPaddingException e) {
			// Fail silently
			return null;
		}

	}

	/**
	 * RSA EME-OEAP decoding method.
	 * 
	 * @param k - Private key size in bytes;
	 * @param EM - Encoded message octet string
	 * @return The decoded byte array.
	 * @throws BadParameterException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidPaddingException 
	 */
	private byte[] emeOAEPDecode(int k, byte[] EM)
		throws BadParameterException, IllegalBlockSizeException, InvalidPaddingException {

		// a. If the label L (pSource) is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		byte[] lHash = digest.digest(pSource);

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

		// c. Let seedMask = MGF(maskedDB, hLen).
		CKRSAmgf1 mdmgf = new CKRSAmgf1(digestType);
		byte[] seedMask = mdmgf.generateMask(maskedDB, hLen);

		// d. Let seed = maskedSeed \xor seedMask.
		seed = xor(maskedSeed, seedMask);

		// e. Let dbMask = MGF(seed, k - hLen - 1).
		CKRSAmgf1 dbmgf = new CKRSAmgf1(digestType);
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
			throw new InvalidPaddingException("Bad padding");
		}
		byte[] lHashPrime = Arrays.copyOf(DB, hLen);
		if (!Arrays.equals(lHash, lHashPrime)) {
			throw new InvalidPaddingException("Bad padding");
		}
		int found = -1;
		int index = hLen;
		while (found < 0 && index < DB.length) {
			if (DB[index] == 0x01) {
				found = index;
			}
			index++;
		}
		if (found < 0) {
			throw new InvalidPaddingException("Bad padding");
		}
		byte[] PS = Arrays.copyOfRange(DB, hLen, found);
		for (byte p : PS) {
			if (p != 0) {
				throw new InvalidPaddingException("Bad padding");				
			}
		}

		return Arrays.copyOfRange(DB, found + 1, DB.length);

	}

	/**
	 * RSA EME-OEAP encoding method.
	 * 
	 * @param k - Public key size in bytes.
	 * @param M - Plaintext octet string.
	 * 
	 * @throws InvalidPaddingException
	 * @throws IllegalBlockSizeException 
	 * @throws BadParameterException 
	 */
	private byte[] emeOAEPEncode(int k, byte[] M)
							throws InvalidPaddingException, IllegalBlockSizeException, BadParameterException {

		// a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		byte[] lHash = digest.digest(pSource);

		// b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
        // zero octets.  The length of PS may be zero.
		int hLen = digestLength;
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
			throw new RuntimeException("Invalid output stream");
		}

		// d. Generate a random octet string seed of length hLen.
		// The seed can be set in the setSeed function.
		if (seed == null) {
			FortunaSecureRandom rnd = new FortunaSecureRandom();
			seed = new byte[hLen];
			rnd.nextBytes(seed);
		}
		if (seed.length != hLen) {
			throw new InvalidPaddingException("Invalid seed");
		}
		//byte[] seed = new byte[hLen];
		//SecureRandom rnd = new FortunaSecureRandom();
		//rnd.nextBytes(seed);

		// e. Let dbMask = MGF(seed, k - hLen - 1).
		CKRSAmgf1 dmgf = new CKRSAmgf1(digestType);
		byte[] dbMask = dmgf.generateMask(seed, k - hLen - 1);

		// f. Let maskedDB = DB \xor dbMask.
		byte[] maskedDB = xor(DB.toByteArray(), dbMask);

		// g. Let seedMask = MGF(maskedDB, hLen).
		CKRSAmgf1 smgf = new CKRSAmgf1(digestType);
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
			throw new RuntimeException("Invalid array operation");
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
	 * @throws InvalidPaddingException 
	 * @throws BadParameterException 
	 * 
	 * @returns Ciphertext octet string.
	 * 
	 */
	@Override
	public byte[] encrypt(RSAPublicKey K, byte[] M)
			throws IllegalBlockSizeException, BadParameterException, InvalidPaddingException {

		// Length checking.

		// We're supposed to check L to make sure it's not larger than
		// the hash limitation. That is 2^64 - 1for SHA1 and SHA256, and
		// 2^128 - 1 for SHA384 and SHA512. Java can only create a string
		// that is 2^31 - 1 bytes long. The test would be pointless and
		// technically infeasible.

		int hLen = digestLength;
		int k = K.getBitsize() / 8;
		int mLen = M.length;
		if (mLen > k - (2 * hLen) - 2) {
			throw new IllegalBlockSizeException("Illegal block size");
		}
		// We're supposed to check L to make sure it's not larger than
		// the hash limitation, which is ginormous for SHA-1 and above
		// (~= 2 exabytes). Not going to worry about it.

		// Do encoding first.
		byte[] EM = emeOAEPEncode(k, M);
		// Do encryption primitive
		BigInteger c = rsaep(K, os2ip(EM));
		// Return octet string.
		return i2osp(c, k);

	}

	/**
	 * 
	 * Set the hash algorithm
	 *
	 * @param pSource
	 * @throws UnsupportedAlgorithmException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 
	public void setHashAlgorithm(String hashAlgorithm)
							throws NoSuchAlgorithmException, NoSuchProviderException {

		this.hashAlgorithm = hashAlgorithm;
		digest = MessageDigest.getInstance(hashAlgorithm, "CK");
		digestLength = digest.getDigestLength();

		switch(hashAlgorithm) {
			case "SHA-1":
				maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
				break;
			case "SHA-256":
				maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
				break;
			case "SHA-384":
				maxHash = BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);
				break;
			case "SHA-512":
				maxHash = BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);
				break;
		}

	}*/

	/**
	 * Set the Label
	 */
	public void setPSource(byte[] pSource) {

		this.pSource = pSource;

	}

	public void setSeed(byte[] seed) throws BadParameterException {

		if (seed.length != digest.getDigestLength()) {
			throw new BadParameterException("Invalid seed");
		}
		
		this.seed = seed;

	}

}
