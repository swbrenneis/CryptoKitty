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

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * Implementation of the RSA cipher. See RFC 3447 for details.
 * 
 * Some of the variable names and method names are a bit opaque.
 * This is to more easily relate them to the RFC. Comments are
 * provided so the function won't be a mystery.
 */
public class RSA {

	/*
	 * Empty (null string) hash values.
	 */
	private static final byte[] SHA1_EMPTY =
		{ (byte)0xda, 0x39, (byte)0xa3, (byte)0xee, 0x5e, 0x6b, 0x4b,
			0x0d, 0x32, 0x55, (byte)0xbf, (byte)0xef, (byte)0x95, 0x60,
			0x18, (byte)0x90, (byte)0xaf, (byte)0xd8, 0x07, 0x09 };

	private static final byte[] SHA256_EMPTY = 
		{ (byte)0xe3, (byte)0xb0, (byte)0xc4, 0x42, (byte)0x98,
			(byte)0xfc, 0x1c, 0x14, (byte)0x9a, (byte)0xfb, (byte)0xf4,
			(byte)0xc8, (byte)0x99, 0x6f, (byte)0xb9, 0x24, 0x27,
			(byte)0xae, 0x41, (byte)0xe4, 0x64, (byte)0x9b, (byte)0x93,
			0x4c, (byte)0xa4, (byte)0x95, (byte)0x99, 0x1b, 0x78, 0x52,
			(byte)0xb8, 0x55 };

	private static final byte[] SHA384_EMPTY = 
		{ 0x38, (byte)0xb0, 0x60, (byte)0xa7, 0x51, (byte)0xac, (byte)0x96,
			0x38, 0x4c, (byte)0xd9, 0x32, 0x7e, (byte)0xb1, (byte)0xb1,
			(byte)0xe3, 0x6a, 0x21, (byte)0xfd, (byte)0xb7, 0x11, 0x14,
			(byte)0xbe, 0x07, 0x43, 0x4c, 0x0c, (byte)0xc7, (byte)0xbf,
			0x63, (byte)0xf6, (byte)0xe1, (byte)0xda, 0x27, 0x4e,
			(byte)0xde, (byte)0xbf, (byte)0xe7, 0x6f, 0x65, (byte)0xfb,
			(byte)0xd5, 0x1a, (byte)0xd2, (byte)0xf1, 0x48, (byte)0x98,
			(byte)0xb9, 0x5b };

	private static final byte[] SHA512_EMPTY = 
		{ (byte)0xcf, (byte)0x83, (byte)0xe1, 0x35, 0x7e, (byte)0xef,
			(byte)0xb8, (byte)0xbd, (byte)0xf1, 0x54, 0x28, 0x50,
			(byte)0xd6, 0x6d, (byte)0x80, 0x07, (byte)0xd6, 0x20,
			(byte)0xe4, 0x05, 0x0b, 0x57, 0x15, (byte)0xdc, (byte)0x83,
			(byte)0xf4, (byte)0xa9, 0x21, (byte)0xd3, 0x6c, (byte)0xe9,
			(byte)0xce, 0x47, (byte)0xd0, (byte)0xd1, 0x3c, 0x5d,
			(byte)0x85, (byte)0xf2, (byte)0xb0, (byte)0xff, (byte)0x83,
			0x18, (byte)0xd2, (byte)0x87, 0x7e, (byte)0xec, 0x2f, 0x63,
			(byte)0xb9, 0x31, (byte)0xbd, 0x47, 0x41, 0x7a, (byte)0x81,
			(byte)0xa5, 0x38, 0x32, 0x7a, (byte)0xf9, 0x27, (byte)0xda, 0x3e };

	/*
	 * Mask generation function. See RFC 3447, Appendix B.2.1 for details
	 */
	private final class MGF1 {

		/*
		 * Hash function.
		 */
		private Hash hash;
	
		/*
		 * Sole constructor.
		 */
		public MGF1(int hashAlgorithm) {
			try {
				this.hash = HashFactory.getDigest(hashAlgorithm);
			}
			catch (UnsupportedAlgorithmException e) {
				// Won't happen. Algorithm verified in RSA constructor.
			}
		}

		/*
		 * Generate the mask.
		 */
		public byte[] generateMask(byte[] mgfSeed, int maskLen)
				throws BadParameterException {

			int hLen = hash.getDigestLength();
			if (maskLen > hLen) {
				throw new BadParameterException("Mask too long");
			}

			ByteArrayOutputStream T = new ByteArrayOutputStream();
			for (int counter = 0;
					counter < Math.ceil((double)maskLen / hLen);
						++ counter) {
				byte[] C = Scalar32.encode(counter);
				byte[] h = new byte[C.length + mgfSeed.length];
				System.arraycopy(mgfSeed, 0, h, 0, mgfSeed.length);
				System.arraycopy(C, 0, h, mgfSeed.length, 4);
				byte[] t = hash.digest(h);
				try {
					T.write(t);
				}
				catch (IOException e) {
					// TODO What do we do with this?
					// Not likely to happen
				}
			}

			return Arrays.copyOf(T.toByteArray(), maskLen);

		}

	}

	/*
	 * Public key POD
	 */
	public final class PublicKey {
		// The RSA modulus.
		public BigInteger n;
		// The RSA public exponent.
		public BigInteger e;
		// Key size in bits.
		public int bitsize;
	}

	/*
	 * Base class for private keys
	 */
	private class PrivateKey {
		// Key size in bits.
		public int bitsize;
	}

	/*
	 * Private key POD.
	 */
	public final class ModulusPrivateKey
							extends PrivateKey {
		// The RSA modulus.
		public BigInteger n;
		// The RSA private exponent.
		public BigInteger d;
	}

	/*
	 * CRT private key
	 */
	public final class CRTPrivateKey
							extends PrivateKey {
		// First prime.
		public BigInteger p;
		// Second prime.
		public BigInteger q;
		// First prime CRT exponent.
		public BigInteger dP;
		// Second prime CRT exponent.
		public BigInteger dQ;
		// CRT coefficient.
		public BigInteger qInv;
	}

	/*
	 * The empty hash value.
	 */
	private byte[] emptyHash;

	/*
	 * Hash algorithm for OAEP.
	 */
	private int hashAlgorithm;

	/*
	 * Intended salt length for EMSA-PSS signature encoding
	 */
	private int sLen;

	/**
	 * Default constructor for PKCS1 scheme.
	 */
	public RSA() {
		emptyHash = null;
		hashAlgorithm = -1;
		sLen = -1;
	}

	/**
	 * Constructor used for OAEP scheme.
	 */
	public RSA(int hashAlgorithm)
		throws UnsupportedAlgorithmException {

		this.hashAlgorithm = hashAlgorithm;
		switch(hashAlgorithm) {
		case HashFactory.SHA1:
			emptyHash = SHA1_EMPTY;
			break;
		case HashFactory.SHA256:
			emptyHash = SHA256_EMPTY;
			break;
		case HashFactory.SHA384:
			emptyHash = SHA384_EMPTY;
			break;
		case HashFactory.SHA512:
			emptyHash = SHA512_EMPTY;
			break;
		default:
			throw new UnsupportedAlgorithmException("Invalid hash algorithm");
		}

	}

	/**
	 * Constructor used for EMSA-PSS scheme.
	 */
	public RSA(int hashAlgorithm, int sLen)
		throws UnsupportedAlgorithmException {

		this.sLen = sLen;
		this.hashAlgorithm = hashAlgorithm;
		switch(hashAlgorithm) {
		case HashFactory.SHA1:
			emptyHash = SHA1_EMPTY;
			break;
		case HashFactory.SHA256:
			emptyHash = SHA256_EMPTY;
			break;
		case HashFactory.SHA384:
			emptyHash = SHA384_EMPTY;
			break;
		case HashFactory.SHA512:
			emptyHash = SHA512_EMPTY;
			break;
		default:
			throw new UnsupportedAlgorithmException("Invalid hash algorithm");
		}

	}

	/**
	 * RSA EME-OEAP decoding method.
	 * 
	 * @param k - Private key size in bytes;
	 * @param EM - Encoded message octet string
	 * @param l - Optional output label. Can be empty, must not be null.
	 * 
	 */
	private byte[] emeOAEPDecode(int k, byte[] EM, String l)
			throws DecryptionException {
		
		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e1) {
			// Won't happen. Algorithm verified in the constructor.
		}
		// a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		String L = "";
		byte[] lHash = emptyHash;
		if (l != null) {
			L = l;
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
	 * @param l - Optional output label. Can be empty, must not be null.
	 * 
	 */
	private byte[] emeOAEPEncode(int k, byte[] M, String l)
			throws BadParameterException {

		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e1) {
			// Won't happen. Algorithm verified in the constructor.
		}
		// a. If the label L is not provided, let L be the empty string. Let
        //    lHash = Hash(L), an octet string of length hLen
		String L = "";
		byte[] lHash = emptyHash;
		if (l != null) {
			L = l;
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
	 * Message signature encoding operation.
	 * 
	 * @param M - Message octet string.
	 * @param emBits - maximal bit length of the integer representation of
	 * 					the encoded message.
	 * 
	 * @return Encoded octet string.
	 */
	private byte[] emsaPSSEncode(byte[] M, int emBits)
			throws BadParameterException {

		// The check here for message size with respect to the hash input
		// size (~= 2 exabytes for SHA1) isn't necessary.

		// 2.  Let mHash = Hash(M), an octet string of length hLen.
		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e1) {
			// Won't happen. The hash algorithm was verified in the constructor
		}
		byte[] mHash = emptyHash;
		if (M.length > 0) {
			mHash = hash.digest(M);
		}

		// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
		int hLen = hash.getDigestLength();
		int emLen = (int)Math.ceil((double)emBits / 8);
		if (emLen < hLen + sLen + 2) {
			throw new BadParameterException("Encoding error");
		}

		// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
		//     then salt is the empty string.
		byte[] salt = new byte[sLen];
		if (salt.length > 0) {
			SecureRandom rnd = new SecureRandom();
			rnd.nextBytes(salt);
		}

		// 5.  Let
		//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
		//
		// M' is an octet string of length 8 + hLen + sLen with eight
		// initial zero octets.
		byte[] mPrime = new byte[8 + hLen + sLen];
		Arrays.fill(mPrime, (byte)0x00);
		System.arraycopy(mHash, 0, mPrime, 8, hLen);
		System.arraycopy(salt, 0, mPrime, hLen + 8, sLen);

		// 6.  Let H = Hash(M'), an octet string of length hLen.
		hash.reset();
		byte[] H = hash.digest(mPrime);

		// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
		//     zero octets.  The length of PS may be 0.
		byte[] PS = new byte[emLen - sLen - hLen -2];
		Arrays.fill(PS, (byte)0x00);

		// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
		//     emLen - hLen - 1.
		byte[] DB = new byte[emLen - hLen - 1];
		System.arraycopy(PS, 0, DB, 0, PS.length);
		DB[PS.length] = 0x01;
		System.arraycopy(salt, 0, DB, PS.length + 1, salt.length);

		// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
		MGF1 dbmgf = new MGF1(hashAlgorithm);
		byte[] dbMask = dbmgf.generateMask(H, emLen - hLen - 1);

		// 10. Let maskedDB = DB \xor dbMask.
		byte[] maskedDB = xor(DB, dbMask);

		// 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
		//     maskedDB to zero.
		byte bitmask = (byte)0xff;
		for (int i = 0; i < (8 * emLen) - emBits; i++) {
			bitmask = (byte)((bitmask >>> 1) & 0xff);
			maskedDB[0] = (byte)(maskedDB[0] & bitmask);
		}

		// 12. Let EM = maskedDB || H || 0xbc.
		ByteArrayOutputStream EM = new ByteArrayOutputStream();
		try {
			EM.write(maskedDB);
			EM.write(H);
			EM.write((byte)0xbc);
		}
		catch (IOException e) {
			// Not happening
		}

		// 13. Output EM.
		return EM.toByteArray();

	}

	/*
	 * Convert an integer representation to an octet string.
	 */
	private byte[] i2osp(BigInteger x, int xLen)
			throws BadParameterException {
		
		if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) > 0) {
			throw new BadParameterException("Integer too large");
		}
	
		byte[] xBytes = x.toByteArray();
		if (xBytes.length < xLen) {
			// Fill MSB with zeros.
			byte[] r = new byte[xLen];
			Arrays.fill(r, (byte)0);
			System.arraycopy(xBytes, 0, r, xLen-xBytes.length, xBytes.length);
			return r;
		}
		// xLen will not be < result.length because of the size
		// check above.
		return xBytes;

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
	public byte[] OAEPdecrypt(PrivateKey K, byte[] C, String L)
			throws DecryptionException {

		// Length checking.
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
		// We're supposed to check L to make sure it's not larger than
		// the hash limitation, which is ginormous for SHA-1 and above
		// (~= 2 exabytes). Not going to worry about it.

		try {
			BigInteger c = null;
			if (K instanceof ModulusPrivateKey) {
				// Do decryption primitive
				c = rsadp((ModulusPrivateKey)K, os2ip(C));
			}
			else {
				c = rsadp((CRTPrivateKey)K, os2ip(C));
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
	public byte[] OAEPencrypt(PublicKey K, byte[] M, String L)
			throws BadParameterException {

		// Length checking.
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

	/**
	 * Decrypt a ciphertext octet string using PKCS1 v 1.5.
	 * 
	 * @param K - The private key.
	 * @param C - The ciphertext octet string.
	 * 
	 * @returns Plaintext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	public byte[] PKCS1decrypt(PrivateKey K, byte[] C)
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
			else {
				m = rsadp((CRTPrivateKey)K, os2ip(C));
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
	 * Verify an EMSA-PSS encoded signature.
	 * 
	 * @param M - Message to be verified.
	 * @param EM - Encoded message octet string
	 * @param emBits - maximal bit length of the integer
	 *                 representation of EM
	 *                 
	 * @return True if the encoding is consistent, otherwise false.
	 */
	private boolean emsaPSSVerify(byte[] M, byte[] EM, int emBits) {
/*
		   1.  If the length of M is greater than the input limitation for the
	       hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
	       and stop.

	   2.  Let mHash = Hash(M), an octet string of length hLen.

	   3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.

	   4.  If the rightmost octet of EM does not have hexadecimal value
	       0xbc, output "inconsistent" and stop.

	   5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
	       let H be the next hLen octets.

	   6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
	       maskedDB are not all equal to zero, output "inconsistent" and
	       stop.

	   7.  Let dbMask = MGF(H, emLen - hLen - 1).

	   8.  Let DB = maskedDB \xor dbMask.

	   9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
	       to zero.

	   10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
	       or if the octet at position emLen - hLen - sLen - 1 (the leftmost
	       position is "position 1") does not have hexadecimal value 0x01,
	       output "inconsistent" and stop.

	   11.  Let salt be the last sLen octets of DB.

	   12.  Let
	            M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;

	       M' is an octet string of length 8 + hLen + sLen with eight
	       initial zero octets.

	   13. Let H' = Hash(M'), an octet string of length hLen.

	   14. If H = H', output "consistent." Otherwise, output "inconsistent."
*/
		return false;
	}

	/**
	 * Encrypt a plaintext octet string using PKCS1 v 1.5.
	 * 
	 * @param K - The public key in the form of (n,e).
	 * @param M - The plaintext octet string.
	 * 
	 * @returns Ciphertext octet string.
	 * 
	 * @throws BadParameterException if M is too long
	 */
	public byte[] PKCS1encrypt(PublicKey K, byte[] M)
			throws BadParameterException {

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
	 * Convert an octet string to an integer.
	 * This is really just a wrapper function for the BigInteger constructor,
	 * but it is here to keep the function nomenclature from the RFC clear.
	 */
	private BigInteger os2ip(byte[] X) {
		return new BigInteger(X);
	}

	/**
	 * RSA decryption primitive, modulus and exponent
	 */
	private BigInteger rsadp(ModulusPrivateKey K, BigInteger c)
		throws BadParameterException {

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Ciphertext representative out of range");
		}

		// 2. Let m = c^d mod n.
		BigInteger m = c.modPow(K.d, K.n);

		return m;

	}

	/**
	 * RSA decryption primitive, CRT method
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param c - Ciphertext representative.
	 * 
	 * @return The plaintext representative
	 * 
	 * @throws BadParameterException if ciphertext representative is out of range
	 */
	private BigInteger rsadp(CRTPrivateKey K, BigInteger c)
		throws BadParameterException {

		// We have to compute the modulus for the range check
		BigInteger n = K.p.multiply(K.q);

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Ciphertext representative out of range");
		}

		// i.    Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
		BigInteger m_1 = c.modPow(K.dP, K.p);
		BigInteger m_2 = c.modPow(K.dQ, K.q);

		// iii.  Let h = (m_1 - m_2) * qInv mod p.
		BigInteger h = m_1.subtract(m_2).multiply(K.qInv).mod(K.p);

		// iv.   Let m = m_2 + q * h.
		BigInteger m = K.q.multiply(h).add(m_2);

		return m;

	}

	/**
	 * RSA encryption primitive
	 * 
	 * @param m - Message representative.
	 * @param publicKey - The public key
	 * 
	 * @throws BadParameterException 
	 */
	private BigInteger rsaep(PublicKey K, BigInteger m)
			throws BadParameterException {

		// 1. If the message representative m is not between 0 and n - 1, output
		//  "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Message representative out of range");
		}

		// 2. Let c = m^e mod n.
		BigInteger c = m.modPow(K.e, K.n);

		return c;

	}

	/**
	 * Signature generation primitive. Modulus and exponent method.
	 * 
	 * @param K - Private key of the form (n, d).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	private BigInteger rsasp1(ModulusPrivateKey K, BigInteger m)
			throws BadParameterException {

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Message representative out of range");
		}

		// Let s = m^d mod n.
		BigInteger s = m.modPow(K.d, K.n);

		return s;

	}

	/**
	 * Signature generation primitive. CRT method.
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	private BigInteger rsasp1(CRTPrivateKey K, BigInteger m)
			throws BadParameterException {

		// We have to compute the modulus for the range check
		BigInteger n = K.p.multiply(K.q);

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Message representative out of range");
		}

		// i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
		BigInteger s_1 = m.modPow(K.dP, K.p);
		BigInteger s_2 = m.modPow(K.dQ, K.q);

		// iii.  Let h = (s_1 - s_2) * qInv mod p.
		BigInteger h = s_1.subtract(s_2).multiply(K.qInv).mod(K.p);

		// iv.   Let s = s_2 + q * h.
		BigInteger s = K.q.multiply(h).add(s_2);

		return s;

	}

	/**
	 * Sign a message.
	 * 
	 * @param K - The private key.
	 * @param M - Message octet string to be signed
	 * 
	 * @return Signature octet string.
	 */
	public byte[] rsassaPSSSign(PrivateKey K, byte[] M)
			throws BadParameterException {

		// 1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation to
		// the message M to produce an encoded message EM of length
		// \ceil ((modBits - 1)/8) octets such that the bit length of the
		// integer OS2IP (EM) is at most modBits - 1, where modBits is the
		// length in bits of the RSA modulus n:
		//
		//    EM = EMSA-PSS-ENCODE (M, modBits - 1).
		//
		// Note that the octet length of EM will be one less than k if
		// modBits - 1 is divisible by 8 and equal to k otherwise.  If the
		// encoding operation outputs "message too long," output "message too
		// long" and stop.  If the encoding operation outputs "encoding
		// error," output "encoding error" and stop.
		//
		// The encoding operation won't output "message too long" since the
		// message would have to be ~= 2 exabytes long.
		byte[] EM = emsaPSSEncode(M, K.bitsize - 1);

		// RSA signature
		//
		// a. Convert the encoded message EM to an integer message
		//    representative m (see Section 4.2):
		//
		//      m = OS2IP (EM).
		BigInteger m = os2ip(EM);

		// b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
		//    private key K and the message representative m to produce an
		//    integer signature representative s:
		//
		//       s = RSASP1 (K, m).
		BigInteger s;
		if (K instanceof ModulusPrivateKey) {
			s = rsasp1((ModulusPrivateKey)K, m);
		}
		else {
			s = rsasp1((CRTPrivateKey)K, m);
		}

		// c. Convert the signature representative s to a signature S of
		//    length k octets (see Section 4.1):
		//
		//      S = I2OSP (s, k).
		int k = K.bitsize / 8;
		return i2osp(s, k);

	}

	/**
	 * 
	 * Verify an EMSA-PSS encoded signature.
	 * 
	 * @param K - The public key in the form of (n,e).
	 * @param M - The signed message octet string.
	 * @param S - The signature octet string.
	 * 
	 * @return True if the signature is valid, otherwise false.
	 * 
	 */
	public boolean rsassaPSSVerify(PublicKey K, byte[] M, byte[] S) {

		// Length check.
		int k = K.bitsize / 8;
		if (S.length != k) {
			// Fail silently
			return false;
		}

		// a. Convert the signature S to an integer signature representative s
		//
		//      s = OS2IP (S).
		//
		// b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
		//    RSA public key (n, e) and the signature representative s to
		//    produce an integer message representative m:
		//
		//       m = RSAVP1 ((n, e), s).
		//
		// If RSAVP1 output "signature representative out of range,"
		// output "invalid signature" and stop.
		try {
			BigInteger m = rsavp1(K, os2ip(S));

			// c. Convert the message representative m to an encoded message EM
			//    of length emLen = \ceil ((modBits - 1)/8) octets, where modBits
			//    is the length in bits of the RSA modulus n:
			//
			//      EM = I2OSP (m, emLen).
			//
			// Note that emLen will be one less than k if modBits - 1 is
			// divisible by 8 and equal to k otherwise.  If I2OSP outputs
			// "integer too large," output "invalid signature" and stop.
			int emLen = (int)Math.ceil((double)(K.bitsize - 1) / 8);
			byte[] EM = i2osp(m, emLen);

			return emsaPSSVerify(M, EM, K.bitsize - 1);

		}
		catch (BadParameterException e) {
			// Fail silently
			return false;
		}

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
	private BigInteger rsavp1(PublicKey K, BigInteger s)
			throws BadParameterException {

		// 1. If the signature representative m is not between 0 and n - 1, output
		//  "signature representative out of range" and stop.
		if (s.compareTo(BigInteger.ZERO) < 1 
				|| s.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new BadParameterException("Signature representative out of range");
		}

		// 2. Let m = s^e mod n.
		BigInteger m = s.modPow(K.e, K.n);

		return m;

	}

	/*
	 * Byte array bitwise exclusive or.
	 */
	private byte[] xor(byte[] a, byte[] b)
			throws BadParameterException {

		if (a.length != b.length) {
			throw new BadParameterException("Xor byte arrays must be same length");
		}

		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; ++i) {
			result[i] = (byte)((a[i] ^ b[i]) & 0xff);
		}
		return result;
	}

}
