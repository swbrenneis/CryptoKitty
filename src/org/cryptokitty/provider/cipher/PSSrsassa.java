/**
 * 
 */
package org.cryptokitty.provider.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.EncodingException;
import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA PSS signing scheme
 */
public class PSSrsassa extends RSA {

	/*
	 * Intended salt length for EMSA-PSS signature encoding
	 */
	private int sLen;

	/**
	 * @param hashAlgorithm
	 * @param sLen
	 * @throws UnsupportedAlgorithmException
	 */
	public PSSrsassa(String hashAlgorithm, int sLen)
			throws UnsupportedAlgorithmException {

		this.sLen = sLen;
		this.hashAlgorithm = hashAlgorithm;
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
		default:
			throw new UnsupportedAlgorithmException("Invalid hash algorithm");
		}

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#decrypt(org.cryptokitty.provider.RSA.PrivateKey, byte[])
	 */
	@Override
	public byte[] decrypt(PrivateKey K, byte[] C) {
		// Operation not supported. Fail silently.
		return null;
	}

	/**
	 * Message signature encoding operation.
	 * 
	 * @param M - Message octet string.
	 * @param emBits - maximal bit length of the integer representation of
	 * 					the encoded message.
	 * 
	 * @return Encoded octet string.
	 * 
	 * @throws ProviderException
	 */
	private byte[] emsaPSSEncode(byte[] M, int emBits)
			throws ProviderException {

		// The check here for message size with respect to the hash input
		// size (~= 2 exabytes for SHA1) isn't necessary.

		// 2.  Let mHash = Hash(M), an octet string of length hLen.
		Digest hash = Digest.getInstance(hashAlgorithm);
		byte[] mHash = hash.digest(M);

		// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
		int hLen = hash.getDigestLength();
		int emLen = (int)Math.ceil((double)emBits / 8);
		if (emLen < hLen + sLen + 2) {
			throw new EncodingException("Encoding error");
		}

		// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
		//     then salt is the empty string.
		byte[] salt = new byte[sLen];
		if (salt.length > 0) {
			try {
				SecureRandom rnd =
						SecureRandom.getInstance("CMWC", "CryptoKitty");
				rnd.nextBytes(salt);
			}
			catch (NoSuchAlgorithmException e) {
				// Shouldn't happen, but...
				throw new EncodingException(e);
			}
			catch (NoSuchProviderException e) {
				// Shouldn't happen, but...
				throw new EncodingException(e);
			}
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
		// hash.reset(); Not needed CK hashes don't retain state.
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
		}
		maskedDB[0] = (byte)(maskedDB[0] & bitmask);

		// 12. Let EM = maskedDB || H || 0xbc.
		ByteArrayOutputStream EM = new ByteArrayOutputStream();
		try {
			EM.write(maskedDB);
			EM.write(H);
			EM.write((byte)0xbc);
		}
		catch (IOException e) {
			// Not happening
			throw new EncodingException("Illegal array operation");
		}

		// 13. Output EM.
		return EM.toByteArray();

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#encrypt(org.cryptokitty.provider.RSA.PublicKey, byte[])
	 */
	@Override
	public byte[] encrypt(PublicKey K, byte[] M) throws ProviderException {
		throw new ProviderException("Illegal operation");
	}

	/**
	 * Sign a message.
	 * 
	 * @param K - The private key.
	 * @param M - Message octet string to be signed
	 * 
	 * @return Signature octet string.
	 */
	public byte[] sign(PrivateKey K, byte[] M)
			throws ProviderException {

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
		if (K instanceof CRTPrivateKey) {
			s = rsasp1((CRTPrivateKey)K, m);
		}
		else {
			throw new BadParameterException("Invalid private key");
		}

		// c. Convert the signature representative s to a signature S of
		//    length k octets (see Section 4.1):
		//
		//      S = I2OSP (s, k).
		int k = K.bitsize / 8;
		return i2osp(s, k);

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
	public boolean emsaPSSVerify(byte[] M, byte[] EM, int emBits) {

		// 1.  If the length of M is greater than the input limitation for the
		//     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
		//     and stop.
		//
		// As noted before, this test is impractical since the actual size limit
		// for SHA1 is 2^64 - 1 octets and Java cannot create a string or array
		// longer than 2^63 - 1.

		// 2.  Let mHash = Hash(M), an octet string of length hLen.
		Digest hash = null;
		try {
			hash = Digest.getInstance(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen. The has algorithm was verified in the constructor.
			return false;
		}
		byte[] mHash = hash.digest(M);

		// 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
		int hLen = hash.getDigestLength();
		int emLen = (int)Math.ceil((double)emBits / 8);
		if (emLen < hLen + sLen + 2) {
			return false;
		}

		// 4.  If the rightmost octet of EM does not have hexadecimal value
		//     0xbc, output "inconsistent" and stop.
		if (EM[EM.length - 1] != 0xbc) {
			return false;
		}

		// 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
		//     let H be the next hLen octets.
		int masklength = emLen - hLen - 1;
		byte[] maskedDB = Arrays.copyOf(EM, masklength);
		byte[] H = Arrays.copyOfRange(maskedDB, masklength, maskedDB.length);

		// 6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
		//     maskedDB are not all equal to zero, output "inconsistent" and
		//     stop.
		byte bitmask = (byte)0xff;
		bitmask = (byte)((bitmask >>> ((8 * emLen) - emBits)) & 0xff);
		byte invert = (byte)(bitmask ^ 0xff);
		if ((maskedDB[0] & invert) != 0) {
			return false;
		}

		// 7.  Let dbMask = MGF(H, emLen - hLen - 1).
		MGF1 dbmgf = new MGF1(hashAlgorithm);
		byte[] dbMask;
		try {
			dbMask = dbmgf.generateMask(H, emLen - hLen - 1);
		}
		catch (BadParameterException e) {
			// Fail silently
			return false;
		}

		// 8.  Let DB = maskedDB \xor dbMask.
		byte[] DB;
		try {
			DB = xor(maskedDB, dbMask);
		}
		catch (BadParameterException e) {
			// Fail silently
			return false;
		}

		// 9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
		//     to zero.
		bitmask = (byte)0xff;
		bitmask = (byte)((bitmask >>> ((8 * emLen) - emBits)) & 0xff);
		DB[0] = (byte)(DB[0] & bitmask);

		// 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
		//     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
		//     position is "position 1") does not have hexadecimal value 0x01,
		//     output "inconsistent" and stop.
		//
		// TODO umm...
		for (int i = 0; i < emLen - hLen - sLen - 2; ++i) {
			if (DB[i] != 0) {
				return false;
			}
		}
		if (DB[emLen - hLen - sLen - 1] != 0x01) {
			return false;
		}

		// 11.  Let salt be the last sLen octets of DB.
		byte[] salt = Arrays.copyOfRange(DB, DB.length - sLen, DB.length);

		// 12.  Let
		//        M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
		//
		// M' is an octet string of length 8 + hLen + sLen with eight
		// initial zero octets.
		byte[] mPrime = new byte[8 + hLen + sLen];
		Arrays.fill(mPrime, (byte)0x00);
		System.arraycopy(mHash, 0, mPrime, 8, mHash.length);
		System.arraycopy(salt, 0, mPrime, 8 + hLen, sLen);

		// 13. Let H' = Hash(M'), an octet string of length hLen.
		// hash.reset(); Not needed. CK digests don't retail state.
		byte[] hPrime = hash.digest(mPrime);

		// 14. If H = H', output "consistent." Otherwise, output "inconsistent."
		return Arrays.equals(H, hPrime);

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
	public boolean verify(PublicKey K, byte[] M, byte[] S) {

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
		catch (ProviderException e) {
			// Fail silently
			return false;
		}

	}

}
