/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.cipher.CKRSAmgf1;
import org.cryptokitty.provider.digest.CKSHA224;
import org.cryptokitty.provider.digest.CKSHA256;
import org.cryptokitty.provider.digest.CKSHA384;
import org.cryptokitty.provider.digest.CKSHA512;
import org.cryptokitty.provider.digest.Digest;
import org.cryptokitty.provider.keys.CKRSAPrivateKey;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * This class implements the RSA PSS signing scheme
 */
public class PSSrsassa extends RSASignature {

	/**
	 * Intended salt length for EMSA-PSS signature encoding
	 */
	private int sLen;

	/**
	 * Message digest.
	 */
	private Digest digest;

	/**
	 * Digest length.
	 */
	private int digestLength;
	
	/**
	 * @param hashAlgorithm
	 * @param sLen
	 * @throws UnsupportedAlgorithmException
	 */
	public PSSrsassa(DigestTypes type) {

		this.digestType = type;
		switch (type) {
		case SHA224:
			digest = new CKSHA224();
			break;
		case SHA256:
			digest = new CKSHA256();
			break;
		case SHA384:
			digest = new CKSHA384();
			break;
		case SHA512:
			digest = new CKSHA512();
			break;
		}
		digestLength = digest.getDigestLength();

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
									throws SignatureException {

		// The check here for message size with respect to the hash input
		// size (~= 2 exabytes for SHA1) isn't necessary.

		// 2.  Let mHash = Hash(M), an octet string of length hLen.
		byte[] mHash = digest.digest(M);

		// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
		int hLen = digestLength;
		int emLen = (int)Math.ceil((double)emBits / 8);
		if (emLen < hLen + sLen + 2) {
			throw new SignatureException("Invalid signature");
		}

		// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
		//     then salt is the empty string.
		byte[] salt = new byte[sLen];
		if (salt.length > 0) {
			try {
				SecureRandom rnd = SecureRandom.getInstanceStrong();
				rnd.nextBytes(salt);
			}
			catch (NoSuchAlgorithmException e) {
				throw new SignatureException("Invalid signature");
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
		byte[] H = digest.digest(mPrime);

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

		try {
			// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
			CKRSAmgf1 dbmgf = new CKRSAmgf1(digestType);
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
			throw new RuntimeException("Illegal array operation");
			}

			// 13. Output EM.
			return EM.toByteArray();
		}
		catch (BadPaddingException e) {
			throw new SignatureException("Invalid signature");
		}

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#sign()
	 */
	@Override
	public byte[] sign(CKRSAPrivateKey K, byte[] M)
								throws SignatureException {

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
		byte[] EM = emsaPSSEncode(M, K.getBitsize() - 1);

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
		BigInteger s = K.rsasp1(m);

		// c. Convert the signature representative s to a signature S of
		//    length k octets (see Section 4.1):
		//
		//      S = I2OSP (s, k).
		int k = K.getBitsize() / 8;
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
	 * @throws SignatureException 
	 */
	public boolean emsaPSSVerify(byte[] M, byte[] EM, int emBits) throws SignatureException {

		// 1.  If the length of M is greater than the input limitation for the
		//     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
		//     and stop.
		//
		// As noted before, this test is impractical since the actual size limit
		// for SHA1 is 2^64 - 1 octets and Java cannot create a string or array
		// longer than 2^63 - 1.

		// 2.  Let mHash = Hash(M), an octet string of length hLen.
		byte[] mHash = digest.digest(M);

		// 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
		int hLen = digestLength;
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
		CKRSAmgf1 dbmgf = new CKRSAmgf1(digestType);
		byte[] dbMask;
		try {
			dbMask = dbmgf.generateMask(H, emLen - hLen - 1);
		}
		catch (BadPaddingException e) {
			throw new SignatureException("Invalid signature");
		}

		// 8.  Let DB = maskedDB \xor dbMask.
		byte[] DB = xor(maskedDB, dbMask);

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
		byte[] hPrime = digest.digest(mPrime);

		// 14. If H = H', output "consistent." Otherwise, output "inconsistent."
		return Arrays.equals(H, hPrime);

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#setHashAlgorithm(String)
	 
	@Override
	public void setHashAlgorithm(String hashAlgorithm)
					throws NoSuchAlgorithmException, NoSuchProviderException {

		this.hashAlgorithm = hashAlgorithm;
		digest = MessageDigest.getInstance(hashAlgorithm, "CK");
		digestLength = digest.getDigestLength();

	}*/

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#setSeedLength(int)
	 */
	@Override
	public void setSeedLength(int seedLen) {
		
		sLen = seedLen;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#verify()
	 */
	@Override
	public boolean verify(CKRSAPublicKey K, byte[] M, byte[] S)
									throws SignatureException {

		// Length check.
		int k = K.getBitsize() / 8;
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
		int emLen = (int)Math.ceil((double)(K.getBitsize() - 1) / 8);
		byte[] EM = i2osp(m, emLen);
		return emsaPSSVerify(M, EM, K.getBitsize() - 1);

	}

}
