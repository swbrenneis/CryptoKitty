/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.EncodingException;
import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.cipher.RSA;
import org.cryptokitty.provider.digest.Digest;

/**
 * @author Steve Brenneis
 *
 * This class implements the PKCS #1 v1.5 encoded signing.
 */
public class PKCS1rsassa extends RSA {

	/*
	 * DER hash algorithm identifiers.
	 */
	private final static byte[] SHA1_DER =
				{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
					0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
	private final static byte[] SHA256_DER =
				{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 
					0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
					0x00, 0x04, 0x20 };
	private final static byte[] SHA384_DER = 
				{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86,
					0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
					0x00, 0x04, 0x30 };
	private final static byte[] SHA512_DER = 
				{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86,
					0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
					0x00, 0x04, 0x40 };

	/*
	 * The ASN.1 hash algorithm identifier.
	 */
	private byte[] algorithmOID;

	/**
	 * 
	 */
	public PKCS1rsassa(String hashAlgorithm)
			throws UnsupportedAlgorithmException {

		this.hashAlgorithm = hashAlgorithm;
		switch(hashAlgorithm) {
		case "SHA-1":
			algorithmOID = SHA1_DER;
			maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
			break;
		case "SHA-256":
			algorithmOID = SHA256_DER;
			maxHash = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);
			break;
		case "SHA-384":
			algorithmOID = SHA384_DER;
			maxHash = BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);
			break;
		case "SHA-512":
			algorithmOID = SHA512_DER;
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

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#encrypt(org.cryptokitty.provider.RSA.PublicKey, byte[])
	 */
	@Override
	public byte[] encrypt(PublicKey K, byte[] M)
		throws ProviderException {
		throw new ProviderException("Operation not supported");
	}

	/**
	 * PKCS 1 v1.5 signing
	 * 
	 * @param K - Signer's private key.
	 * @param M - The message to be signed.
	 * 
	 * @return The signature as an octet string.
	 * @throws BadParameterException 
	 */
	public byte[] sign(PrivateKey K, byte[] M)
			throws ProviderException {

		// 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
		//    operation (Section 9.2) to the message M to produce an encoded
		//    message EM of length k octets:
		//
		// If the encoding operation outputs "message too long," output
		// "message too long" and stop.  If the encoding operation outputs
		// "intended encoded message length too short," output "RSA modulus
		// too short" and stop.

		int k = K.bitsize / 8;
		byte[] EM = null;
		try {
			EM = emsaPKCS1Encode(M, k);
		}
		catch (EncodingException e) {
			if (e.getMessage() == "Intended encoded message length too short") {
				throw new BadParameterException("RSA modulus too short");
			}
			else {
				throw e;
			}
		}

		// RSA signature
		//
		// Convert the encoded message EM to an integer message
		// representative m
		//
		//    m = OS2IP (EM).
		//
		// Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
		// private key K and the message representative m to produce an
		// integer signature representative s:
		//
		//    s = RSASP1 (K, m).
		BigInteger s;
		if (K instanceof ModulusPrivateKey) {
			s = rsasp1((ModulusPrivateKey)K, os2ip(EM));
		}
		else if (K instanceof CRTPrivateKey) {
			s = rsasp1((CRTPrivateKey)K, os2ip(EM));
		}
		else {
			throw new BadParameterException("Invalid private key");
		}

		// Convert the signature representative s to a signature S of
		// length k octets:
		//
		//    S = I2OSP (s, k).
		return i2osp(s, k);

	}

	/**
	 * EMSA-PKCS1 encoding.
	 * 
	 * @param - M the message to be encoded.
	 * @param - emLen - the intended length of the encoded message.
	 * 
	 * @return - The encoded message as an octet string
	 */
	private byte[] emsaPKCS1Encode(byte[] M, int emLen)
			throws EncodingException {

		// 1. Apply the hash function to the message M to produce a hash value
		//     H:
		//
		//         H = Digest(M).
		Digest hash = null;
		try {
			hash = Digest.getInstance(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen. The hash algorithm was verified in the constructor.
		}
		byte[] H = hash.digest(M);

		// 2. Encode the algorithm ID for the hash function and the hash value
		//    into an ASN.1 value of type DigestInfo with the Distinguished
		//    Encoding Rules (DER), where the type DigestInfo has the syntax
		//
		//      DigestInfo ::= SEQUENCE {
		//          digestAlgorithm AlgorithmIdentifier,
		//          digest OCTET STRING
		//      }
		//
		//    The first field identifies the hash function and the second
		//    contains the hash value.  Let T be the DER encoding of the
		//    DigestInfo value and let tLen be the length in octets of T.
		int tLen = H.length + algorithmOID.length;
		byte[] T = new byte[tLen];
		System.arraycopy(algorithmOID, 0, T, 0, algorithmOID.length);
		System.arraycopy(H, 0, T, algorithmOID.length, H.length);

		// 3. If emLen < tLen + 11, output "intended encoded message length too
		//    short" and stop.
		if (emLen < tLen + 11) {
			throw new EncodingException("Intended encoded message length too short");
		}

		// 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
		//    with hexadecimal value 0xff.  The length of PS will be at least 8
		//    octets.
		byte[] PS = new byte[emLen - tLen - 3];
		Arrays.fill(PS, (byte)0xff);

		// 5. Concatenate PS, the DER encoding T, and other padding to form the
		//    encoded message EM as
		//
		//       EM = 0x00 || 0x01 || PS || 0x00 || T.
		ByteArrayOutputStream EM = new ByteArrayOutputStream();
		try {
			EM.write(0x00);
			EM.write(0x01);
			EM.write(PS);
			EM.write(0x00);
			EM.write(T);
		}
		catch (IOException e) {
			// Not happening.
		}
		
		return EM.toByteArray();
		
	}

	/**
	 * PKCS 1 v1.5 verification.
	 * 
	 * @param K - Signer's public key.
	 * @param M - The message whose signature is to be verified.
	 * @param S - The signature to verify.
	 * 
	 * @return True if the signature is valid, otherwise false.
	 */
	public boolean verify(PublicKey K, byte[] M, byte[] S) {

		// Length checking.
		// If the length of the signature S is not k octets,
		// output "invalid signature" and stop.
		int k = K.bitsize / 8;
		if (S.length != k) {
			return false;
		}

		// RSA verification
		//
		// Convert the signature S to an integer signature representative s:
		//
		//    s = OS2IP (S).
		//
		// Apply the RSAVP1 verification primitive (Section 5.2.2) to the
		// RSA public key (n, e) and the signature representative s to
		// produce an integer message representative m:
		//
		//    m = RSAVP1 ((n, e), s).
		BigInteger m;
		try {
			m = rsavp1(K, os2ip(S));
		}
		catch (SignatureException e) {
			// Fail silently
			return false;
		}

		// Convert the message representative m to an encoded message EM
		// of length k octets:
		//
		//    EM = I2OSP (m, k).
		byte[] EM;
		try {
			EM = i2osp(m, k);
		}
		catch (BadParameterException e) {
			// Fail silently
			return false;
		}

		// Apply the EMSA-PKCS1-v1_5 encoding operation to the message M
		// to produce a second encoded message EM' of length k octets:
		//
		//    EM' = EMSA-PKCS1-V1_5-ENCODE (M, k).
		//
		// The RFC says:
		//
		// If the encoding operation outputs "message too long," output
		// "message too long" and stop.  If the encoding operation outputs
		// "intended encoded message length too short," output "RSA modulus
		// too short" and stop.
		//
		// This would violate the best practice of voiding the creation of
		// oracles. We will just fail silently on any exceptions.
		byte[] emPrime;
		try {
			emPrime = emsaPKCS1Encode(M, k);
		}
		catch (EncodingException e) {
			// Fail silently
			return false;
		}

		// Compare the encoded message EM and the second encoded message EM'.
		// If they are the same, output "valid signature"; otherwise, output
		// "invalid signature."
		return Arrays.equals(EM, emPrime);

	}

}
