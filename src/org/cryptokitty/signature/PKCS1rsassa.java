/**
 * 
 */
package org.cryptokitty.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.cryptokitty.digest.Digest;
import org.cryptokitty.digest.SHA224;
import org.cryptokitty.digest.SHA256;
import org.cryptokitty.digest.SHA384;
import org.cryptokitty.digest.SHA512;
import org.cryptokitty.exceptions.SignatureException;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * This class implements the PKCS #1 v1.5 encoded signing.
 */
public class PKCS1rsassa extends RSASignature {

	/**
	 * DER hash algorithm identifiers.
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
	 */

	/*
	 * The ASN.1 hash algorithm identifier.
	 */
	private byte[] algorithmOID;
	
	/**
	 * Message digest
	 */
	private Digest digest;

	/**
	 * 
	 */
	public PKCS1rsassa(DigestTypes type) {

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
		//digestLength = digest.getDigestLength();

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#sign()
	 */
	@Override
	public byte[] sign(RSAPrivateKey K, byte[] M)
									throws SignatureException {

		// 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
		//    operation (Section 9.2) to the message M to produce an encoded
		//    message EM of length k octets:
		//
		// If the encoding operation outputs "message too long," output
		// "message too long" and stop.  If the encoding operation outputs
		// "intended encoded message length too short," output "RSA modulus
		// too short" and stop.

		int k = K.getBitsize() / 8;
		byte[] EM = emsaPKCS1Encode(M, k);

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
		BigInteger s = K.rsasp1(os2ip(EM));

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
										throws SignatureException {

		// 1. Apply the hash function to the message M to produce a hash value
		//     H:
		//
		//         H = Digest(M).
		byte[] H = digest.digest(M);

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
			throw new SignatureException("Invalid signature");
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

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#setHashAlgorithm(String)
	 */
	/*@Override
	public void setHashAlgorithm(String hashAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
		// TODO Auto-generated method stub
		
		this.hashAlgorithm = hashAlgorithm;
		digest = MessageDigest.getInstance(hashAlgorithm, "CK");

	}*/

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#setSeedLength(int)
	 */
	@Override
	public void setSeedLength(int seedLen) {
		// TODO Auto-generated method stub
		
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.RSA#verify()
	 */
	@Override
	public boolean verify(RSAPublicKey K, byte[] M, byte[] S)
										throws SignatureException {

		// Length checking.
		// If the length of the signature S is not k octets,
		// output "invalid signature" and stop.
		int k = K.getBitsize() / 8;
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
		BigInteger m = rsavp1(K, os2ip(S));

		// Convert the message representative m to an encoded message EM
		// of length k octets:
		//
		//    EM = I2OSP (m, k).
		byte[] EM = i2osp(m, k);

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
		byte[] emPrime = emsaPKCS1Encode(M, k);

		// Compare the encoded message EM and the second encoded message EM'.
		// If they are the same, output "valid signature"; otherwise, output
		// "invalid signature."
		return Arrays.equals(EM, emPrime);

	}

}
