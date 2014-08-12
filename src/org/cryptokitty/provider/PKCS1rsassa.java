/**
 * 
 */
package org.cryptokitty.provider;

import java.math.BigInteger;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * This class implements the PKCS 1 v1.5 encoded signing.
 */
public class PKCS1rsassa extends RSA {

	/**
	 * 
	 */
	public PKCS1rsassa(int hashAgorithm)
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
	 * PKCS 1 v1.5 signing
	 * 
	 * @param K - Signer's private key.
	 * @param M - The message to be signed.
	 * 
	 * @return The signature as an octet string.
	 */
	public byte[] sign(PrivateKey K, byte[] M) {

		// 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
		//    operation (Section 9.2) to the message M to produce an encoded
		//    message EM of length k octets:

		int k = K.bitsize / 8;
		byte[] EM = emsaPKCS1Encode(M, k);

		// If the encoding operation outputs "message too long," output
		// "message too long" and stop.  If the encoding operation outputs
		// "intended encoded message length too short," output "RSA modulus
		// too short" and stop.

/*	   2. RSA signature:

	      a. Convert the encoded message EM to an integer message
	         representative m (see Section 4.2):

	            m = OS2IP (EM).

	      b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
	         private key K and the message representative m to produce an
	         integer signature representative s:

	            s = RSASP1 (K, m).

	      c. Convert the signature representative s to a signature S of
	         length k octets (see Section 4.1):

	            S = I2OSP (s, k).

	   3. Output the signature S.*/
		return null;
	}

	/**
	 * PKCS 1 v1.5 signing
	 * 
	 * @param K - Signer's public key.
	 * @param M - The message whose signature is to be verified.
	 * @param S - The signature to verify.
	 * 
	 * @return True if the signature is valid, otherwise false.
	 */
	public boolean verify(PublicKey K, byte[] M, byte[] S) {
/*
	   RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

	   Input:
	   (n, e)   signer's RSA public key
	   M        message whose signature is to be verified, an octet string
	   S        signature to be verified, an octet string of length k, where
	            k is the length in octets of the RSA modulus n

	   Output:
	   "valid signature" or "invalid signature"

	   Errors: "message too long"; "RSA modulus too short"

	   Steps:

	   1. Length checking: If the length of the signature S is not k octets,
	      output "invalid signature" and stop.

	   2. RSA verification:

	      a. Convert the signature S to an integer signature representative
	         s (see Section 4.2):

	            s = OS2IP (S).

	      b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
	         RSA public key (n, e) and the signature representative s to
	         produce an integer message representative m:

	            m = RSAVP1 ((n, e), s).

	         If RSAVP1 outputs "signature representative out of range,"
	         output "invalid signature" and stop.

	      c. Convert the message representative m to an encoded message EM
	         of length k octets (see Section 4.1):

	            EM' = I2OSP (m, k).

	         If I2OSP outputs "integer too large," output "invalid
	         signature" and stop.

	   3. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
	      operation (Section 9.2) to the message M to produce a second
	      encoded message EM' of length k octets:

	            EM' = EMSA-PKCS1-V1_5-ENCODE (M, k).

	      If the encoding operation outputs "message too long," output
	      "message too long" and stop.  If the encoding operation outputs
	      "intended encoded message length too short," output "RSA modulus
	      too short" and stop.

	   4. Compare the encoded message EM and the second encoded message EM'.
	      If they are the same, output "valid signature"; otherwise, output
	      "invalid signature." */
		return false;
	}

	/**
	 * EMSA-PKCS1 encoding.
	 * 
	 * @param - M the message to be encoded.
	 * @param - emLen - the intended length of the encoded message.
	 * 
	 * @return - The encoded message as an octet string
	 */
	private byte[] emsaPKCS1Encode(byte[] M, int emLen) {
	   /*   EMSA-PKCS1-v1_5-ENCODE (M, emLen)

	      Option:
	      Hash     hash function (hLen denotes the length in octets of the hash
	               function output)

	      Input:
	      M        message to be encoded
	      emLen    intended length in octets of the encoded message, at least
	               tLen + 11, where tLen is the octet length of the DER
	               encoding T of a certain value computed during the encoding
	               operation

	      Output:
	      EM       encoded message, an octet string of length emLen

	      Errors:
	      "message too long"; "intended encoded message length too short"
*/
		// 1. Apply the hash function to the message M to produce a hash value
		//     H:
		//
		//         H = Hash(M).
		Hash hash = null;
		try {
			hash = HashFactory.getDigest(hashAlgorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen. The hash algorithm was verified in the constructor.
		}

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

/*	      3. If emLen < tLen + 11, output "intended encoded message length too
	         short" and stop.

	      4. Generate an octet string PS consisting of emLen - tLen - 3 octets
	         with hexadecimal value 0xff.  The length of PS will be at least 8
	         octets.

	      5. Concatenate PS, the DER encoding T, and other padding to form the
	         encoded message EM as

	            EM = 0x00 || 0x01 || PS || 0x00 || T.

	      6. Output EM. */
		
		return null;
		
	}

}
