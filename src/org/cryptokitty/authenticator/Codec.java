/**
 * 
 */
package org.cryptokitty.authenticator;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.data.Scalar64;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author stevebrenneis
 *
 * Encoder/decoder for client and server responses.
 */
public class Codec {

	/**
	 * 
	 */
	public Codec() {
		// Default constructor
	}

	/*
	 * Decode an RSA key.
	 * 
	 * Encoding is:
	 * 
	 * modulus length || modulus || exponent length || exponent
	 */
	public RSAPublicKey decodeKey(byte[] data) {

		int nsize = Scalar32.decode(Arrays.copyOf(data, 4));
		BigInteger n = new BigInteger(1, Arrays.copyOfRange(data, 4, nsize+4));
		int esize = Scalar32.decode(Arrays.copyOfRange(data, nsize+4, nsize+8));
		BigInteger e = new BigInteger(1, Arrays.copyOfRange(data, nsize+8, nsize+esize+8));
		
		return new CKRSAPublicKey(n, e);

	}

	/*
	 * Decode an AuthenticatorWork POD.
	 * 
	 * Encoding is:
	 * iteration count || salt || signature length || signature
	 */
	public AuthenticatorWork decodeWork(byte[] data) {

		AuthenticatorWork work = new AuthenticatorWork();
		work.iterations = Scalar64.decode(Arrays.copyOf(data, 8));
		work.salt = Arrays.copyOfRange(data, 8, 16);	// Salt is always 8 bytes
		int sLen = Scalar32.decode(Arrays.copyOfRange(data, 16, 20));
		work.signature = Arrays.copyOfRange(data, 20, sLen+20);

		return work;

	}

	/*
	 * Decode a ServerKeys POD.
	 * 
	 * Encoding is:
	 * encoded encryption key || encoded signing key
	 */
	public ServerKeys decodeServerKeys(byte[] data) {

		ServerKeys keys = new ServerKeys();
		keys.encrypt = decodeKey(data);
		int offset = Scalar32.decode(Arrays.copyOf(data, 4)) + 4;
		keys.sign = decodeKey(Arrays.copyOfRange(data, offset, data.length));

		return keys;

	}

	/*
	 * Encode an RSA key.
	 * 
	 * Encoding is:
	 * 
	 * modulus length || modulus || exponent length || exponent
	 */
	public byte[] encodeKey(RSAPublicKey key) {

		byte[] n = key.getModulus().toByteArray();
		byte[] e = key.getPublicExponent().toByteArray();

		byte[] encoded = new byte[n.length + e.length + 8];
		int index = 0;
		System.arraycopy(Scalar32.encode(n.length), 0, encoded, 0, 4);
		index += 4;
		System.arraycopy(n, 0, encoded, index, n.length);
		index += n.length;
		System.arraycopy(Scalar32.encode(e.length), 0, encoded, index, 4);
		index += 4;
		System.arraycopy(e, 0, encoded, index, e.length);

		return encoded;
	}

	/*
	 * Encode a ServerKeys POD.
	 * 
	 * Encoding is:
	 * encoded encryption key || encoded signing key
	 */
	public byte[] encodeServerKeys(ServerKeys keys) {

		byte[] encrypt = encodeKey(keys.encrypt);
		byte[] sign = encodeKey(keys.sign);
		byte[] encoded = new byte[encrypt.length + sign.length];
		System.arraycopy(encrypt, 0, encoded, 0, encrypt.length);
		System.arraycopy(sign, 0, encoded, encrypt.length, sign.length);

		return encoded;

	}

	/*
	 * Encode an AuthenticatorWork POD.
	 * 
	 * Encoding is:
	 * iteration count || salt || signature length || signature
	 */
	public byte[] encodeWork(AuthenticatorWork work) {

		byte[] encoded = new byte[8 + 8 + 4 + work.signature.length];

		System.arraycopy(Scalar64.encode(work.iterations), 0, encoded, 0, 8);
		System.arraycopy(work.salt, 0, encoded, 8, 8);
		System.arraycopy(Scalar32.encode(work.signature.length), 0, encoded, 16, 4);
		System.arraycopy(work.signature, 0, encoded, 20, work.signature.length);

		return encoded;

	}

}
