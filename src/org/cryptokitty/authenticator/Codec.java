/**
 * 
 */
package org.cryptokitty.authenticator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.cryptokitty.data.DataException;
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
	public static RSAPublicKey decodeKey(InputStream data)
			throws DataException, IOException {

		int size = new Scalar32(data).getValue();
		byte[] keyBytes = new byte[size];
		data.read(keyBytes);
		BigInteger n = new BigInteger(1, keyBytes);
		size = new Scalar32(data).getValue();
		keyBytes = new byte[size];
		data.read(keyBytes);
		BigInteger e = new BigInteger(1, keyBytes);
		
		return new CKRSAPublicKey(n, e);

	}

	/*
	 * Decode an AuthenticatorWork POD.
	 * 
	 * Encoding is:
	 * iteration count || salt || signature length || signature
	 */
	public static AuthenticatorWork decodeWork(InputStream data)
			throws DataException, IOException {

		AuthenticatorWork work = new AuthenticatorWork();
		work.iterations = new Scalar64(data).getValue();
		work.salt = new byte[8];
		data.read(work.salt);	// Salt is always 8 bytes
		int sLen = new Scalar32(data).getValue();
		work.signature = new byte[sLen];
		data.read(work.signature);

		return work;

	}

	/*
	 * Decode a ServerKeys POD.
	 * 
	 * Encoding is:
	 * encoded encryption key || encoded signing key
	 */
	public static ServerKeys decodeServerKeys(InputStream data)
			throws DataException, IOException {

		ServerKeys keys = new ServerKeys();
		keys.encrypt = decodeKey(data);
		keys.sign = decodeKey(data);

		return keys;

	}

	/*
	 * Encode an RSA key.
	 * 
	 * Encoding is:
	 * 
	 * modulus length || modulus || exponent length || exponent
	 */
	public static void encodeKey(RSAPublicKey key, OutputStream out)
			throws IOException {

		byte[] n = key.getModulus().toByteArray();
		byte[] e = key.getPublicExponent().toByteArray();

		out.write(Scalar32.encode(n.length));
		out.write(n);
		out.write(Scalar32.encode(e.length));
		out.write(e);

	}

	/*
	 * Encode a ServerKeys POD.
	 * 
	 * Encoding is:
	 * encoded encryption key || encoded signing key
	 */
	public static void encodeServerKeys(ServerKeys keys, OutputStream out)
			throws IOException {

		encodeKey(keys.encrypt, out);
		encodeKey(keys.sign, out);

	}

	/*
	 * Encode an AuthenticatorWork POD.
	 * 
	 * Encoding is:
	 * iteration count || salt || signature length || signature
	 */
	public static void encodeWork(AuthenticatorWork work, OutputStream out)
			throws IOException {

		out.write(Scalar64.encode(work.iterations));
		out.write(work.salt);
		out.write(Scalar64.encode(work.signature.length));
		out.write(work.signature);

	}

}
