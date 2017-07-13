/**
 * 
 */
package org.cryptokitty.codec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Arrays;

import org.cryptokitty.exceptions.CodecException;
import org.cryptokitty.jni.BigInteger;
import org.cryptokitty.keys.RSAPrivateCrtKey;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPrivateModKey;
import org.cryptokitty.keys.RSAPublicKey;

/**
 * @author stevebrenneis
 *
 * This is used to encode/decode CryptoKitty keys.
 * 
 */
public class PEMCodec {

	/**
	 * Preambles and epilogues
	 */
	private static final String RSA_PUBLIC_PREAMBLE = "-----BEGIN RSA PUBLIC KEY-----";
	private static final String PUBLIC_PREAMBLE = "-----BEGIN PUBLIC KEY-----";
	private static final String RSA_PRIVATE_PREAMBLE = "-----BEGIN RSA PRIVATE KEY-----";
	private static final String PRIVATE_PREAMBLE = "-----BEGIN PRIVATE KEY-----";
	private static final String RSA_PUBLIC_EPILOGUE = "-----END RSA PUBLIC KEY-----";
	private static final String PUBLIC_EPILOGUE = "-----END PUBLIC KEY-----";
	private static final String RSA_PRIVATE_EPILOGUE = "-----END RSA PRIVATE KEY-----";
	private static final String PRIVATE_EPILOGUE = "-----END PRIVATE KEY-----";

	/**
	 * Private key versions.
	 */
	public static final byte[] TWO_PRIME_VERSION = { 0 };
	public static final byte[] MULTIPRIME_VERSION = { 1 };

	/**
	 * Flag for X509 keys or raw RSA keys.
	 */
	private boolean x509Keys;

	/**
	 * ASN.1 DER encoder/decoder.
	 */
	private DERCodec derCodec;

	/**
	 * 
	 */
	public PEMCodec() {
		// TODO Auto-generated constructor stub
	}

	public PEMCodec(boolean x509Keys) {

		this.x509Keys = x509Keys;

	}

	/**
	 * 
	 * @param keyString
	 * @return
	 * @throws CodecException
	 */
	public RSAPrivateKey decodePrivateKey(String keyString) throws CodecException {

		if (keyString.startsWith(RSA_PRIVATE_PREAMBLE)) {
			x509Keys = false;
		}
		else if (keyString.startsWith(PRIVATE_PREAMBLE)) {
			x509Keys = true;
		}
		else {
			throw new CodecException("Not a PEM format private key");
		}

		try {
			byte[] decoded = Base64Wrapper.decodePEM(keyString);
			ByteArrayInputStream encoded =
								new ByteArrayInputStream(decoded);

			derCodec = new DERCodec();
			ByteArrayOutputStream sequence = new ByteArrayOutputStream();
			derCodec.getSequence(encoded, sequence);
			// The sequence should be the entire array.
			if (encoded.available() > 0) {
				throw new CodecException("Invalid private key encoding");
			}

			ByteArrayInputStream seq = new ByteArrayInputStream(sequence.toByteArray());
			if (x509Keys) {
				return parsePrivateKey(seq);
			}
			else {
				return getPrivateKey(seq);
			}
		}
		catch (IOException e) {
			throw new CodecException("I/O error: " + e.getLocalizedMessage());
		}

	}

	/**
	 * 
	 * @param keyString
	 * @return
	 * @throws CodecException 
	 */
	public RSAPublicKey decodePublicFromPrivate(String keyString) throws CodecException {

		if (keyString.startsWith(RSA_PRIVATE_PREAMBLE)) {
			x509Keys = false;
		}
		else if (keyString.startsWith(PRIVATE_PREAMBLE)) {
			x509Keys = true;
		}
		else {
			throw new CodecException("Not a PEM format private key");
		}

		try {
			byte[] decoded = Base64Wrapper.decodePEM(keyString);
			ByteArrayInputStream encoded =
								new ByteArrayInputStream(decoded);

			derCodec = new DERCodec();
			ByteArrayOutputStream sequence = new ByteArrayOutputStream();
			derCodec.getSequence(encoded, sequence);
			// The sequence should be the entire array.
			if (encoded.available() > 0) {
				throw new CodecException("Invalid private key encoding");
			}

			ByteArrayInputStream seq = new ByteArrayInputStream(sequence.toByteArray());
			if (x509Keys) {
				return parsePublicFromPrivate(seq);
			}
			else {
				return getPublicFromPrivate(seq);
			}
		}
		catch (IOException e) {
			throw new CodecException("I/O error: " + e.getLocalizedMessage());
		}

	}

	/**
	 * 
	 * @param keyString
	 * @return
	 * @throws CodecException 
	 */
	public RSAPublicKey decodePublicKey(String keyString) throws CodecException {

		if (keyString.startsWith(RSA_PUBLIC_PREAMBLE)) {
			x509Keys = false;
		}
		else if (keyString.startsWith(PUBLIC_PREAMBLE)) {
			x509Keys = true;
		}
		else {
			throw new CodecException("Not a PEM format key");
		}

		try {
			byte[] decoded = Base64Wrapper.decodePEM(keyString);
			ByteArrayInputStream encoded =
								new ByteArrayInputStream(decoded);

			derCodec = new DERCodec();
			ByteArrayOutputStream sequence = new ByteArrayOutputStream();
			derCodec.getSequence(encoded, sequence);
			// The sequence should be the entire array.
			if (encoded.available() > 0) {
				throw new CodecException("Invalid private key encoding");
			}

			ByteArrayInputStream seq = new ByteArrayInputStream(sequence.toByteArray());
			if (x509Keys) {
				return parsePublicKey(seq);
			}
			else {
				return getPublicKey(seq);
			}
		}
		catch (IOException e) {
			throw new CodecException("I/O error: " + e.getLocalizedMessage());
		}
	}

	/**
	 * 
	 * @param out
	 * @param key
	 */
	public void encode(StringWriter out, RSAPrivateKey privateKey, RSAPublicKey publicKey) {

		if (x509Keys) {
			out.write(PRIVATE_PREAMBLE);
		}
		else {
			out.write(RSA_PRIVATE_PREAMBLE);
		}
		out.write("\n");

		derCodec = new DERCodec();
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		if (privateKey instanceof RSAPrivateModKey) {
			encodeTwoPrimeKey(keyBytes, (RSAPrivateModKey)privateKey);
		}
		else {
			encodeMultiprimeKey(keyBytes, (RSAPrivateCrtKey)privateKey, publicKey);
		}

		ByteArrayOutputStream sequence;
		if (x509Keys ) {
			sequence= new ByteArrayOutputStream();
			derCodec.encodeSequence(sequence, keyBytes.toByteArray());
		}
		else {
			sequence = keyBytes;
		}
		try {
			ByteArrayOutputStream base64 = new ByteArrayOutputStream();
			Base64Wrapper.encodePEM(base64, sequence.toByteArray());
			out.write(new String(base64.toByteArray(), "UTF-8"));
		}
		catch(IOException e) {
			
		}

		if (x509Keys) {
			out.write(PRIVATE_EPILOGUE);
		}
		else {
			out.write(RSA_PRIVATE_EPILOGUE);
		}

	}

	/**
	 * 
	 * @param out
	 * @param key
	 */
	public void encode(StringWriter out, RSAPublicKey key) {

		if (x509Keys) {
			out.write(PUBLIC_PREAMBLE);
		}
		else {
			out.write(RSA_PUBLIC_PREAMBLE);
		}
		out.write("\n");

		derCodec = new DERCodec();
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		encodePublicKey(keyBytes, key);

		ByteArrayOutputStream sequence;
		if (x509Keys ) {
			sequence= new ByteArrayOutputStream();
			derCodec.encodeSequence(sequence, keyBytes.toByteArray());
		}
		else {
			sequence = keyBytes;
		}
		try {
			ByteArrayOutputStream base64 = new ByteArrayOutputStream();
			Base64Wrapper.encodePEM(base64, sequence.toByteArray());
			out.write(new String(base64.toByteArray(), "UTF-8"));
		}
		catch(IOException e) {
			// Nope
		}

		if (x509Keys) {
			out.write(PUBLIC_EPILOGUE);
		}
		else {
			out.write(RSA_PUBLIC_EPILOGUE);
		}

	}

	/**
	 * 
	 * @param out
	 * @param key
	 */
	private void encodeMultiprimeKey(ByteArrayOutputStream out,
				RSAPrivateCrtKey privateKey, RSAPublicKey publicKey) {

		ByteArrayOutputStream primes = new ByteArrayOutputStream();
		derCodec.encodeInteger(primes, MULTIPRIME_VERSION);
		encodePrimes(primes, privateKey, publicKey);

		if (x509Keys) {
			derCodec.encodeInteger(out, MULTIPRIME_VERSION);
			derCodec.encodeAlgorithm(out);
			ByteArrayOutputStream primeSeq = new ByteArrayOutputStream();
			derCodec.encodeSequence(primeSeq, primes.toByteArray());
			derCodec.encodeOctetString(out, primeSeq.toByteArray());
		}
		else {
			try {
				out.write(primes.toByteArray());
			}
			catch (IOException e) {
				// Stupid Java
			}
		}

	}

	/**
	 * 
	 * @param out
	 * @param privateKey
	 * @param publicKey
	 */
	private void encodePrimes(ByteArrayOutputStream out,
					RSAPrivateCrtKey privateKey, RSAPublicKey publicKey) {

		derCodec.encodeInteger(out, privateKey.getModulus().getEncoded());
		derCodec.encodeInteger(out, publicKey.getPublicExponent().getEncoded());
		derCodec.encodeInteger(out, privateKey.getPrivateExponent().getEncoded());
		derCodec.encodeInteger(out, privateKey.getPrimeP().getEncoded());
		derCodec.encodeInteger(out, privateKey.getPrimeQ().getEncoded());
		derCodec.encodeInteger(out, privateKey.getPrimeExponentP().getEncoded());
		derCodec.encodeInteger(out, privateKey.getPrimeExponentQ().getEncoded());
		derCodec.encodeInteger(out, privateKey.getCrtCoefficient().getEncoded());

	}

	/**
	 * 
	 * @param out
	 * @param key
	 */
	private void encodePrimes(ByteArrayOutputStream out, RSAPrivateModKey key) {

		derCodec.encodeInteger(out, key.getModulus().getEncoded());
		derCodec.encodeInteger(out, key.getPrivateExponent().getEncoded());

	}

	/**
	 * 
	 * @param out
	 * @param key
	 */
	private void encodePublicKey(ByteArrayOutputStream out, RSAPublicKey key) {

		ByteArrayOutputStream primes = new ByteArrayOutputStream();
		derCodec.encodeInteger(primes, key.getModulus().getEncoded());
		derCodec.encodeInteger(primes, key.getPublicExponent().getEncoded());
		
		try {
			if (x509Keys) {
				derCodec.encodeAlgorithm(out);
				ByteArrayOutputStream primeSeq = new ByteArrayOutputStream();
				derCodec.encodeSequence(primeSeq, primes.toByteArray());
				ByteArrayOutputStream bitstring = new ByteArrayOutputStream();
				derCodec.encodeBitString(bitstring, primeSeq.toByteArray());
				out.write(bitstring.toByteArray());
			}
			else {
				out.write(primes.toByteArray());
			}
		}
		catch (IOException e) {
			// No thanks.
		}

	}

	/**
	 * 
	 * @param out The key body stream. This will be encoded to a sequence
	 * @param key
	 */
	private void encodeTwoPrimeKey(ByteArrayOutputStream out, RSAPrivateModKey key) {

		ByteArrayOutputStream primes = new ByteArrayOutputStream();
		derCodec.encodeInteger(primes, TWO_PRIME_VERSION);
		encodePrimes(primes, key);

		if (x509Keys) {
			derCodec.encodeInteger(out, TWO_PRIME_VERSION);
			derCodec.encodeAlgorithm(out);
			ByteArrayOutputStream primeSeq = new ByteArrayOutputStream();
			derCodec.encodeSequence(primeSeq, primes.toByteArray());
			derCodec.encodeOctetString(out, primeSeq.toByteArray());
		}
		else {
			try {
				out.write(primes.toByteArray());
			}
			catch (IOException e) {
				// Stupid Java
			}
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException 
	 */
	private RSAPrivateKey getPrivateKey(ByteArrayInputStream key) throws CodecException {

		ByteArrayOutputStream version = new ByteArrayOutputStream();
		derCodec.getInteger(key, version);		
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}
		byte[] vBytes = version.toByteArray();
		
		ByteArrayOutputStream nBytes = new ByteArrayOutputStream();
		derCodec.getInteger(key, nBytes);
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}
		BigInteger n = new BigInteger(nBytes.toByteArray());

		if (vBytes[0] == TWO_PRIME_VERSION[0]) {
			ByteArrayOutputStream dBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, dBytes);
			if (key.available() != 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger d = new BigInteger(dBytes.toByteArray());
			return new RSAPrivateModKey(n, d);
		}
		else if (vBytes[0] == MULTIPRIME_VERSION[0]) {
			ByteArrayOutputStream eBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, eBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			@SuppressWarnings("unused")
			BigInteger e = new BigInteger(eBytes.toByteArray());

			ByteArrayOutputStream dBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, dBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger d = new BigInteger(dBytes.toByteArray());

			ByteArrayOutputStream pBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, pBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger p = new BigInteger(pBytes.toByteArray());

			ByteArrayOutputStream qBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, qBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger q = new BigInteger(qBytes.toByteArray());

			ByteArrayOutputStream ppBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, ppBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger expp = new BigInteger(ppBytes.toByteArray());

			ByteArrayOutputStream qqBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, qqBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger expq = new BigInteger(qqBytes.toByteArray());

			ByteArrayOutputStream cBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, cBytes);
			if (key.available() != 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger coeff = new BigInteger(cBytes.toByteArray());
			RSAPrivateCrtKey k = new RSAPrivateCrtKey(p, q, expp, expq, coeff);
			k.setPrivateExponent(d);
			return k;
		}
		else {
			throw new CodecException("Invalid private key encoding");
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException
	 */
	private RSAPublicKey getPublicFromPrivate(ByteArrayInputStream key)
															throws CodecException {

		ByteArrayOutputStream version = new ByteArrayOutputStream();
		derCodec.getInteger(key, version);		
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}
		byte[] vBytes = version.toByteArray();
		
		ByteArrayOutputStream nBytes = new ByteArrayOutputStream();
		derCodec.getInteger(key, nBytes);
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}
		BigInteger n = new BigInteger(nBytes.toByteArray());

		if (vBytes[0] == TWO_PRIME_VERSION[0]) {
			throw new CodecException("Unable to extract a public key from this encoding");
		}
		else if (vBytes[0] == MULTIPRIME_VERSION[0]) {
			ByteArrayOutputStream eBytes = new ByteArrayOutputStream();
			derCodec.getInteger(key, eBytes);
			if (key.available() == 0) {
				throw new CodecException("Invalid private key encoding");
			}
			BigInteger e = new BigInteger(eBytes.toByteArray());
			return new RSAPublicKey(n, e);
		}
		else {
			throw new CodecException("Invalid private key encoding");
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException
	 */
	private RSAPublicKey getPublicKey(ByteArrayInputStream key) throws CodecException {

		ByteArrayOutputStream nBytes = new ByteArrayOutputStream();
		derCodec.getInteger(key, nBytes);
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}
		BigInteger n = new BigInteger(nBytes.toByteArray());

		ByteArrayOutputStream eBytes = new ByteArrayOutputStream();
		derCodec.getInteger(key, eBytes);
		if (key.available() != 0) {
			throw new CodecException("Invalid private key encoding");
		}
		BigInteger e = new BigInteger(eBytes.toByteArray());
		return new RSAPublicKey(n, e);

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException 
	 */
	private RSAPrivateKey parsePrivateKey(ByteArrayInputStream key) throws CodecException {

		ByteArrayOutputStream version = new ByteArrayOutputStream();
		derCodec.getInteger(key, version);		
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}

		// Nothing useful in this sequence. Parsing for errors only.
		derCodec.parseAlgorithm(key);
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayOutputStream octetString = new ByteArrayOutputStream();
		derCodec.getOctetString(key, octetString);
		if (key.available() != 0) {
			// Stuff after the end of the string. Suspicious!
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayOutputStream sequence = new ByteArrayOutputStream();
		ByteArrayInputStream octets = new ByteArrayInputStream(octetString.toByteArray());
		derCodec.getSequence(octets, sequence);
		if (key.available() != 0) {
			// Stuff after the end of the sequence. Suspicious!
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayInputStream keyStream = new ByteArrayInputStream(sequence.toByteArray());
		return getPrivateKey(keyStream);

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException 
	 */
	private RSAPublicKey parsePublicKey(ByteArrayInputStream key) throws CodecException {

		// Nothing useful in this sequence. Parsing for errors only.
		derCodec.parseAlgorithm(key);
		if (key.available() == 0) {
			throw new CodecException("Invalid public key encoding");
		}

		ByteArrayOutputStream bitString = new ByteArrayOutputStream();
		derCodec.getBitString(key, bitString);
		byte[] bitBytes = bitString.toByteArray();
		if (key.available() != 0 || bitBytes[0] != 0) {
			// The first byte in the bit string segment indicates an independent element.
			throw new CodecException("Invalid public key encoding");
		}

		ByteArrayOutputStream sequence = new ByteArrayOutputStream();
		ByteArrayInputStream bits =
				new ByteArrayInputStream(Arrays.copyOfRange(bitBytes, 1, bitBytes.length));
		derCodec.getSequence(bits, sequence);
		if (key.available() != 0) {
			// Stuff after the end of the sequence. Suspicious!
			throw new CodecException("Invalid public key encoding");
		}

		ByteArrayInputStream keyStream = new ByteArrayInputStream(sequence.toByteArray());
		return getPublicKey(keyStream);

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException
	 */
	private RSAPublicKey parsePublicFromPrivate(ByteArrayInputStream key) throws CodecException {

		ByteArrayOutputStream version = new ByteArrayOutputStream();
		derCodec.getInteger(key, version);		
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}

		// Nothing useful in this sequence. Parsing for errors only.
		derCodec.parseAlgorithm(key);
		if (key.available() == 0) {
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayOutputStream octetString = new ByteArrayOutputStream();
		derCodec.getOctetString(key, octetString);
		if (key.available() != 0) {
			// Stuff after the end of the string. Suspicious!
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayOutputStream sequence = new ByteArrayOutputStream();
		ByteArrayInputStream octets = new ByteArrayInputStream(octetString.toByteArray());
		derCodec.getSequence(octets, sequence);
		if (key.available() != 0) {
			// Stuff after the end of the sequence. Suspicious!
			throw new CodecException("Invalid private key encoding");
		}

		ByteArrayInputStream keyStream = new ByteArrayInputStream(sequence.toByteArray());
		return getPublicFromPrivate(keyStream);

	}

}
