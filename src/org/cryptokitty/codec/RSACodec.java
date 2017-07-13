/**
 * 
 */
package org.cryptokitty.codec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.cryptokitty.cipher.OAEPrsaes;
import org.cryptokitty.cipher.RSACipher;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidPaddingException;
import org.cryptokitty.exceptions.SignatureException;
import org.cryptokitty.exceptions.CodecException;
import org.cryptokitty.keys.RSAPrivateKey;
import org.cryptokitty.keys.RSAPublicKey;
import org.cryptokitty.signature.PKCS1rsassa;
import org.cryptokitty.signature.RSASignature;

/**
 * @author stevebrenneis
 *
 * Provides RSA encryption and signing for a byte stream.
 * 
 * For reading the stream:
 * 1. Invoke the byte[] constructor with the encrypted block.
 * 2. Invoke decrypt with the private key.
 * 3. Invoke the various byte stream get methods.
 * 
 * For writing the stream:
 * 1. Invoke the default constructor.
 * 2. Invoke the various byte stream put methods.
 * 3. Invoke the encrypt method with the public key.
 * 
 * To sign the stream:
 * 1. Invoke the default constructor.
 * 2. Invoke the various byte stream put methods.
 * 3. Invoke the sign method with the private key.
 * 
 * To verify the stream:
 * 1. Invoke the byte[] constructor with the byte block.
 * 2. Invoke verify with the public key and the signature.
 * 3. Invoke the various byte stream get methods.
 * 
 */
public class RSACodec extends ByteStreamCodec {

	/**
	 * Encrypted block or block to be verified.
	 */
	private byte[] text;

	/**
	 * 
	 */
	public RSACodec() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param bytes
	 */
	public RSACodec(byte[] text) {

		this.text = text;
		// Release the stream created in the default constructor
		out = null;

	}

	/**
	 * 
	 * @param key
	 * @throws CodecException
	 */
	public void decrypt(RSAPrivateKey key) throws CodecException {

		try {
			OAEPrsaes cipher = new OAEPrsaes(RSACipher.DigestTypes.SHA256);
			byte[] plaintext = cipher.decrypt(key, text);
			if (plaintext == null) {
				throw new CodecException("Decryption failed");
			}
			in = new ByteArrayInputStream(plaintext);
		}
		catch (IllegalBlockSizeException e) {
			throw new CodecException("Invalid ciphertext");
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException
	 */
	public byte[] encrypt(RSAPublicKey key) throws CodecException {

		try {
			OAEPrsaes cipher = new OAEPrsaes(RSACipher.DigestTypes.SHA256);
			return cipher.encrypt(key, out.toByteArray());
		}
		catch (IllegalBlockSizeException e) {
			throw new CodecException("Invalid plaintext");
		}
		catch (BadParameterException | InvalidPaddingException e) {
			throw new CodecException("Encryption error: " + e.getLocalizedMessage());
		}

	}

	/**
	 * Encrypt and sign convenience method.
	 * 
	 * @param publicKey
	 * @param privateKey
	 * @return
	 * @throws CodecException
	 */
	public byte[] encryptAndSign(RSAPublicKey publicKey, RSAPrivateKey privateKey)
															throws CodecException {

		try {
			byte[] ciphertext = encrypt(publicKey);
			out = new ByteArrayOutputStream();
			out.write(ciphertext);
			return sign(privateKey);
		}
		catch (IOException e) {
			// Not likely.
			throw new CodecException(e);
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException
	 */
	public byte[] sign(RSAPrivateKey key) throws CodecException {

		try {
			PKCS1rsassa sig = new PKCS1rsassa(RSASignature.DigestTypes.SHA256);
			return sig.sign(key, out.toByteArray());
		}
		catch (SignatureException e) {
			throw new CodecException("Signing error: " + e.getLocalizedMessage());
		}

	}

	/**
	 * 
	 * @param key
	 * @return
	 * @throws CodecException 
	 */
	public boolean verify(RSAPublicKey key, byte[] signature) throws CodecException {

		try {
			PKCS1rsassa sig = new PKCS1rsassa(RSASignature.DigestTypes.SHA256);
			return sig.verify(key, text, signature);
		}
		catch (SignatureException e) {
			throw new CodecException("Signing error: " + e.getLocalizedMessage());
		}

	}

	/**
	 * Verify signature and decrypt convenience method.
	 * 
	 * @param publicKey
	 * @param privateKey
	 * @param signature
	 * @return
	 * @throws CodecException
	 */
	public boolean verifyAndDecrypt(RSAPublicKey publicKey, RSAPrivateKey privateKey,
											byte[] signature) throws CodecException {

		if (verify(publicKey, signature)) {
			decrypt(privateKey);
			return true;
		}
		else {
			return false;
		}

	}

}
