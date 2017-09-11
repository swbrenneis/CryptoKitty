/**
 * 
 * Provides GCM encryption for a byte stream.
 * 
 * For reading the stream:
 * 1. Invoke the byte[] constructor with the encrypted block.
 * 2. Invoke decrypt with the key and the AEAD.
 * 3. Invoke the various byte stream get methods.
 * 
 * For writing the stream:
 * 1. Invoke the default constructor.
 * 2. Invoke the various byte stream put methods.
 * 3. Invoke the encrypt method with the key and the AEAD.
 * 
 */
package org.cryptokitty.codec;

import java.io.ByteArrayInputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import org.cryptokitty.cipher.AES;
import org.cryptokitty.exceptions.AuthenticationException;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.CodecException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidKeyException;
import org.cryptokitty.modes.GCM;
import org.cryptokitty.random.FortunaSecureRandom;

/**
 * @author stevebrenneis
 *
 */
public class GCMCodec extends ByteStreamCodec {

	/**
	 * Encrypted block.
	 */
	private byte[] ciphertext;

	/**
	 * Initial value.
	 */
	private byte[] iv;

	/**
	 * 
	 */
	public GCMCodec() {

		this.iv = null;

	}

	/**
	 * 
	 * @param encoded
	 */
	public GCMCodec(byte[] ciphertext) {

		this.ciphertext = ciphertext;
		this.iv = null;
		// Release the stream created in the default constructor
		out = null;

	}

	/**
	 * 
	 * @param key
	 * @param aead
	 */
	public void decrypt(byte[] key, byte[] aead) throws CodecException {

		try {
			if (iv == null) {
				ByteBuffer buf = ByteBuffer.wrap(ciphertext);
				ciphertext = new byte[ciphertext.length - 12];
				buf.get(ciphertext);
				iv = new byte[12];
				buf.get(iv);
			}
			GCM cipher = new GCM(new AES(key.length), true);
			cipher.setIV(iv);
			cipher.setAuthenticationData(aead);
			byte[] plaintext = cipher.decrypt(ciphertext, key);
			in = new ByteArrayInputStream(plaintext);
		}
		catch (BufferUnderflowException e) {
			throw new CodecException("Invalid ciphertext");
		}
		catch (IllegalStateException e) {
			throw new CodecException("Illegal cipher state");
		}
		catch (BadParameterException | IllegalBlockSizeException e) {
			throw new CodecException("Invalid parameter");
		}
		catch (InvalidKeyException e) {
			throw new CodecException("Invalid key");
		}
		catch (AuthenticationException e) {
			throw new CodecException("AEAD authentication failed");
		}

	}

	/**
	 * 
	 * @param key
	 * @param aead
	 * @return
	 */
	public byte[] encrypt(byte[] key, byte[] aead) throws CodecException {

		try {
			byte[] plaintext = out.toByteArray();
			GCM cipher = new GCM(new AES(key.length), true);
			boolean appendIv = false;
			if (iv == null) {
				appendIv = true;
				FortunaSecureRandom rnd = new FortunaSecureRandom();
				iv = new byte[12];
				rnd.nextBytes(iv);
			}
			cipher.setIV(iv);
			cipher.setAuthenticationData(aead);
			byte[] ciphertext = cipher.encrypt(plaintext, key);
			if (appendIv) {
				ByteBuffer buf = ByteBuffer.allocate(ciphertext.length + 12);
				buf.put(ciphertext);
				buf.put(iv);
				return buf.array();
			}
			else {
				return ciphertext;
			}
		}
		catch (IllegalStateException e) {
			throw new CodecException("Illegal cipher state");
		}
		catch (BadParameterException | IllegalBlockSizeException e) {
			throw new CodecException("Invalid parameter");
		}
		catch (InvalidKeyException e) {
			throw new CodecException("Invalid key");
		}

	}

	/**
	 * Sets the initial value.
	 * 
	 * @param iv
	 */
	public void setIV(byte[] iv) {
		this.iv = iv;
	}

}
