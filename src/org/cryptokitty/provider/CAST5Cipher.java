/**
 * 
 */
package org.cryptokitty.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author Steve Brenneis
 *
 */
public class CAST5Cipher extends CipherSpi {

	/*
	 * Mode constants.
	 */
	private static final int BLOCK = 0;
	private static final int CFB8 = 1;
	private static final int PGPCFB = 2;

	/*
	 * The cipher implementation.
	 */
	private CAST5 cast5;

	/*
	 * The block mode handler.
	 */
	private BlockMode blockMode;

	/*
	 * Block mode output stream.
	 */
	private ByteArrayOutputStream blockOut;
	
	/*
	 * Initialization vector parameter.
	 */
	private IvParameterSpec iv;

	/*
	 * Cipher mode.
	 */
	private int mode;

	/*
	 * Cipher operation mode. Will be one of Cipher.ENCRYPT_MODE,
	 * Cipher.DECRYPT_MODE, Cipher.WRAP_KEY, or Cipher.UNWRAP_KEY
	 */
	private int opmode;

	/*
	 * Algorithm parameters.
	 */
	private AlgorithmParameters params;

	/**
	 * 
	 * Creates an empty an uninitialized cipher.
	 */
	public CAST5Cipher() {
		opmode = 0; // Undefined.
		params = null;
		iv = null;
		cast5 = null;
		mode = BLOCK;
		blockOut = new ByteArrayOutputStream();
	}

	/*
	 * Do CFB8 encryption/decryption.
	 */
	private byte[] doCFB8(byte[] inBytes)
			throws IllegalBlockSizeException {

		ByteArrayInputStream bytesIn =
				new ByteArrayInputStream(inBytes);

		switch (opmode) {
		case Cipher.DECRYPT_MODE:
			try {
				blockMode.decrypt(bytesIn, blockOut);
				return blockOut.toByteArray();
			}
			catch (IOException e) {
				// TODO This won't happen.
				e.printStackTrace();
				return null;
			}
		case Cipher.ENCRYPT_MODE:
			try {
				blockMode.encrypt(bytesIn, blockOut);
				return blockOut.toByteArray();
			}
			catch (IOException e) {
				// TODO This won't happen.
				e.printStackTrace();
				return null;
			}
		case Cipher.UNWRAP_MODE:
		case Cipher.WRAP_MODE:
		default:
			return null;
		}

	}

	/*
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLength)
			throws IllegalBlockSizeException, BadPaddingException {

		byte[] text = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLength);

		switch (mode) {
		case BLOCK:
			if (text.length != 8) {
				throw new IllegalBlockSizeException("CAST5 block size must be 8");
			}
			else {
				switch (opmode) {
				case Cipher.DECRYPT_MODE:
					return cast5.decrypt(text);
				case Cipher.ENCRYPT_MODE:
					return cast5.encrypt(text);
				case Cipher.UNWRAP_MODE:	// Not supported yet.
				case Cipher.WRAP_MODE:
				default:
					return null;
				}
			}
		case CFB8:
		{
			byte[] o = doCFB8(text);
			byte[] finalOut = Arrays.copyOf(o, o.length);
			blockMode.reset();
			blockOut.reset();
			return finalOut;
		}
		default:
			// Invalid cipher mode. Shouldn't ever happen.
			return null;
		}

	}

	/*
	 * One step encyption/decryption. Block size must be 8.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLength, byte[] output,
			int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {

		byte[] text = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLength);

		switch (mode) {
		case BLOCK:
			if (text.length != 8) {
				throw new IllegalBlockSizeException("CAST5 block size must be 8");
			}
			else if (output.length - outputOffset < 8) {
				throw new ShortBufferException("CAST5 block size must be 8");
			}
			else {
				byte[] o;
				switch (opmode) {
				case Cipher.DECRYPT_MODE:
					o = cast5.decrypt(text);
					System.arraycopy(o, 0, output, outputOffset, 8);
					return 8;
				case Cipher.ENCRYPT_MODE:
					o = cast5.encrypt(text);
					System.arraycopy(o, 0, output, outputOffset, 8);
					return 8;
				case Cipher.UNWRAP_MODE:	// Not supported yet.
				case Cipher.WRAP_MODE:
				default:
					return 0;
				}
			}
		case CFB8:
		{
			byte[] out = doCFB8(text);
			if (output.length - outputOffset < out.length) {
				throw new ShortBufferException("Output buffer too small");
			}
			System.arraycopy(out, 0, output, outputOffset, out.length);
			blockMode.reset();
			blockOut.reset();
		}
		default:
			// Invalid cipher mode. Shouldn't ever happen.
			return 0;
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {
		return 8;
	}

	/*
	 * No IV is used in the simple block cipher.
	 */
	@Override
	protected byte[] engineGetIV() {
		return iv.getIV();
	}

	/*
	 * Inputs and outputs are always 8 for the simple block cipher.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLength) {

		switch (mode) {
		case BLOCK:
			return 8;
		case CFB8:
			return blockOut.size() + inputLength;
		default:
			return 0;
		}

	}

	/*
	 * No algorithm parameters are stored in the simple cipher.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {
		return params;
	}

	/*
	 * Initializes the cipher using the specified key. The secure random
	 * is used to generate the initialization vector.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		byte[] ivBytes = new byte[8];
		random.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);
		if (mode == CFB8) {
			// Create the CFB8 mode with a default segment size.
			try {
				blockMode = new CFB8(cast5, 1, ivBytes);
			}
			catch (IllegalBlockSizeException e) {
				// Won't happen.
				e.printStackTrace();
			}
		}

	}

	/*
	 * Initializes the cipher using the specified key and IV parameter. Throws an
	 * exception if the IV parameter is missing. The secure random is ignored.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		if (params != null && params instanceof IvParameterSpec) {
			iv = (IvParameterSpec)params;
			if (mode == CFB8) {
				// Create the CFB8 mode with a default segment size.
				try {
					blockMode = new CFB8(cast5, 1, iv.getIV());
				}
				catch (IllegalBlockSizeException e) {
					// Won't happen.
					e.printStackTrace();
				}
			}
		}
		else {
			throw new InvalidAlgorithmParameterException("Expecting initialization vector");
		}

	}

	/*
	 * Initializes the cipher using the specified key and parameters. The
	 * secure random is used to generate the initialization vector.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		this.params = params;
		byte[] ivBytes = new byte[8];
		random.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);
		if (mode == CFB8) {
			// Create the CFB8 mode with a default segment size.
			try {
				blockMode = new CFB8(cast5, 1, ivBytes);
			}
			catch (IllegalBlockSizeException e) {
				// Won't happen.
				e.printStackTrace();
			}
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
	 */
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

		switch (mode) {
		case "CFB8":
			this.mode = CFB8;
			break;
		case "PGPCFB":
			this.mode = PGPCFB;
			break;
		default:
			throw new NoSuchAlgorithmException("CAST5 " + mode + " mode not supported");
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
	 */
	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {

		if (padding.compareToIgnoreCase("NOPADDING") != 0) {
			throw new NoSuchPaddingException("CAST5 padding not supported");
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLength) {

		byte[] text = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLength);

		switch (mode) {
		case BLOCK:
			if (text.length != 8) {
				return null;
			}
			else {
				switch (opmode) {
				case Cipher.DECRYPT_MODE:
					return cast5.decrypt(text);
				case Cipher.ENCRYPT_MODE:
					return cast5.encrypt(text);
				case Cipher.UNWRAP_MODE:	// Not supported yet.
				case Cipher.WRAP_MODE:
				default:
					return null;
				}
			}
		case CFB8:
		{
			try {
				byte[] soFar = doCFB8(text);
				return Arrays.copyOf(soFar, soFar.length);
			}
			catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			}
		}
		default:
			// Invalid cipher mode. Shouldn't ever happen.
			return null;
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLength, byte[] output,
			int outputOffset) throws ShortBufferException {

		byte[] text = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLength);

		switch (mode) {
		case BLOCK:
			if (text.length != 8) {
				return 0;
			}
			else if (output.length - outputOffset < 8) {
				throw new ShortBufferException("CAST5 block size must be 8");
			}
			else {
				byte[] o;
				switch (opmode) {
				case Cipher.DECRYPT_MODE:
					o = cast5.decrypt(text);
					System.arraycopy(o, 0, output, outputOffset, 8);
					return 8;
				case Cipher.ENCRYPT_MODE:
					o = cast5.encrypt(text);
					System.arraycopy(o, 0, output, outputOffset, 8);
					return 8;
				case Cipher.UNWRAP_MODE:	// Not supported yet.
				case Cipher.WRAP_MODE:
				default:
					return 0;
				}
			}
		case CFB8:
		{
			try {
				byte[] out = doCFB8(text);
				if (output.length - outputOffset < out.length) {
					throw new ShortBufferException("Output buffer too small");
				}
				System.arraycopy(out, 0, output, outputOffset, out.length);
				return out.length;
			}
			catch (IllegalBlockSizeException e) {
				e.printStackTrace();
				return 0;
			}
		}
		default:
			// Invalid cipher mode. Shouldn't ever happen.
			return 0;
		}

	}

}
