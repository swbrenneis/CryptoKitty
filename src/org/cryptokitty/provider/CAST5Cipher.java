/**
 * 
 */
package org.cryptokitty.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
	private static final int CFB = 2;
	private static final int CFB8 = 3;
	private static final int PGPCFB = 4;

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
	private byte[] doMode(byte[] inBytes)
			throws ProviderException {

		ByteArrayInputStream bytesIn =
				new ByteArrayInputStream(inBytes);

		switch (opmode) {
		case Cipher.DECRYPT_MODE:
			blockMode.decrypt(bytesIn, blockOut);
			return blockOut.toByteArray();
		case Cipher.ENCRYPT_MODE:
			blockMode.encrypt(bytesIn, blockOut);
			return blockOut.toByteArray();
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
		case CFB:
		case CFB8:
		{
			try {
				byte[] o = doMode(text);
				byte[] finalOut = Arrays.copyOf(o, o.length);
				blockMode.reset();
				blockOut.reset();
				return finalOut;
			}
			catch (ProviderException e) {
				// The only time this will happen is on a decryption error in the block mode.
				// The CAST5 cipher doesn't throw exceptions.
				return null;
			}
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
		case CFB:
		case CFB8:
		{
			try {
				byte[] out = doMode(text);
				if (output.length - outputOffset < out.length) {
					throw new ShortBufferException("Output buffer too small");
				}
				System.arraycopy(out, 0, output, outputOffset, out.length);
				blockMode.reset();
				blockOut.reset();
				return out.length;
			}
			catch (ProviderException e) {
				// The only time this will happen is on a decryption error in the block mode.
				// The CAST5 cipher doesn't throw exceptions.
				return 0;
			}
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
			return inputLength == 8 ? 8 : 0;
		case CFB:
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
	 * Initializes the cipher using the specified key. The provided secure random
	 * is not used to generate the initialization vector. This is a security issue.
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
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);
		switch (mode) {
		case CFB:
			// Create the CFB mode.
			try {
				blockMode = new CFB(cast5, iv.getIV());
			}
			catch (ProviderException e) {
				// Shouldn't happen
				throw new IllegalStateException("Cipher unknown state");
			}
			break;
		case CFB8:
			// Create the CFB8 mode with a default segment size.
			try {
				blockMode = new CFB8(cast5, 1, ivBytes);
			}
			catch (IllegalBlockSizeException e) {
				// TODO Figure out what to do with these.
			}
			catch (Exception e) {
				// Java and/or Eclipse are being stupid about this.
				// The CFB8 constructor throws a ProviderException. However
				// Eclipse won't let you put it in the catch block because
				// it claims it is unreachable code. If you don't add it to the
				// catch block, Java claims it is an uncaught exception.
				// TODO Figure out what to do with these.
			}
			break;
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
			switch (mode) {
			case CFB:
				// Create the CFB mode.
				try {
					blockMode = new CFB(cast5, iv.getIV());
				}
				catch (ProviderException e1) {
					// CAST5 get block size always returns 8.
					// No need to handle this.
					e1.printStackTrace();
				}
				break;
			case CFB8:
				// Create the CFB8 mode with a default segment size.
				try {
					blockMode = new CFB8(cast5, 1, iv.getIV());
				}
				catch (IllegalBlockSizeException e) {
					// TODO Figure out what to do with these.
				}
				catch (Exception e) {
					// Java and/or Eclipse are being stupid about this.
					// The CFB8 constructor throws a ProviderException. However
					// Eclipse won't let you put it in the catch block because
					// it claims it is unreachable code. If you don't add it to the
					// catch block, Java claims it is an uncaught exception.
					// TODO Figure out what to do with these.
				}
				break;
			}
		}
		else {
			throw new InvalidAlgorithmParameterException("Expecting initialization vector");
		}

	}

	/*
	 * Initializes the cipher using the specified key and parameters. The
	 * secure random is not used to generate the initialization vector. This
	 * is a security issue.
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
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);
		switch (mode) {
		case CFB:
			// Create the CFB mode.
			try {
				blockMode = new CFB(cast5, iv.getIV());
			}
			catch (ProviderException e1) {
				// CAST5 get block size always returns 8.
				// No need to handle this.
				e1.printStackTrace();
			}
			break;
		case CFB8:
			// Create the CFB8 mode with a default segment size.
			try {
				blockMode = new CFB8(cast5, 1, iv.getIV());
			}
			catch (IllegalBlockSizeException e) {
				// TODO Figure out what to do with these.
			}
			catch (Exception e) {
				// Java and/or Eclipse are being stupid about this.
				// The CFB8 constructor throws a ProviderException. However
				// Eclipse won't let you put it in the catch block because
				// it claims it is unreachable code. If you don't add it to the
				// catch block, Java claims it is an uncaught exception.
				// TODO Figure out what to do with these.
			}
			break;
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
	 */
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

		switch (mode) {
		case "CFB":
			this.mode = CFB;
			break;
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
		case CFB:
		case CFB8:
		{
			try {
				byte[] soFar = doMode(text);
				return Arrays.copyOf(soFar, soFar.length);
			}
			catch (ProviderException e) {
				// This will only happen on a block mode decrypt.
				// CAST5 cipher doesn't throw exceptions.
				return null;
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
		case CFB:
		case CFB8:
		{
			try {
				byte[] out = doMode(text);
				if (output.length - outputOffset < out.length) {
					throw new ShortBufferException("Output buffer too small");
				}
				System.arraycopy(out, 0, output, outputOffset, out.length);
				return out.length;
			}
			catch (ProviderException e) {
				// This will only happen on a block mode decrypt.
				// CAST5 cipher doesn't throw exceptions.
				return 0;
			}
		}
		default:
			// Invalid cipher mode. Shouldn't ever happen.
			return 0;
		}

	}

}
