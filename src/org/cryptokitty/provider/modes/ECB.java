package org.cryptokitty.provider.modes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.provider.cipher.BlockCipher;

/**
 * 
 */

/**
 * @author Steve Brenneis
 *
 * This implements the Electronic Code Book block encryption mode.
 * This mode is cryptographically weak. It is implemented to comply
 * with the JCA. It is NOT recommended for use.
 */
public class ECB implements BlockMode {

	/*
	 * The BlockCipher object.
	 */
	private BlockCipher cipher;

	/**
	 * 
	 */
	public ECB() {
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#decrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void encrypt(InputStream plaintext, OutputStream ciphertext)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#reset()
	 */
	@Override
	public void reset() {
		// TODO Auto-generated method stub

	}

	@Override
	public int getBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#getIV()
	 */
	@Override
	public byte[] getIV() {
		
		return null;

	}

	@Override
	public void setBlockCipher(BlockCipher cipher) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setIV(byte[] iv) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setKey(byte[] key) throws InvalidKeyException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		
	}

}
