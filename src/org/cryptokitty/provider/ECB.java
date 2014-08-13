package org.cryptokitty.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.IllegalBlockSizeException;

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

	/**
	 * 
	 */
	public ECB() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#decrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws IOException, IllegalBlockSizeException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void encrypt(InputStream plaintext, OutputStream ciphertext)
			throws IOException, IllegalBlockSizeException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#reset()
	 */
	@Override
	public void reset() {
		// TODO Auto-generated method stub

	}

}
