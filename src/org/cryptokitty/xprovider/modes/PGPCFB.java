/**
 * 
 */
package org.cryptokitty.xprovider.modes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.xprovider.cipher.BlockCipher;

/**
 * @author Steve Brenneis
 *
 * This provides the OpenPGP variant on CFB mode. In this mode, the
 * initialization vector is set to all zeros and encrypted. The resulting
 * cipher block is xor'd with a random block of data and that is placed
 * in the feedback register. The feedback register is encrypted and the
 * "leftmost" (LSB) octets are xor'd with the result.
 */
public class PGPCFB implements BlockMode {

	/**
	 * 
	 */
	public PGPCFB() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#decrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void encrypt(InputStream cleartext, OutputStream ciphertext)
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
