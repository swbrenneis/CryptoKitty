/**
 * 
 */
package org.cryptokitty.provider;

import java.io.InputStream;
import java.io.OutputStream;

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
			throws DecryptionException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void encrypt(InputStream cleartext, OutputStream ciphertext)
			throws ProviderException {
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
