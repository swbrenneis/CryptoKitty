package org.cryptokitty.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * Cipher feedback block cipher mode.
 * 
 * The shift register is set to the initialization vector and applied
 * to the block cipher. The MSB of the resulting block of ciphertext is
 * exclusive-or'd with the specified segment of plaintext to produce
 * a cipher segment. The cipher segment is then shifted into the shift
 * register from the left (MSB) side and the resulting block is applied
 * to the cipher. The operation is repeated until all segments of
 * plaintext have been processed. 
 * 
 */
public class CFB implements BlockMode {

	/*
	 * The block cipher.
	 */
	private BlockCipher cipher;

	/*
	 * The output cipher block.
	 */
	private byte[] cipherBlock;

	/*
	 * The initialization vector.
	 */
	private byte[] iv;

	/*
	 * Input segment size in bytes.
	 */
	private int segmentSize;

	/*
	 * Feedback shift register.
	 */
	private byte[] shiftRegister;

	/**
	 * 
	 * @param cipher
	 * @param segmentSize
	 * @param iv
	 */
	public CFB(BlockCipher cipher, int segmentSize, byte[] iv) {
		this.iv = iv;
		shiftRegister = Arrays.copyOf(iv, iv.length);
		this.segmentSize = segmentSize;
		cipherBlock = cipher.encrypt(shiftRegister);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#decrypt(byte[])
	 */
	@Override
	public byte[] decrypt(byte[] ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(byte[])
	 */
	@Override
	public byte[] encrypt(byte[] cleartext) {

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		for (int i = 0; i < cleartext.length; i += segmentSize) {
			byte[] cipherSeg = Arrays.copyOf(cipherBlock, segmentSize);
			byte[] clearSeg = Arrays.copyOf(cipherBlock, segmentSize);
			for (int n = 0; n < segmentSize; n++) {
				clearSeg[n] = (byte)(clearSeg[n] ^ cipherSeg[n]);
			}
			try {
				out.write(clearSeg);
			}
			catch (IOException e) {
				// Nope.
			}
			shiftIn(clearSeg);
			cipherBlock = cipher.encrypt(shiftRegister);
		}

		return out.toByteArray();

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#reset()
	 */
	@Override
	public void reset() {
		shiftRegister = Arrays.copyOf(iv, iv.length);
	}

	/*
	 * Shift a segment into the shift register.
	 */
	private void shiftIn(byte[] segment) {
		System.arraycopy(shiftRegister, 0, shiftRegister, segmentSize,
									shiftRegister.length - segmentSize);
		System.arraycopy(segment, 0, shiftRegister, 0, segmentSize);
	}

}
