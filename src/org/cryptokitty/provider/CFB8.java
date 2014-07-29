package org.cryptokitty.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * @author Steve Brenneis
 *
 * Cipher feedback block cipher mode.
 * 
 * Encryption:
 * 
 * The shift register is set to the initialization vector and applied to the block
 * cipher. The MSB of the resulting block of ciphertext is exclusive-or'd with the
 * specified segment of plaintext to produce a cipher segment. The cipher segment
 * is then shifted into the shift register from the left (MSB) side and the
 * resulting block is applied to the cipher. The operation is repeated until all
 * segments of plaintext have been processed. This is the self-synchronizing stream
 * version of classic CFB.
 * 
 */
public class CFB8 implements BlockMode {

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
	 * @param cipher - The block cipher.
	 * @param segmentSize - Segment size in bytes.
	 * @param iv - Initialization vector.
	 */
	public CFB8(BlockCipher cipher, int segmentSize, byte[] iv)
			throws IllegalBlockSizeException {
		this.cipher = cipher;
		this.iv = iv;
		shiftRegister = Arrays.copyOf(iv, iv.length);
		this.segmentSize = segmentSize;
		int blockSize = cipher.getBlockSize();
		if (segmentSize > blockSize || blockSize % segmentSize != 0) {
			throw new IllegalBlockSizeException("Illegal segment or block size");
		}
		cipherBlock = cipher.encrypt(shiftRegister);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#decrypt(byte[])
	 */
	@Override
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws IOException, IllegalBlockSizeException {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.BlockMode#encrypt(byte[])
	 */
	@Override
	public void encrypt(InputStream cleartext, OutputStream ciphertext)
			throws IOException, IllegalBlockSizeException {

		byte[] cipherSeg = new byte[segmentSize];
		byte[] clearSeg = new byte[segmentSize];
		int read = cleartext.read(clearSeg);
		while (read == segmentSize) {
			for (int n = 0; n < segmentSize; n++) {
				cipherSeg[n] = (byte)(clearSeg[n] ^ cipherBlock[n]);
			}
			ciphertext.write(cipherSeg);
			shiftIn(cipherSeg);
			cipherBlock = cipher.encrypt(shiftRegister);
			read = cleartext.read(cipherSeg);
		}
		if (read > 0) {
			throw new IllegalBlockSizeException("Illegal segment");
		}

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
