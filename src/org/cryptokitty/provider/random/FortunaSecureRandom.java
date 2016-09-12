/**
 * 
 */
package org.cryptokitty.provider.random;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import org.cryptokitty.provider.SecureRandomException;

/**
 * @author stevebrenneis
 *
 */
public class FortunaSecureRandom extends SecureRandom {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1502563938023171603L;

	/**
	 * Fortuna RNG device
	 */
	private static final String FORTUNAPATH = "/dev/fortuna";

	/**
	 * 
	 */
	public FortunaSecureRandom() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * 
	 * @param bytes
	 */
	public void nextBytes(byte[] bytes) {

		int length = bytes.length;
		int offset = 0;
		try {
			while (length > 0) {
				byte[] rbytes = readBytes(length);
				if (rbytes.length != 0) {
					System.arraycopy(rbytes, 0, bytes, offset, rbytes.length);
					length -= rbytes.length;
					offset += rbytes.length;
				}
			}
		}
		catch (SecureRandomException e) {
			// No clue what to do with this.
			System.err.println(e.getMessage());
		}

	}

	/**
	 * 
	 * @return
	 */
	public int nextInt() {

		byte[] bytes = new byte[4];
		nextBytes(bytes);
		ByteBuffer buf = ByteBuffer.wrap(bytes);
		return buf.getInt();

	}

	/**
	 * 
	 * @return
	 */
	public long nextLong() {

		byte[] bytes = new byte[8];
		nextBytes(bytes);
		ByteBuffer buf = ByteBuffer.wrap(bytes);
		return buf.getLong();

	}

	private byte[] readBytes(int count) throws SecureRandomException {
		
		try {
			File file = new File(FORTUNAPATH);
			file.setReadOnly();
			InputStream in = new FileInputStream(file);
			byte[] bytes = new byte[count];
			in.read(bytes);
			in.close();
			return bytes;
		}
		catch (FileNotFoundException e) {
			throw new SecureRandomException("Fortuna device not available");
		}
		catch (IOException e) {
			throw new SecureRandomException("Fortuna read error: " + e.getMessage());
		}

	}

}
