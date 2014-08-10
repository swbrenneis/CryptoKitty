/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * Compressed data packet. See RFC 4880, section 5.6.
 */
public class CompressedDataPacket {

	/*
	 * Compression algorithm constants.
	 */
	public static final int UNCOMPRESSED = 0;
	public static final int ZIP = 1;
	public static final int ZLIB = 2;
	public static final int BZIP2 = 3;

	/*
	 * Compression algorithm.
	 */
	private int algorithm;

	/*
	 * Compressed data.
	 */
	private byte[] compressed;

	/**
	 * 
	 */
	public CompressedDataPacket(InputStream in) throws InvalidPacketException {

		try {
			algorithm = in.read();
			compressed = new byte[in.available()];
			in.read(compressed);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

}
