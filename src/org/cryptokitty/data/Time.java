/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * Convenience class for representing and encoding timestamps.
 * See RFP 4880, section 3.5.
 * 
 */
public class Time {

	/*
	 * Time representation.
	 */
	private long time;

	/**
	 * Creates a time object representing the current time.
	 */
	public Time() {
		time = System.currentTimeMillis() / 1000;
	}

	/**
	 * Creates a time representation from an input stream.
	 */
	public Time(InputStream in)
		throws DataException {
		byte[] timeBytes = new byte[4];
		try {
			in.read(timeBytes);
		}
		catch (IOException e) {
			throw new DataException(e);
		}

		time = 0;
		for (byte b : timeBytes) {
			time = time << 8;
			time = time + (((int)b) & 0xff);
		}
	}

	/**
	 * Creates a time representation from an encoded octet array.
	 * The array must be 4 bytes and big endian.
	 */
	public Time(byte[] octets) throws DataException {
		if (octets.length != 4) {
			throw new DataException("Invalid time array");
		}

		time = 0;
		for (byte b : octets) {
			time = time << 8;
			time = time + (((int)b) & 0xff);
		}
	}

	/*
	 * Returns an encoded octet representation. 
	 */
	public byte[] getEncoded() {
		byte[] encoded = new byte[4];
		long encode = time;
		for (int i = 3; i >= 0; i--) {
			encoded[i] = (byte)(encode & 0xff);
			encode  = encode >> 8;
		}
		return encoded;
	}
}
