/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;

//import org.cryptokitty.data.DataException;
//import org.cryptokitty.data.Time;

/**
 * @author Steve Brenneis
 *
 * Literal data packet. Contains data to be encrypted along
 * with format identifiers. See RFC 4880, section 5.9.
 */
public class LiteralDataPacket {

	/*
	 * The RFC says this is a date associated with the literal
	 * data but makes no reference to the format. We'll assume
	 * it is a Time object until we know otherwise.
	 */
//	private Time date;

	/*
	 * File name.
	 */
	@SuppressWarnings("unused")
	private String fileName;

	/*
	 * Format identifier.
	 */
	@SuppressWarnings("unused")
	private char format;

	/*
	 * Literal data.
	 */
	private byte[] data;

	/**
	 * 
	 */
	public LiteralDataPacket(InputStream in)
			throws InvalidPacketException {

		try {
			int f = in.read();
			switch (f) {
			case 'b':
			case 't':
			case 'u':
				format = (char)f;
				break;
			default:
				throw new InvalidPacketException("Illegal format field");
			}

			int length = in.read();
			byte[] string = new byte[length];
			fileName = new String(string);

//			try {
//				date = new Time(in);
//			}
//			catch (DataException e) {
//				throw new InvalidPacketException(e);
//			}

			data = new byte[in.available()];
			in.read(data);

		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
	}

}
