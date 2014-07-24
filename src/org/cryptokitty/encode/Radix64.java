/**
 * 
 */
package org.cryptokitty.encode;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Arrays;

/**
 * @author stevebrenneis
 *
 * Radix-64 encoding class. See RFC 4880, section 6.3.
 */
public class Radix64 {

	/*
	 * Radix-64 alphabet.
	 */
	private static final char[] ALPHABET = {
						'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
						'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
						'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
						'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
						'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
						'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
						'w', 'x', 'y', 'z', '0', '1', '2', '3',
						'4', '5', '6', '7', '8', '9', '+', '/',
											};

	/**
	 * 
	 */
	protected Radix64() {
		// Nothing to do here
	}

	/*
	 * Checks to see if the line length has reached 76 and inserts a
	 * newline character.
	 */
	private String checkLine(String line, BufferedWriter writer)
			throws IOException {
		if (line.length() == 76) {
			writer.write(line);
			writer.newLine();
			return "";
		}
		else {
			return line;
		}
	}

	/*
	 * Decode an incoming armored stream to an output stream. Looks
	 * for the CRC delimiter. Really ugly plumbing code, but it can't
	 * be helped.
	 */
	public void decode(InputStream in, OutputStream out)
			throws EncodingException {

		try {
			byte[] sextets = new byte[4];
			byte[] letters = new byte[4];
			boolean end = false;
			int length = in.read(letters);
			while (!end) {
				for (int i = 0; i < 4; ++i) {
					sextets[i] = (byte)findIndex((char)letters[i]);
				}
				byte octet = (byte)(((sextets[0] << 2) & 0xfc) | ((sextets[1] >> 4) & 0x03));
				out.write(octet);
				octet = (byte)((sextets[1] << 4) & 0xf0);
				if (sextets[2] >= 0) {
					octet |= (byte)((sextets[2] >> 2) & 0x0f);
					out.write(octet);
					octet = (byte)((sextets[2] << 6) & 0xc0);
					if (sextets[3] >= 0) {
						octet |= (byte)(sextets[3] & 0x3f);
						out.write(octet);
					}
					else {
						end = true;
					}
				}
				else {
					end = true;
				}
				length = in.read(letters);
				if (length < 4) {
					end = true;
				}
			}
		}
		catch (IOException e) {
			throw new EncodingException(e);
		}

	}

	/*
	 * Decode a CRC encoding. String must start with '=' and must be
	 * 5 characters long. Throws an exception if not.
	 */
	public long decodeCRC(String encoded)
			throws EncodingException {
		if (encoded.length() != 5 || encoded.charAt(0) != '=') {
			throw new EncodingException("Illegal CRC string");
		}

		byte[] letters = Arrays.copyOfRange(encoded.getBytes(), 1, 5);
		byte[] sextets = new byte[4];
		for (int i = 0; i < 4; ++i) {
			sextets[i] = (byte)findIndex((char)letters[i]);
		}
		byte octet = (byte)(((sextets[0] << 2) & 0xfc) | ((sextets[1] >> 4) & 0x03));
		long crcValue = (octet << 16) & 0xff0000;
		octet = (byte)(((sextets[1] << 4) & 0xf0) | (byte)((sextets[2] >> 2) & 0x0f));
		crcValue |= (octet << 8) & 0xff00;
		octet = (byte)(((sextets[2] << 6) & 0xc0) | (byte)(sextets[3] & 0x3f));
		crcValue |= octet & 0xff;

		return crcValue;
	}
	/*
	 * Encode an incoming stream of data to an output stream. More
	 * plumbing code.
	 */
	public void encode(InputStream in, OutputStream out)
			throws EncodingException {

		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
		byte[] triplet = new byte[3];
		String encoded = "";

		try {
			int length = in.read(triplet);
			while (length == 3) {
				// 6 MSB from first octet.
				int sextet1 = (triplet[0] >> 2) & 0x3f;
				encoded += ALPHABET[sextet1];
				encoded = checkLine(encoded, writer);
				// 2 LSB from first octet and 4 MSB from second octet.
				int sextet2 = ((triplet[0] << 4) & 0x30) | ((triplet[1] >> 4) & 0x0f);
				encoded += ALPHABET[sextet2];
				encoded = checkLine(encoded, writer);
				// 4 LSB from second octet and 2 MSB from third octet.
				int sextet3 = ((triplet[1] << 2) & 0x3C) | ((triplet[2] >> 6) & 0x03);
				encoded += ALPHABET[sextet3];
				encoded = checkLine(encoded, writer);
				// 6 LSB from third octet.
				int sextet4 = triplet[2] & 0x3f;
				encoded += ALPHABET[sextet4];
				encoded = checkLine(encoded, writer);
				length = in.read(triplet);
			}

			// Do padding.
			if (length == 2) {
				// 6 MSB from first octet.
				int sextet1 = (triplet[0] >> 2) & 0x3f;
				encoded += ALPHABET[sextet1];
				encoded = checkLine(encoded, writer);
				// 2 LSB from first octet and 4 MSB from second octet.
				int sextet2 = ((triplet[0] << 4) & 0x30) | ((triplet[1] >> 4) & 0x0f);
				encoded += ALPHABET[sextet2];
				encoded = checkLine(encoded, writer);
				// 4 LSB from second octet and zero padding.
				int sextet3 = (triplet[1] << 2) & 0x3C;
				encoded += ALPHABET[sextet3];
				encoded = checkLine(encoded, writer);
				// Pad character
				encoded += "=";
				encoded = checkLine(encoded, writer);
			}
			else if (length == 1) {
				// 6 MSB from first octet.
				int sextet1 = (triplet[0] >> 2) & 0x3f;
				encoded += ALPHABET[sextet1];
				encoded = checkLine(encoded, writer);
				// 2 LSB from first octet and zero padding.
				int sextet2 = (triplet[0] << 4) & 0x30;
				encoded += ALPHABET[sextet2];
				encoded = checkLine(encoded, writer);
				encoded += "=";
				encoded = checkLine(encoded, writer);
				encoded += "=";
				encoded = checkLine(encoded, writer);
			}

			if (encoded.length() > 0) {
				writer.write(encoded);
				writer.newLine();
			}
			writer.flush();

		}
		catch (IOException e) {
			throw new EncodingException(e);
		}
	}

	/*
	 * Encode CRC value.
	 */
	public String encodeCRC(long crcValue) {
		byte[] triplet = new byte[3];
		triplet[0] = (byte)((crcValue >> 16) & 0xff);
		triplet[1] = (byte)((crcValue >> 8) & 0xff);
		triplet[2] = (byte)(crcValue & 0xff);

		String encoded = "=";
		// 6 MSB from first octet.
		int sextet1 = (triplet[0] >> 2) & 0x3f;
		encoded += ALPHABET[sextet1];
		// 2 LSB from first octet and 4 MSB from second octet.
		int sextet2 = ((triplet[0] << 4) & 0x30) | ((triplet[1] >> 4) & 0x0f);
		encoded += ALPHABET[sextet2];
		// 4 LSB from second octet and 2 MSB from third octet.
		int sextet3 = ((triplet[1] << 2) & 0x3C) | ((triplet[2] >> 6) & 0x03);
		encoded += ALPHABET[sextet3];
		// 6 LSB from third octet.
		int sextet4 = triplet[2] & 0x3f;
		encoded += ALPHABET[sextet4];
		return encoded;
	}

	/*
	 * Find the index of the radix-64 character. Returns -1 on the special
	 * case of '=' (end of stream delimiter. Throws an encoding exception
	 * if the index isn't found.
	 */
	private int findIndex(char letter)
			throws EncodingException {

		if (letter == '=') {
			return -1;
		}

		int index = 0;
		while (index < ALPHABET.length) {
			if (ALPHABET[index] == letter) {
				return index;
			}
			index++;
		}
		throw new EncodingException("Armored character out of range");
	}

}
