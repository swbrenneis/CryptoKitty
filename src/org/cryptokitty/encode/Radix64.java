/**
 * 
 */
package org.cryptokitty.encode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
	 * Decode an incoming armored stream to an output stream. Really
	 * ugly plumbing code, but it can't be helped.
	 */
	public void decode(InputStream in, OutputStream out)
			throws EncodingException {

		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		boolean end = false;

		try {
			String line = reader.readLine();
			while (!end) {
				byte[] sextets = line.getBytes();
				for (int i = 0; i < sextets.length; ++i) {
					byte[] quad = Arrays.copyOfRange(sextets, i, i+3);
					byte octet = (byte)(((quad[0] << 2) & 0xfc) & ((quad[1] >> 6) & 0x03));
					out.write(findIndex((char)octet));
					octet = (byte)((quad[1] << 4) & 0xf0);
					if (quad[2] != '=') {
						octet |= (byte)((quad[2] >> 2) & 0x03);
						out.write(findIndex((char)octet));
						octet = (byte)((quad[2] << 6) & 0xfc);
						if (quad[3] != '=') {
							octet |= (byte)(quad[3] & 0x3f);
						}
						out.write(findIndex((char)octet));
					}
					else {
						out.write(findIndex((char)octet));
						end = true;
					}
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

		byte[] quad = Arrays.copyOfRange(encoded.getBytes(), 1, 4);
		byte octet = (byte)(((quad[0] << 2) & 0xfc) & ((quad[1] >> 6) & 0x03));
		long crcValue = (octet << 16) & 0xff0000;
		octet = (byte)(((quad[1] << 4) & 0xf0) | (byte)((quad[2] >> 2) & 0x03));
		crcValue |= (octet << 8) & 0xff00;
		octet = (byte)(((quad[2] << 6) & 0xfc) | (byte)(quad[3] & 0x3f));
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
			int index = in.read(triplet);
			while (index == 3) {
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
				index = in.read(triplet);
			}

			// Do padding.
			if (index == 2) {
				// 6 MSB from first octet.
				int sextet1 = (triplet[0] >> 2) & 0x3f;
				encoded += ALPHABET[sextet1];
				encoded = checkLine(encoded, writer);
				// 2 LSB from first octet and 4 MSB from second octet.
				int sextet2 = ((triplet[0] & 0x03) << 4) | ((triplet[1] >> 4) & 0x0f);
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
			else if (index == 1) {
				// 2 LSB from first octet and zero padding.
				int sextet2 = (triplet[0] & 0x03) << 4;
				encoded += ALPHABET[sextet2];
				encoded = checkLine(encoded, writer);
				encoded += "=";
				encoded = checkLine(encoded, writer);
				encoded += "=";
				encoded = checkLine(encoded, writer);
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
		triplet[3] = (byte)(crcValue & 0xff);

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
	 * Find the index of the radix-64 character. throws an
	 * encoding exception if the index isn't found.
	 */
	private int findIndex(char letter)
			throws EncodingException {
		int index = 0;
		while (index < ALPHABET.length) {
			if (ALPHABET[index] == letter) {
				return index;
			}
		}
		throw new EncodingException("Armored character out of range");
	}

}
