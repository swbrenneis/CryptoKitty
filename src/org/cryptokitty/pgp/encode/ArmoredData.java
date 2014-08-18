/**
 * 
 */
package org.cryptokitty.pgp.encode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import org.cryptokitty.pgp.packet.PacketReader;

/**
 * @author Steve Brenneis
 *
 * This class creates the radix-64 encoded "armored"
 * output given as buffer of binary data. Binary data
 * means any kind of literal, or literal compressed data.
 * See RFC 4880, section 6.2.
 */
public class ArmoredData {

	/*
	 * CRC initialization values
	 */
	private static final long CRC24_INIT = 0xB704CEL;
	private static final long CRC24_POLY = 0x1864CFBL;

	/*
	 * Binary data to be armored.
	 */
	private byte[] data;

	/**
	 * Empty object for decoding.
	 */
	public ArmoredData() {
		data = null;
	}

	/**
	 * Takes a byte array of raw data to be encoded.
	 */
	public ArmoredData(byte[] data) {
		this.data = data;
	}

	/*
	 * Perform the CRC-24 calculation.
	 */
	private long crc() {

		long crcValue = CRC24_INIT;
		int index = 0;
		while (index < data.length) {
			crcValue ^= (data[index++] << 16) & 0xff0000;
			for (int i = 0; i < 8; i++) {
				crcValue = crcValue << 1;
				if ((crcValue & 0x1000000) != 0) {
					crcValue ^= CRC24_POLY;
				}
			}
		}
		return crcValue;

	}

	/*
	 * Decode incoming data and populate the raw data byte array.
	 */
	public void decode(InputStream in)
			throws EncodingException {

		ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));

		try {
			String line = reader.readLine();
			if (!line.startsWith("-----")) {
				throw new EncodingException("Invalid message block start");
			}

			// TODO Decode message type and comments
			line = reader.readLine();
			// First blank line delimits data block.
			while (line.length() > 0) {
				line = reader.readLine();
			}
			
			//Load the encoded data into a byte array.
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			line = reader.readLine();
			while (line.charAt(0) != '=') {
				bOut.write(line.getBytes());
				line = reader.readLine();
			}

			ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());

			// Decodes the stream to the CRC delimiter.
			Radix64 decoder = new Radix64();
			decoder.decode(bIn, bytesOut);
			data = bytesOut.toByteArray();

			long crcValue = decoder.decodeCRC(line);
			if (crcValue != crc()) {
				throw new EncodingException("CRC error");
			}
		}
		catch (IOException e) {
			throw new EncodingException(e);
		}

	}

	/*
	 * Encode the data to the output stream.
	 */
	public void encode(OutputStream out)
			throws EncodingException {

		try {
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
			// TODO Figure out the real cases for different headers.
			String header = "-----";
			String footer = "-----";
			int tag = getTag();
			switch (tag) {
			case 1:
				header += "BEGIN PGP MESSAGE";
				footer += "END PGP MESSAGE";
				break;
			case PacketReader.PUBLIC_KEY_PACKET:
				header += "BEGIN PGP PUBLIC KEY BLOCK";
				footer += "END PGP PUBLIC KEY BLOCK";
				break;
			case 3:
				header += "BEGIN PGP PRIVATE KEY BLOCK";
				footer += "END PGP PRIVATE KEY BLOCK";
				break;
			case 11:
				header += "BEGIN PGP MESSAGE, PART X/Y";
				footer += "END PGP MESSAGE, PART X/Y";
				break;
			case 5:
				header += "BEGIN PGP MESSAGE, PART X";
				footer += "END PGP MESSAGE, PART X";
				break;
			case PacketReader.SIGNATURE_PACKET:
			case PacketReader.ONE_PASS_SIGNATURE_PACKET:
				header += "BEGIN PGP SIGNATURE";
				footer += "END PGP SIGNATURE";
				break;
			}
			header += "-----";
			footer += "-----";
			writer.write(header);
			writer.newLine();
			writer.write("Version: CryptoKitty PGP v0.1");
			writer.newLine();
			writer.newLine();
			writer.flush();

			ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
			Radix64 encoder = new Radix64();
			encoder.encode(bytesIn, out);

			// CRC
			String crcString = encoder.encodeCRC(crc());
			writer.write(crcString);
			writer.newLine();
			writer.write(footer);
			writer.newLine();
			writer.flush();

		}
		catch (IOException e) {
			throw new EncodingException(e);
		}

	}

	/*
	 * Return the decoded data.
	 */
	public byte[] getData() {
		return data;
	}

	/*
	 * Get the packet tag.
	 */
	private int getTag() {
		int type = data[0] & 0x7f;
		int tag;
		if ((type & 0x40) != 0) {
			// New format tag.
			tag = type & 0x3f;
		}
		else {
			tag = (type >> 2) & 0x0f;
		}
		return tag;
	}

}
