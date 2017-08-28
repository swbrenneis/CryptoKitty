/**
 * 
 */
package org.cryptokitty.codec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.cryptokitty.exceptions.CodecException;

/**
 * @author stevebrenneis
 *
 */
public class ByteStreamCodec {

	/**
	 * Input byte stream.
	 */
	protected ByteArrayInputStream in;

	/**
	 * Output byte stream.
	 */
	protected ByteArrayOutputStream out;

	/**
	 * Input constructor.
	 */
	public ByteStreamCodec() {

		in = null;
		out = new ByteArrayOutputStream();

	}

	/**
	 * Output constructor.
	 */
	public ByteStreamCodec(byte[] bytes) {

		out = null;
		in = new ByteArrayInputStream(bytes);

	}

	/**
	 * Get a byte array from the stream.
	 * 
	 * @param bytes
	 * @throws CodecException 
	 */
	public byte[] getBlock() throws CodecException {

		byte[] bytes32 = new byte[4];
		getBytes(bytes32);
		Scalar32 s32 = new Scalar32(bytes32);
		byte[] bytes = new byte[s32.getValue()];
		getBytes(bytes);
		return bytes;

	}

	/**
	 * Get a single byte from the stream
	 * 
	 * @return
	 * @throws CodecException 
	 */
	public byte getByte() throws CodecException {

		byte[] abyte = new byte[1];
		getBytes(abyte);
		return abyte[0];

	}

	/**
	 * Get bytes from the stream.
	 * 
	 * @throws CodecException 
	 */
	public void getBytes(byte[] bytes) throws CodecException {

		if (in == null) {
			throw new CodecException("Invalid byte stream state");
		}

		if (bytes.length > 0) {
			int bytesRead = 0;
			try {
				bytesRead = in.read(bytes);
			}
			catch (IOException e) {
				// Not going to happen
				throw new CodecException(e);
			}
			if (bytesRead < bytes.length) {
				throw new CodecException("Byte buffer underrun");
			}
		}

	}

	/**
	 * Retrieve a 32 bit integer from the byte stream
	 * 
	 * @return
	 * @throws CodecException 
	 */
	public int getInt() throws CodecException {

		byte[] bytes32 = new byte[4];
		getBytes(bytes32);
		Scalar32 s32 = new Scalar32(bytes32);
		return s32.getValue();

	}

	/**
	 * Retrieve a 64 bit integer from the byte stream
	 * 
	 * @return
	 * @throws CodecException 
	 */
	public long getLong() throws CodecException {

		byte[] bytes64 = new byte[8];
		getBytes(bytes64);
		Scalar64 s64 = new Scalar64(bytes64);
		return s64.getValue();

	}

	/**
	 * Retrieve a 16 bit integer from the byte stream
	 * 
	 * @return
	 * @throws CodecException 
	 */
	public short getShort() throws CodecException {

		byte[] bytes16 = new byte[2];
		getBytes(bytes16);
		Scalar16 s16 = new Scalar16(bytes16);
		return s16.getValue();

	}

	/**
	 * Get a String from the stream.
	 * 
	 * @throws CodecException 
	 */
	public String getString() throws CodecException {

		byte[] bytes32 = new byte[4];
		getBytes(bytes32);
		Scalar32 s32 = new Scalar32(bytes32);
		byte[] bytes = new byte[s32.getValue()];
		getBytes(bytes);
		try {
			return new String(bytes, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			// Sadness!
			throw new CodecException("UTF-8 character encoding not supported");
		}
 
	}

	/**
	 * Insert a byte array into the stream.
	 * 
	 * @param bytes
	 * @throws CodecException 
	 */
	public void putBlock(byte[] bytes) throws CodecException {

		Scalar32 s32 = new Scalar32(bytes.length);
		putBytes(s32.getEncoded());
		putBytes(bytes);

	}

	/**
	 * Write a single byte to the stream
	 * 
	 * @param b
	 * @throws CodecException 
	 */
	public void putByte(byte b) throws CodecException {

		byte[] abyte = new byte[1];
		putBytes(abyte);

	}

	/**
	 * Insert bytes to the stream.
	 * 
	 * @param bytes
	 * @throws CodecException
	 */
	public void putBytes(byte[] bytes) throws CodecException {

		if (out == null) {
			throw new CodecException("Invalid byte stream state");
		}
		try {
			out.write(bytes);
		}
		catch (IOException e) {
			// Not going to happen
			throw new CodecException(e);
		}

	}

	/**
	 * Insert a 32 bit integer to the stream.
	 * 
	 * @param i
	 * @throws CodecException 
	 */
	public void putInt(int i) throws CodecException {

		Scalar32 s32 = new Scalar32(i);
		putBytes(s32.getEncoded());
		
	}

	/**
	 * Insert a 64 bit integer to the stream.
	 * 
	 * @param l
	 * @throws CodecException 
	 */
	public void putLong(long l) throws CodecException {

		Scalar64 s64 = new Scalar64(l);
		putBytes(s64.getEncoded());
		
	}

	/**
	 * Insert a 16 bit integer to the stream.
	 * 
	 * @param s
	 * @throws CodecException 
	 */
	public void putShort(short s) throws CodecException {

		Scalar16 s16 = new Scalar16(s);
		putBytes(s16.getEncoded());
		
	}

	/**
	 * Insert a String into the stream.
	 * 
	 * @param str
	 * @throws CodecException 
	 */
	public void putString(String str) throws CodecException {

		Scalar32 s32 = new Scalar32(str.length());
		putBytes(s32.getEncoded());
		putBytes(str.getBytes());

	}

	/**
	 * 
	 * @return The current size of the stream.
	 */
	public int length() {
		
		if (out != null) {
			return out.size();
		}
		else {
			return in.available();
		}
		
	}

	/**
	 * 
	 */
	public void reset() {

		if (in != null) {
			in.reset();
		}
		if (out != null) {
			out.reset();
		}

	}

	/**
	 * Get the output stream as a byte array.
	 * 
	 * @return
	 * @throws CodecException
	 */
	public byte[] toArray() throws CodecException {

		if (out == null) {
			throw new CodecException("Invalid byte stream state");
		}
		
		return out.toByteArray();

	}

}
