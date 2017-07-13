/**
 * 
 */
package org.cryptokitty.codec;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.commons.io.IOUtils;
import org.cryptokitty.exceptions.CodecException;

/**
 * @author stevebrenneis
 *
 */
public class Base64Wrapper {

	/**
	 * 
	 */
	public Base64Wrapper() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * 
	 * @param base64
	 * @return
	 * @throws IOException
	 * @throws CodecException
	 */
	public static byte[] decodePEM(String base64)
										throws IOException, CodecException {

		BufferedReader reader = new BufferedReader(new StringReader(base64));
		String line = reader.readLine();
		if (line.charAt(0) != '-') {
			throw new CodecException("Not a PEM string");
		}
		StringBuilder builder = new StringBuilder();
		line = reader.readLine();
		while (line.charAt(0) != '-') {
			builder.append(line);
			line = reader.readLine();
			if (line.charAt(0) != '-') {
				builder.append('\n');
			}
		}
		InputStream stringStream = IOUtils.toInputStream(builder.toString(), "UTF-8");
		InputStream in = new Base64InputStream(stringStream);
		byte[] decoded = IOUtils.toByteArray(in);
		return decoded;

	}

	/**
	 * 
	 * @param pemOut
	 * @throws IOException 
	 */
	public static void encodePEM(OutputStream pemOut, byte[] encoded) throws IOException {

		OutputStream b64Out = new Base64OutputStream(pemOut, true, 64, "\n".getBytes());
		b64Out.write(encoded);
		IOUtils.closeQuietly(b64Out);

	}
}
