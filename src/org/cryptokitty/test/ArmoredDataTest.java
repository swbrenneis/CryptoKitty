/**
 * 
 */
package org.cryptokitty.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.pgp.encode.ArmoredData;
import org.cryptokitty.pgp.encode.EncodingException;

/**
 * @author stevebrenneis
 *
 */
public class ArmoredDataTest {

	/**
	 * 
	 */
	public ArmoredDataTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {
			ArmoredData armored1 = new ArmoredData();
			FileInputStream in1 = new FileInputStream("buzzpPK.asc");
			armored1.decode(in1);
			in1.close();
			byte[] a1 = armored1.getData();
			ArmoredData armored2 = new ArmoredData(a1);
			FileOutputStream out = new FileOutputStream("ArmoredDataTest.asc");
			armored2.encode(out);
			out.close();
			ArmoredData armored3 = new ArmoredData();
			FileInputStream in2 = new FileInputStream("ArmoredDataTest.asc");
			armored3.decode(in2);
			in2.close();
			byte[] a2 = armored3.getData();
			if (Arrays.equals(a1, a2)) {
				System.out.println("Armored data test 1 passed");
			}
			else {
				System.out.println("Armored data test 1 failed");
			}
		}
		catch (IOException e) {
			System.err.println("IO error: " + e.getMessage());
		}
		catch (EncodingException e) {
			System.err.println("Encoding error: " + e.getMessage());
		}

	}

}
