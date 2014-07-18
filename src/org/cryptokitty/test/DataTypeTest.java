/**
 * 
 */
package org.cryptokitty.test;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.KeyID;
import org.cryptokitty.data.Scalar;

/**
 * @author Steve Brenneis
 *
 * Data type classes test.
 */
public class DataTypeTest {

	/**
	 * 
	 */
	public DataTypeTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {

			long k1 = 4219671234237908012L;
			KeyID id1 = new KeyID(k1);
			byte[] kb1 = id1.getEncoded();
			KeyID id2 = new KeyID(kb1);
			long k2 = id2.getID();
			if (k1 == k2) {
				System.out.println("Key ID conversion 1 success!");
			}
			else {
				System.out.println("Key ID conversion 1 failed.");
				System.out.println("k1 = " + String.valueOf(k1) + ", k2 = "
									+ String.valueOf(k2));
			}

			byte[] kb2 = { 0x01, (byte)0xff, 0x02, (byte)0xef, 0x03, (byte)0xfe, 0x04, 0x00 };
			KeyID id3 = new KeyID(kb2);
			if (id3.getID() == 0x01ff02ef03fe0400L) {
				System.out.println("Key ID conversion 2 success!");
			}

			int s1 = 0x73ff;
			Scalar sc1 = new Scalar(s1);
			byte[] sb1 = sc1.getEncoded();
			Scalar sc2 = new Scalar(sb1);
			int s2 = sc2.getValue();
			if (s1 == s2) {
				System.out.println("Scalar conversion 1 success!");
			}
			else {
				System.out.println("Scalar conversion 1 failed.");
				System.out.println("s1 = " + String.valueOf(s1) + ", s2 = "
									+ String.valueOf(s2));
			}

			byte sb2[] = { (byte)0xff, 0x40 };
			Scalar sc3 = new Scalar(sb2);
			int s3 = sc3.getValue();
			if (s3 == 0xff40) {
				System.out.println("Scalar conversion 2 success!");
			}
			else {
				System.out.println("Scalar conversion 1 failed.");
				System.out.println("s3 = " + String.valueOf(s3));
			}

		}
		catch (DataException e) {
			System.err.println("Bad conversion");
		}
		
	}

}
