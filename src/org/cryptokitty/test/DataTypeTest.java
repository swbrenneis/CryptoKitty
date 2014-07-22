/**
 * 
 */
package org.cryptokitty.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.KeyID;
import org.cryptokitty.data.MPI;
import org.cryptokitty.data.Scalar;
import org.cryptokitty.data.Time;

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

			byte[] mpib1 = { 0, 19, 0x07, 0x40, 0x20 };
			ByteArrayInputStream in1 = new ByteArrayInputStream(mpib1);
			MPI mpi1 = new MPI(in1);
			byte[] enc1 = mpi1.getEncoded();
			if (mpib1.length != enc1.length) {
				System.out.println("MPI conversion 1 failed");
				System.out.println("mpib1 length = " + String.valueOf(mpib1.length)
									+ " enc1 length = " + String.valueOf(enc1.length));
				throw new DataException("Conversion failure");
			}
			for (int i = 0; i < mpib1.length; ++i) {
				if (mpib1[i] != enc1[i]) {
					System.out.println("MPI conversion 1 failed");
					System.out.println("mpib1[i] = " + String.valueOf(mpib1[i])
										+ " enc1[i] = " + String.valueOf(enc1[i]));
					throw new DataException("Conversion failure");
				}
			}
			System.out.println("MPI conversion 1 success!");

			byte[] mpib2 = { 0x07, 0x40, 0x20 };
			MPI mpi2 = new MPI(mpib2);
			enc1 = mpi2.getEncoded();
			for (int i = 0; i < mpib1.length; ++i) {
				if (mpib1[i] != enc1[i]) {
					System.out.println("MPI conversion 2 failed");
					System.out.println("mpib1[i] = " + String.valueOf(mpib1[i])
										+ " enc1[i] = " + String.valueOf(enc1[i]));
					throw new DataException("Conversion failure");
				}
			}
			System.out.println("MPI conversion 2 success!");

			byte[] n1 = new byte[4];
			long now = System.currentTimeMillis() / 1000;
			long enc = now;
			for (int b = 3; b >= 0; b--) {
				n1[b] = (byte)(enc & 0xff);
				enc = enc >> 8;
			}
			Time tm1 = new Time();
			byte[] tb1 = tm1.getEncoded();
			Time tm2 = new Time(n1);
			long t1 = tm2.getTime();
			for (int i = 0; i < n1.length; ++i) {
				if (n1[i] != tb1[i]) {
					System.out.println("Time conversion 1 failed");
					System.out.println("n1[i] = " + String.valueOf(n1[i])
										+ " tb1[i] = " + String.valueOf(tb1[i]));
					throw new DataException("Conversion failure");
				}
			}
			System.out.println("Time conversion 1 success!");
			if (t1 != now) {
				System.out.println("Time conversion 2 failed");
				System.out.println("now = " + String.valueOf(now)
									+ " t1 = " + String.valueOf(t1));
				throw new DataException("Conversion failure");
			}
			System.out.println("Time conversion 2 success!");

		}
		catch (IOException e) {
			System.err.println(e.getMessage());
		}
		catch (DataException e) {
			System.err.println(e);
		}
		
	}

}
