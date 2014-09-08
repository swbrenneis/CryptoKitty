/**
 * 
 */
package org.cryptokitty.provider.x509.der;

import java.util.Collection;
import java.util.Iterator;

/**
 * @author stevebrenneis
 *
 */
public class DERSequence extends DERConstructed {

	/**
	 * 
	 */
	public DERSequence() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param object
	 */
	public DERSequence(Collection<DERType> object) {
		super(object);
		// TODO Auto-generated constructor stub
	}

	/*
	 * Get an ordered array of DERTypes.
	 */
	public DERType[] getElements() {

		DERType[] elements = new DERType[objects.size()];
		Iterator<DERType> it = objects.iterator();
		int index = 0;
		while (it.hasNext()) {
			elements[index++] = it.next();
		}
		return elements;

	}

}
