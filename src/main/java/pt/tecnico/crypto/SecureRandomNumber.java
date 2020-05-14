package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.SecureRandom;

/**
 * Generate secure random numbers.
 */
public class SecureRandomNumber {

	public static void main(String[] args) throws Exception {

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

		System.out.println("Generating random byte array ...");

		final byte array[] = new byte[32];
		random.nextBytes(array);

		System.out.print("Results: ");
		System.out.println(printHexBinary(array));
	}

}
