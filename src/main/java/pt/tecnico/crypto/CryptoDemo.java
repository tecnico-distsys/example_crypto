package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.io.InputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Introduce the Java Cryptography Architecture (JCA).
 */
public class CryptoDemo {

	public static void main(String[] args) throws Exception {

		final PrintStream out = System.out;
		final InputStream in = System.in;

		Scanner scanner = new Scanner(in);

		out.println("     _                     ____                  _");
		out.println("    | | __ ___   ____ _   / ___|_ __ _   _ _ __ | |_ ___");
		out.println(" _  | |/ _` \\ \\ / / _` | | |   | '__| | | | '_ \\| __/ _ \\");
		out.println("| |_| | (_| |\\ V / (_| | | |___| |  | |_| | |_) | || (_) |");
		out.println(" \\___/ \\__,_| \\_/ \\__,_|  \\____|_|   \\__, | .__/ \\__\\___/");
		out.println("                                     |___/|_|");
		out.println();

		out.println("Welcome to the Java cryptography demonstration!");
		out.println();

		out.println("The Java Cryptography Architecture (JCA) includes a large set of ");
		out.println("application programming interfaces (APIs), tools, and implementations of security algorithms.");
		out.println();

		out.println("The JCA APIs include abstractions for:");
		out.println("- secure random number generation,");
		out.println("- key generation and management,");
		out.println("- certificates and certificate validation,");
		out.println("- encryption (symmetric/asymmetric block/stream ciphers),");
		out.println("- message digests (secure hashes), and");
		out.println("- digital signatures.");
		out.println();

		out.println("Press enter to start the demonstration");
		scanner.nextLine();

		out.println("*** Symmetric cipher ***");
		out.println();

		out.println("A symmetric cipher uses a secret key to encrypt and decrypt information.");
		out.println();

		final byte[] encodedKey = { (byte) 0x13, (byte) 0x45, (byte) 0x22, (byte) 0x07, (byte) 0x06, (byte) 0xF7,
				(byte) 0xC3, (byte) 0xDD, (byte) 0x13, (byte) 0x77, (byte) 0x22, (byte) 0x07, (byte) 0xE6, (byte) 0xF2,
				(byte) 0x91, (byte) 0x80 };
		SecretKeySpec secretKeySpec = new SecretKeySpec(encodedKey, "AES");

		out.println("In this code we have a predefined key with this value (presented in hexadecimal notation):");
		out.println(printHexBinary(encodedKey));
		out.printf("The key is %d bytes (%d bits) long.%n", encodedKey.length, encodedKey.length * 8);
		out.println();

		String sentence = "";
		do {
			out.println("Please enter a sentence to cipher: ");
			sentence = scanner.nextLine();
		} while (sentence == null || sentence.trim().length() == 0);

		out.println("The string representation of the sentence is:");
		out.println("\"" + sentence + "\"");

		byte[] plainBytes = sentence.getBytes();
		out.println("The binary representation of the sentence (in hexadecimal) is:");
		out.println(printHexBinary(plainBytes));
		out.printf("The data is %d bytes (%d bits) long%n", plainBytes.length, plainBytes.length * 8);
		out.println();

		final String SYM_CIPHER = "AES/ECB/PKCS5Padding";
		out.println("We ask Java for a cipher implementation with a provider string:");
		out.println(SYM_CIPHER);
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);
		out.println();

		out.println("We now have a cipher object:");
		out.println(cipher);
		out.println();

		out.println("We initialize it for encryption with the key shown earlier.");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		out.println();

		out.println("Press enter to continue");
		scanner.nextLine();

		out.println("We encrypt the data...");
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		out.println("This is the ciphered data (in hexadecimal):");
		out.println(printHexBinary(cipherBytes));
		out.printf("The data is %d bytes (%d bits) long.%n", cipherBytes.length, cipherBytes.length * 8);
		out.println();

		out.println("As you can see, the data is very different from the original!");
		out.println("You may notice an increase in data size because of padding to adjust the final data block.");
		out.println();

		out.println("Press enter to continue");
		scanner.nextLine();

		out.println("We decrypt the data...");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);

		out.println("This is the recovered data:");
		out.println(printHexBinary(newPlainBytes));
		out.printf("The data is %d bytes (%d bits) long.%n", newPlainBytes.length, newPlainBytes.length * 8);

		out.println("Converted back to text:");
		String newPlainText = new String(newPlainBytes);
		out.println("\"" + newPlainText + "\"");

		out.println("");

		out.println("Press enter to continue");
		scanner.nextLine();

		out.println("*** Digest ***");
		out.println();

		out.println("A message digest is a cryptographic one-way hashing function computed from an input.");
		out.println("Digests can be used to detect changes to a message and to build integrity protection.");
		out.println();

		final String DIGEST_ALGO = "SHA-256";
		out.println("We ask Java for a digest implementation with a provider string:");
		out.println(DIGEST_ALGO);
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		out.println("We now have an object that can compute a digest:");
		out.println(messageDigest);

		out.println("Press enter to continue");
		scanner.nextLine();

		out.println("Again we will use the sentence:");
		out.println("\"" + sentence + "\"");
		out.println("(in hexadecimal):");
		out.println(printHexBinary(plainBytes));
		out.println();

		out.println("Computing digest ...");
		messageDigest.update(plainBytes);
		byte[] digest = messageDigest.digest();

		out.println("Digest value:");
		out.println(printHexBinary(digest));
		out.printf("The digest is %d bytes (%d bits) long.%n", digest.length, digest.length * 8);
		out.println();

		out.println("For a given function, the digest output is always of the same size.");
		out.println();

		out.println("Press enter to continue");
		scanner.nextLine();

		out.println("We will now make a small modification to the input:");
		sentence = "X" + sentence.substring(1);
		plainBytes = sentence.getBytes();
		out.println("\"" + sentence + "\"");
		out.println("(in hexadecimal):");
		out.println(printHexBinary(plainBytes));

		out.println("Computing digest for new sentence ...");
		messageDigest.reset();
		messageDigest.update(plainBytes);
		digest = messageDigest.digest();

		out.println("New digest value:");
		out.println(printHexBinary(digest));
		out.println();

		out.println("Notice that a small change in the text produced a big change in the digest value.");
		out.println();
		out.println("By itself, the digest does not provide protection,");
		out.println("but it can be combined with a secret or a cipher to produce a signature.");
		out.println();

		out.println("Press enter to conclude demonstration.");
		scanner.nextLine();

		out.println("You can find more code snippets in the examples and tests:");
		out.println("`src/main/java` and `src/test/java`.");
		out.println();

		out.println("You can find the JCA documentation here:");
		out.println(
				"https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Introduction");
		out.println();

		out.println("Have fun with Java cryptography! :)");
		out.println();

		scanner.close();
	}
}
