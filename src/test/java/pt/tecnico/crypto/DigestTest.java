package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;

import org.junit.jupiter.api.Test;

/** Test suite to show how the Java Security API can be used for digests. */
public class DigestTest {

	/** Plain text to use with the digest. */
	final String plainText = "This is the plain text!";
	/** Plain text bytes. */
	final byte[] plainBytes = plainText.getBytes();

	/** Digest algorithm. */
	private static final String DIGEST_ALGO = "SHA-256";

	/**
	 * Generate a digest using a digest algorithm.
	 */
	@Test
	public void testDigest() throws Exception {
		System.out.print("TEST '");
		System.out.print(DIGEST_ALGO);
		System.out.println("' digest");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		System.out.println("Computing digest...");
		messageDigest.update(plainBytes);
		byte[] digest = messageDigest.digest();

		System.out.println("Digest:");
		System.out.println(printHexBinary(digest));

		assertTrue("491e0b645f6d596b76529d2380b1bd96f5a1f7b83b51e64f49fd634d74cd7d15"
				.equalsIgnoreCase(printHexBinary(digest)));

		System.out.println();
		System.out.println();
	}

}
