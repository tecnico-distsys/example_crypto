package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for asymmetric
 * cryptography.
 */
public class AsymCryptoTest {

	/** Plain text to digest. */
	private final String plainText = "This is the plain text!";
	/** Plain text bytes. */
	private final byte[] plainBytes = plainText.getBytes();

	/** Asymmetric cryptography algorithm. */
	private static final String ASYM_ALGO = "RSA";
	/** Asymmetric cryptography key size. */
	private static final int ASYM_KEY_SIZE = 2048;
	/**
	 * Asymmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";

	/**
	 * Public key cryptography test. Cipher with public key, decipher with private
	 * key.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testCipherPublicDecipherPrivate() throws Exception {
		System.out.print("TEST '");
		System.out.print(ASYM_CIPHER);
		System.out.println("' cipher with public, decipher with private");

		System.out.println("Text");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// generate an RSA key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
		keyGen.initialize(ASYM_KEY_SIZE);
		KeyPair keyPair = keyGen.generateKeyPair();

		// get an RSA cipher object
		Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

		System.out.println("Ciphering with public key...");
		// encrypt the plain text using the public key
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		byte[] cipherBytes = cipher.doFinal(plainBytes);

		System.out.println("Ciphered bytes:");
		System.out.println(printHexBinary(cipherBytes));

		System.out.println("Deciphering  with private key...");
		// decipher the ciphered digest using the private key
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] decipheredBytes = cipher.doFinal(cipherBytes);
		System.out.println("Deciphered bytes:");
		System.out.println(printHexBinary(decipheredBytes));

		System.out.println("Text:");
		String newPlainText = new String(decipheredBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);
		
		System.out.println();
		System.out.println();
	}

	/**
	 * Public key cryptography test. Cipher with private key, decipher with public
	 * key.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testCipherPrivateDecipherPublic() throws Exception {
		System.out.print("TEST '");
		System.out.print(ASYM_CIPHER);
		System.out.println("' cipher with private, decipher with public");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// generate an RSA key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
		keyGen.initialize(ASYM_KEY_SIZE);
		KeyPair keyPair = keyGen.generateKeyPair();

		// get an RSA cipher object
		Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

		System.out.println("Ciphering with private key...");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] cipherBytes = cipher.doFinal(plainBytes);

		System.out.println("Ciphered bytes:");
		System.out.println(printHexBinary(cipherBytes));

		System.out.println("Deciphering with public key...");
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		byte[] decipheredBytes = cipher.doFinal(cipherBytes);
		System.out.println("Deciphered bytes:");
		System.out.println(printHexBinary(decipheredBytes));

		System.out.println("Text:");
		String newPlainText = new String(decipheredBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}

}
