package pt.tecnico.crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Program to read and write asymmetric key files
 */
public class AsymKeys {

	public static void main(String[] args) throws Exception {

		// check args
		if (args.length < 3) {
			System.err.println("args: (r/w) (public-key-file) (private-key-file)");
			return;
		}
		final String mode = args[0];
		final String publicKeyPath = args[1];
		final String privateKeyPath = args[2];

		if (mode.startsWith("w")) {
			System.out.println("Generate and save keys");
			write(publicKeyPath, privateKeyPath);
		} else {
			System.out.println("Load keys");
			read(publicKeyPath, privateKeyPath);
		}

		System.out.println("Done.");
	}

	/** Asymmetric cryptography algorithm. */
	private static final String ASYM_ALGO = "RSA";

	/** Asymmetric cryptography key size. */
	private static final int ASYM_KEY_SIZE = 2048;

	public static void write(String publicKeyPath, String privateKeyPath) throws Exception {

		// generate key pair
		System.out.println("Generating " + ASYM_ALGO + " keys ...");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
		System.out.printf("%d bits%n", ASYM_KEY_SIZE);
		keyGen.initialize(ASYM_KEY_SIZE);
		KeyPair key = keyGen.generateKeyPair();

		System.out.println("Public key info:");
		System.out.println("algorithm: " + key.getPublic().getAlgorithm());
		System.out.println("format: " + key.getPublic().getFormat());

		System.out.println("Writing public key to " + publicKeyPath + " ...");
		byte[] pubEncoded = key.getPublic().getEncoded();
		writeFile(publicKeyPath, pubEncoded);

		System.out.println("---");

		System.out.println("Private key info:");
		System.out.println("algorithm: " + key.getPrivate().getAlgorithm());
		System.out.println("format: " + key.getPrivate().getFormat());

		System.out.println("Writing private key to '" + privateKeyPath + "' ...");
		byte[] privEncoded = key.getPrivate().getEncoded();
		writeFile(privateKeyPath, privEncoded);
	}

	public static KeyPair read(String publicKeyPath, String privateKeyPath) throws Exception {

		System.out.println("Reading public key from file " + publicKeyPath + " ...");
		byte[] pubEncoded = readFile(publicKeyPath);

		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
		KeyFactory keyFacPub = KeyFactory.getInstance(ASYM_ALGO);
		PublicKey pub = keyFacPub.generatePublic(pubSpec);
		System.out.println(pub);

		System.out.println("---");

		System.out.println("Reading private key from file " + privateKeyPath + " ...");
		byte[] privEncoded = readFile(privateKeyPath);

		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
		KeyFactory keyFacPriv = KeyFactory.getInstance(ASYM_ALGO);
		PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

		System.out.println("---");

		KeyPair keys = new KeyPair(pub, priv);
		return keys;
	}

	private static void writeFile(String path, byte[] content) throws FileNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(path);
		fos.write(content);
		fos.close();
	}

	private static byte[] readFile(String path) throws FileNotFoundException, IOException {
		FileInputStream fis = new FileInputStream(path);
		byte[] content = new byte[fis.available()];
		fis.read(content);
		fis.close();
		return content;
	}

}
