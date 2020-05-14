package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static javax.xml.bind.DatatypeConverter.printBase64Binary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Test suite to show how the Java Security API can be used for symmetric
 * cryptography using XML documents.
 */
public class XMLCryptoTest {

	/** XML text. */
	final String xml = "<message><body>There and Back Again</body></message>";

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;
	/** Length of initialization vector. */
	private static final int SYM_IV_LEN = 16;
	/** Number generator algorithm. */
	private static final String NUMBER_GEN_ALGO = "SHA1PRNG";
	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String SYM_CIPHER = "AES/CBC/PKCS5Padding";

	/**
	 * Example of how to insert and retrieve cipher data to and from XML, using base
	 * 64 encoding to represent ciphered data as text
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testXMLCrypto() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER);
		System.out.println("' with XML (textual) data");

		System.out.println("XML text:");
		System.out.println(xml);

		// parse XML document
		InputStream xmlInputStream = new ByteArrayInputStream(xml.getBytes());

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		System.out.println("Parsing XML document from string bytes...");
		Document xmlDocument = documentBuilder.parse(xmlInputStream);

		// use transformer to print XML document from memory
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.VERSION, "1.0");
		transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");

		System.out.println("XML document contents:");
		transformer.transform(new DOMSource(xmlDocument), new StreamResult(System.out));
		System.out.println();

		// retrieve body text
		Node bodyNode = null;
		for (Node node = xmlDocument.getDocumentElement().getFirstChild(); node != null; node = node.getNextSibling()) {
			if (node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("body")) {
				bodyNode = node;
				break;
			}
		}
		if (bodyNode == null) {
			throw new Exception("Body node not found!");
		}

		String plainText = bodyNode.getTextContent();
		byte[] plainBytes = plainText.getBytes();

		System.out.println("Body text:");
		System.out.println(plainText);
		System.out.println("Bytes");
		System.out.println(printHexBinary(plainBytes));

		// remove body node
		xmlDocument.getDocumentElement().removeChild(bodyNode);

		// cipher body

		// generate a secret key
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();

		// get an AES cipher object
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);
		// sample AES initialization vector
		byte[] iv = new byte[SYM_IV_LEN];
		SecureRandom random = SecureRandom.getInstance(NUMBER_GEN_ALGO);
		random.nextBytes(iv);
		IvParameterSpec ips = new IvParameterSpec(iv);
		// encrypt using the key and the plain text
		cipher.init(Cipher.ENCRYPT_MODE, key, ips);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.println("Ciphered bytes:");
		System.out.println(printHexBinary(cipherBytes));

		// encoding binary data with base 64
		String cipherText = printBase64Binary(cipherBytes);
		System.out.println("Ciphered bytes in Base64:");
		System.out.println(cipherText);

		// create the element
		Element cipherBodyElement = xmlDocument.createElement("cipherBody");
		Text text = xmlDocument.createTextNode(cipherText);
		cipherBodyElement.appendChild(text);
		// append nodes to document
		xmlDocument.getDocumentElement().appendChild(cipherBodyElement);

		System.out.println("XML document with cipher body:");
		transformer.transform(new DOMSource(xmlDocument), new StreamResult(System.out));
		System.out.println();

		// decipher body
		String cipherBodyText = cipherBodyElement.getTextContent();

		System.out.println("Cipher body text:");
		System.out.println(cipherBodyText);

		// decoding string in base 64
		byte[] cipherBodyBytes = parseBase64Binary(cipherBodyText);
		System.out.print("Ciphered bytes: ");
		System.out.println(printHexBinary(cipherBodyBytes));

		// get an AES cipher object
		Cipher newCipher = Cipher.getInstance(SYM_CIPHER);

		// decipher using the key and the cipher text
		newCipher.init(Cipher.DECRYPT_MODE, key, ips);
		byte[] newPlainBytes = newCipher.doFinal(cipherBodyBytes);
		System.out.println("Deciphered bytes:");
		System.out.println(printHexBinary(newPlainBytes));
		String newPlainText = new String(newPlainBytes);
		System.out.println("Body text:");
		System.out.println(newPlainText);

		// remove cipher body node
		xmlDocument.getDocumentElement().removeChild(cipherBodyElement);

		// create the element
		Element bodyElement = xmlDocument.createElement("body");
		Text newText = xmlDocument.createTextNode(newPlainText);
		bodyElement.appendChild(newText);
		// append nodes to document
		xmlDocument.getDocumentElement().appendChild(bodyElement);

		System.out.println("XML document with new body:");
		transformer.transform(new DOMSource(xmlDocument), new StreamResult(System.out));
		System.out.println();

		assertEquals(plainText, newPlainText);
		
		System.out.println();
		System.out.println();
	}

}
