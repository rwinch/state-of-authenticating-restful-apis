package sample;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

/**
 * Generates M1420 format for hashcat https://hashcat.net/wiki/doku.php?id=example_hashes
 *
 * @author Rob Winch
 */
public class Main {
	static final Random RAND = new SecureRandom();

	public static void main(String[] args) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] saltBytes = new byte[8];

		ClassLoader loader = Thread.currentThread().getContextClassLoader();

		File outputFile = new File("passwords-A0.M1420.hash");
		if(!outputFile.exists()) {
			outputFile.createNewFile();
		}
		try(FileWriter writer = new FileWriter(outputFile)) {
			try(InputStream inputStream = loader.getResourceAsStream("passwords.txt")) {
				BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
				reader.lines().forEach( text-> {
					RAND.nextBytes(saltBytes);
					String saltStr = toHex(saltBytes);
					byte[] textBytes = text.getBytes(Charset.defaultCharset());
					byte[] saltStrBytes = saltStr.getBytes(Charset.defaultCharset());
					md.update(concatenate(saltStrBytes,textBytes));
					byte[] digest = md.digest();
					writeLine(writer,toHex(digest) + ":"+ saltStr);
				});
			}
		}
	}

	private static void writeLine(Writer writer, String value) {
		try {
			writer.write(value);
			writer.write(System.lineSeparator());
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static String toHex(byte[] bytes) {
		return DatatypeConverter.printHexBinary(bytes);
	}

	/**
	 * Combine the individual byte arrays into one array.
	 */
	private static byte[] concatenate(byte[]... arrays) {
		int length = 0;
		for (byte[] array : arrays) {
			length += array.length;
		}
		byte[] newArray = new byte[length];
		int destPos = 0;
		for (byte[] array : arrays) {
			System.arraycopy(array, 0, newArray, destPos, array.length);
			destPos += array.length;
		}
		return newArray;
	}

}
