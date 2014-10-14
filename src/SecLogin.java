import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SecLogin implements Runnable {

	/** Size of user history files */
	private static final int HIST_SIZE = 8 << 10; // 8KB
	
	/** Max h value for history of logins */
	private static final int HIST_H = 20;

	/** Number of distinguishing features per user */
	private static final int DIST_FEAT_CNT = 15;

	/** Random used for generating values */
	private static Random rand = new Random();
	
	/** History file magic text */
	private static final String HIST_TEXT = "This is a history file.";

	/**
	 * Calculate the polynomial given coefficients
	 * @param hpwd The constant for the polynomial
	 * @param coeff The coefficient values for the polynomial
	 * @param x The value of the polynomial variable
	 * @return The summed polynomial
	 */
	private BigInteger calculatePoly(BigInteger hpwd, int[] coeff, int x) {
		BigInteger a0 = new BigInteger(hpwd.toString());
		System.out.println(a0);
		for(int i = 1; i < DIST_FEAT_CNT; ++i) {
			BigInteger xval = BigInteger.valueOf(x);
			BigInteger aval = BigInteger.valueOf(coeff[i - 1]);
			BigInteger b = xval.pow(i).multiply(aval);
			a0 = a0.add(b);
		}
		System.out.println(a0);

		return a0;
	}

	/**
	 * Perform Gr(x) mod q.
	 * @param password What we are encrypting wityh SHA-1
	 * @param q The modulus of the size we are allowing the output to be
	 * @param x Seed for the SHA-1 digest
	 * @return The completed calculation of Gr(x) mod q
	 */
	private BigInteger calculate_hash(String password , BigInteger q, int x) {
		// HmacSHA1 for G(x) - Key is the password (user input) supplied in file 
		BigInteger Alpha1 = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec secret=new SecretKeySpec(password.getBytes(),mac.getAlgorithm());
			mac.init(secret);
			//   String input = new String("2");
			String input =  "" + x;

			byte[] rawHmac = mac.doFinal(input.getBytes());
			Alpha1 = new BigInteger(1,rawHmac);

			System.out.println("Hash value is " + Alpha1);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		Alpha1 = Alpha1.mod(q);
		return Alpha1;

	}

	/**
	 * Encrypt alpha and beta arrays
	 * @param Alpha Alpha array
	 * @param Beta Beta array
	 * @param password User's password, used as the encryption key
	 */
	private void Encrypt_Alpha_Beta(BigInteger[] Alpha, BigInteger[] Beta, String password) {

		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");

			md.update(password.getBytes()); 
			byte[] output = md.digest();
			output = Arrays.copyOf(output,16);

			String encrypt_value = new String ("prabhendu");

			SecretKeySpec secretkeyspec = new SecretKeySpec(output,"AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] encrypted = cipher.doFinal((encrypt_value.getBytes()));
			BigInteger test3 = new BigInteger(1,output);
			System.out.println("encrypted string: " + test3 + "-" + output);
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	static volatile boolean b__ = true;
	
	/**
	 * Attempt to log in
	 * @param credentials CSV of the login credentials and feature vector
	 * @return Whether or not the user was authenticated
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	private boolean loginAttempt(String credentials) throws
			NoSuchAlgorithmException,
			IllegalBlockSizeException,
			BadPaddingException,
			UnsupportedEncodingException,
			NoSuchPaddingException,
			InvalidKeyException {

		// Parse login string
		String[] vals = credentials.split(" ");
		int seqNum = Integer.parseInt(vals[0]);
		String name = vals[1];
		int[] features = new int[DIST_FEAT_CNT];
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			features[i] = Integer.parseInt(vals[i + 2]);
		}

		// Get pasword from the user
		Scanner in = new Scanner(System.in);
		System.out.println("Enter password for user " + name);
		String password = in.nextLine();


		// If new user, do init
		if(!new File(name + ".hist").exists() || b__) {

			// Create random vector
			BigInteger q = new BigInteger(160, Integer.MAX_VALUE, new Random());
			BigInteger hpwd = new BigInteger(256, Integer.MAX_VALUE, new Random()).mod(q);
			int[] coeff = new int[DIST_FEAT_CNT - 1];
			for(int i = 0; i < DIST_FEAT_CNT - 1; ++i) {
				coeff[i] = Math.abs(rand.nextInt());
			}

			BigInteger y, Alpha1, Beta1;
			BigInteger[] Alpha = new BigInteger[DIST_FEAT_CNT];
			BigInteger[] Beta = new BigInteger[DIST_FEAT_CNT];

			//Calculation of Alpha values for instruction table				
			for(int i = 1; i <= DIST_FEAT_CNT ; ++i ) {
				y = calculatePoly(hpwd, coeff, 2*i);
				Alpha1 = calculate_hash(password, q, 2*i);
				Alpha1 = Alpha1.add(y);
				Alpha[i-1] = Alpha1;
			}

			//Calculation of Beta values for instruction table
			for(int i = 1; i <= DIST_FEAT_CNT ; ++i ) {
				y = calculatePoly(hpwd, coeff, 2*i + 1);
				Beta1 = calculate_hash(password, q, 2*i + 1);
				Beta1 = Beta1.add(y);
				Beta[i-1] = Beta1;
			}

			// Encrypt_Alpha_Beta(Alpha, Beta, password);

			// Create history file contents
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			PrintWriter pw = new PrintWriter(caw), fw = null; // fw is our file writer to create history file on disk
			pw.write(HIST_TEXT + "\n");
			pw.write(1 + "\n");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(features[i] + "\n");
			}
			FileWriter fw_intermediate = null;
			try {
				fw_intermediate = new FileWriter(name + ".hist");
				fw = new PrintWriter(fw_intermediate);
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			// Encrypt history file contents
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE);
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(password.getBytes()); 
			byte[] hist_key = md.digest();
			hist_key = Arrays.copyOf(hist_key, 16);
			SecretKeySpec secretkeyspec = new SecretKeySpec(hist_key,"AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] hist_encrypted = cipher.doFinal(new String(hist_contents).getBytes());
			
			// Write history contents to file
			fw.write(new String(hist_encrypted));
		}
		
		// Test decryption
		

		return true;
	}

	/**
	 * Server function. It will have already connected to a client
	 */
	@Override
	public void run() {

		Scanner inputFile = null;
		try {
			inputFile = new Scanner(new File("testfile.txt"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		}

		while(inputFile.hasNext()) {
			String nextLine = inputFile.nextLine();
			boolean attempt = false;
			try {
				attempt = loginAttempt(nextLine);
			} catch (Exception e) {
				e.printStackTrace();
			}
			System.out.println("Attempted login: " + (attempt ? "accept" : "failed"));
		}
	}

	/**
	 * Validate user input, and call the client or server main for SecLogin
	 * @param args Contains IP and port for client, or -s and port for server
	 */
	public static void main(String[] args) {
		new Thread(new SecLogin()).start();
	}
}
