import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

	static volatile boolean ALWAYS_WRITE_INIT_FILES = false;
	
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
	private static final String AB_TEXT = "This is the alpha beta file.";
	
	/** Threshhold value for feature vectors */
	private static int[] THRESH = new int[15];
	static {
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			THRESH[i] = 500;
		}
	}

	/**
	 * Calculate the polynomial given coefficients
	 * @param hpwd The constant for the polynomial
	 * @param coeff The coefficient values for the polynomial
	 * @param x The value of the polynomial variable
	 * @return The summed polynomial
	 */
	private BigInteger calculatePoly(BigInteger hpwd, BigInteger[] coeff, int x) {
		//BigInteger a0 = new BigInteger(hpwd.toString());
		//prabs testing
		BigInteger a0 = hpwd;
//		System.out.println(a0);
		for(int i = 1; i < DIST_FEAT_CNT; ++i) {
			BigInteger xval = BigInteger.valueOf(x);
			//BigInteger aval = BigInteger.valueOf(coeff[i - 1]);
			BigInteger aval = coeff[i - 1];
			BigInteger b = xval.pow(i).multiply(aval);
			a0 = a0.add(b);
		}
//		System.out.println(a0);

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

//			System.out.println("Hash value is " + Alpha1);
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
	
	/**
	 * Attempt to log in
	 * @param credentials CSV of the login credentials and feature vector
	 * @return Whether or not the user was authenticated
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 */
	private boolean loginAttempt(String credentials) throws
			NoSuchAlgorithmException,
			IllegalBlockSizeException,
			BadPaddingException,
			NoSuchPaddingException,
			InvalidKeyException,
			IOException {

		//testing hpwd outside
		BigInteger hpwd1 = null;
		// Parse login string
		String[] vals = credentials.split(" ");
		int seqNum = Integer.parseInt(vals[0]);
		String name = vals[1];
		int[] features = new int[DIST_FEAT_CNT];
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			features[i] = Integer.parseInt(vals[i + 2]);
		}

		// Get password from the user
		Scanner in = new Scanner(System.in);
		System.out.println("Enter password for user " + name);
		String password = in.nextLine();

		// If new user, do init
		if(!new File(name + ".hist").exists() || ALWAYS_WRITE_INIT_FILES) {

			// Create random vector
			BigInteger q = new BigInteger(160, Integer.MAX_VALUE, new Random());
			System.out.println("prabs q " + q);
			System.out.println("length in bits of q " + q.bitLength());
			BigInteger hpwd = new BigInteger(256, Integer.MAX_VALUE, new Random()).mod(q);
			System.out.println("prabs hpwd " + hpwd);
			System.out.println("length in bits of hpwd " + hpwd.bitLength());
			BigInteger[] coeff = new BigInteger[DIST_FEAT_CNT - 1];
			for(int i = 0; i < DIST_FEAT_CNT - 1; ++i) {
				//coeff[i] = Math.abs(rand.nextInt());
				coeff[i] = new BigInteger(159, Integer.MAX_VALUE, new Random());
				coeff[i] = new BigInteger(""+i);
			}

			//hpwd1 = hpwd;
			BigInteger y, Alpha1, Beta1;
			BigInteger[] Alpha = new BigInteger[DIST_FEAT_CNT];
			BigInteger[] Beta = new BigInteger[DIST_FEAT_CNT];

			//Calculation of Alpha values for instruction table				
			for(int i = 1; i <= DIST_FEAT_CNT ; ++i ) {
				y = calculatePoly(hpwd, coeff, 2*i);
				Alpha1 = calculate_hash(password, q, 2*i);
				Alpha1 = Alpha1.multiply(y);  // modifying as per new paper
				//Alpha1 = Alpha1.mod(q);
				Alpha[i-1] = Alpha1;
			}

			//Calculation of Beta values for instruction table
			for(int i = 1; i <= DIST_FEAT_CNT ; ++i ) {
				y = calculatePoly(hpwd, coeff, 2*i + 1);
				Beta1 = calculate_hash(password, q, 2*i + 1);
				Beta1 = Beta1.multiply(y);  // modifying as per new paper
				//Beta1 = Beta1.mod(q);
				Beta[i-1] = Beta1;
			}
			
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				System.out.printf("Alpha:\t%s\nBeta:\t%s\n", Alpha[i], Beta[i]);
			}

			// Create history file contents
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			PrintWriter pw = new PrintWriter(caw);
			pw.write(HIST_TEXT + "\n");
			pw.write(1 + "\n");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(features[i] + "\n");
			}
			FileOutputStream fos = new FileOutputStream(name + ".hist");
			
			// Encrypt history file contents
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE);
			byte[] hist_key = hpwd.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			SecretKeySpec secretkeyspec = new SecretKeySpec(hist_key,"AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] hist_encrypted = cipher.doFinal(new String(hist_contents).getBytes());
			
			// Write history contents to file
			fos.write(hist_encrypted);
			
			// Create alpha and beta file contents
			caw = new CharArrayWriter(HIST_SIZE);
			pw = new PrintWriter(caw);
			pw.write(AB_TEXT + "\n");
			pw.write(q + "\n");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(Alpha[i] + "\n");
				pw.write(Beta[i] + "\n");
			}
			fos = new FileOutputStream(name + ".ab");
			
			// Encrypt alpha beta file contents
			char[] ab_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE);
			byte[] ab_key = password.getBytes();
			ab_key = Arrays.copyOf(ab_key, 16);
			secretkeyspec = new SecretKeySpec(ab_key,"AES");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] ab_encrypted = cipher.doFinal(new String(ab_contents).getBytes());
			
			// Write contents to alpha beta file
			fos.write(ab_encrypted);
		}  // finish of main if statement
		
		else {
		// Open alpha beta file for this login attempt
		Path ab_path = Paths.get(name + ".ab");
		byte[] ab_bytes = Files.readAllBytes(ab_path);
		System.out.printf("ab_bytes size: %d\n", ab_bytes.length);
		byte[] ab_key = password.getBytes();
		ab_key = Arrays.copyOf(ab_key, 16);
		SecretKeySpec secretkeyspec = new SecretKeySpec(ab_key,"AES");
		Cipher cipher = Cipher.getInstance("AES");
		String ab_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] ab_decrypted = cipher.doFinal(ab_bytes);
			ab_decrypted_string = new String(ab_decrypted);
		} catch (BadPaddingException e) {
			// Login failed
			return false;
		}
		
		// Verify that the password was correct
		Scanner ab_file_scanner = new Scanner(ab_decrypted_string);
		String ab_magic_text = ab_file_scanner.nextLine();
		System.out.println("ab Magic text: " + ab_magic_text);
		if(!AB_TEXT.equals(ab_magic_text)) {
			return false;
		}
		
		// Retrieve Alpha and Beta values
		BigInteger q = new BigInteger(ab_file_scanner.nextLine());
		BigInteger[] Alpha = new BigInteger[DIST_FEAT_CNT],
				     Beta  = new BigInteger[DIST_FEAT_CNT];
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			Alpha[i] = new BigInteger(ab_file_scanner.nextLine());
			Beta[i] = new BigInteger(ab_file_scanner.nextLine());
		}
		
		// Calculate hpwd
		BigInteger[] X = new BigInteger[DIST_FEAT_CNT],
		             Y = new BigInteger[DIST_FEAT_CNT];
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			if (features[i] < THRESH[i]) {
				Y[i] = Alpha[i].divide(calculate_hash(password, q, 2*(i+1)));  // modifying as per new paper
				//Y[i] = Y[i].mod(q);
				X[i] = BigInteger.valueOf(2*(i+1));
			} else {
				Y[i] = Alpha[i].divide(calculate_hash(password, q, 2*(i+1) + 1));  // modifying as per new paper
				//Y[i] = Y[i].mod(q);
				X[i] = BigInteger.valueOf(2*(i+1) + 1);
			}
		}
		BigInteger hpwd_new = new BigInteger("0"), lambda;
		for (int i = 0; i < DIST_FEAT_CNT ; ++i) {
			lambda = new BigInteger("1");
			for(int j = 0; j < DIST_FEAT_CNT; ++j) {
				if(i != j) {
					lambda = lambda.multiply(X[j].divide(X[j].subtract(X[i])));
				}				
			}
			//lambda = lambda.mod(q);
			
			hpwd_new = hpwd_new.add(Y[i].multiply(lambda));
		}
		hpwd_new = hpwd_new.mod(q);
		
		System.out.println("Calculated hardened password is " + hpwd_new);
		
		// Open the history file for this login attempt
		Path hist_path = Paths.get(name + ".hist");
		byte[] hist_bytes = Files.readAllBytes(hist_path);
		System.out.printf("Hist_bytes size: %d\n", hist_bytes.length);
		byte[] hist_key = hpwd_new.toByteArray();
		hist_key = Arrays.copyOf(hist_key, 16);
		secretkeyspec = new SecretKeySpec(hist_key,"AES");
		cipher = Cipher.getInstance("AES");
		String hist_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] hist_decrypted = cipher.doFinal(hist_bytes);
			hist_decrypted_string = new String(hist_decrypted);
		} catch (BadPaddingException e) {
			// Could not decrypt history file with hpwd'
			System.err.println("Could not decrpyt historiy file with hpwd\'");
			return false;
		}
		
		// Verify that the password was correct
		Scanner hist_file_scanner = new Scanner(hist_decrypted_string);
		String hist_magic_text = hist_file_scanner.nextLine();
		if(!HIST_TEXT.equals(hist_magic_text)) {
			return false;
		}
		
		ab_file_scanner.close();
		hist_file_scanner.close();
		} // finish of main else statement
		return true; 
	} // finish of boolean function..

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
