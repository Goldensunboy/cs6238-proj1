import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class SecLogin {
	
	/** Variable precision */
	private static final int VAR_PREC = 150;
	
	/** Threshold for feature values in calculating X and Y */
	private static final int THRESH = 500;
	
	/** Size of user history files */
	private static final int HIST_SIZE = 8 << 10; // 8KB
	
	/** Magic text */
	private static final String HIST_TEXT = "This is a history file.";
	
	/** History file size limit */
	private static final int HIST_LIMIT = 20;
	
	/** Static q */
	private static final BigInteger q =
			new BigInteger("957117109103230102421885836974304804951875593197");
	
	/** Distinguishing feature count */
	private static final int DIST_FEAT_CNT = 15;
	
	/** Verify input is correct and send arg to parse main */
	public static void main(String[] args) {
		if(args.length != 1) {
			System.err.println("Usage: java SecLogin <testfile>.txt");
		} else {
			parseMain(args[0]);
		}
	}
	
	/**
	 * Parse input file and make a series of login attempts
	 * @param filename The name of the file from which features are read
	 */
	private static void parseMain(String filename) {
		try (Scanner in = new Scanner(System.in)) {
			Scanner file_scan = new Scanner(new File(filename));
			while(file_scan.hasNext()) {
				LoginFeatures lf = new LoginFeatures(file_scan.nextLine().split(" "));
				System.out.printf("Password for %s: ", lf.username);
				String password = in.nextLine();
				boolean attempt = loginAttempt(lf, password);
				System.out.printf("Login attempt for %s: %s\n",
						lf.username, attempt ? "success" : "failed");
			}
			file_scan.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Perform Gr(x) mod q.
	 * @param password What we are encrypting with SHA-1
	 * @param q The modulus of the size we are allowing the output to be
	 * @param x Seed for the SHA-1 digest
	 * @return The completed calculation of Gr(x) mod q
	 */
	private static BigInteger calculate_hash(String password, int x) {
		// HmacSHA1 for G(x) - Key is the password (user input) supplied in file 
		BigInteger Alpha1 = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec secret=new SecretKeySpec(password.getBytes(),mac.getAlgorithm());
			mac.init(secret);
			String input =  "" + x;
			byte[] rawHmac = mac.doFinal(input.getBytes());
			Alpha1 = new BigInteger(1,rawHmac);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return Alpha1;
	}
	
	/**
	 * Calculate the polynomial given coefficients
	 * @param hpwd The constant for the polynomial
	 * @param coeff The coefficient values for the polynomial
	 * @param x The value of the polynomial variable
	 * @return The summed polynomial
	 */
	private static BigInteger calculatePoly(BigInteger hpwd, BigInteger[] coeff, int x) {
		BigInteger a0 = hpwd;
		for(int i = 1; i < DIST_FEAT_CNT; ++i) {
			BigInteger xval = BigInteger.valueOf(x);
			BigInteger aval = coeff[i - 1];
			BigInteger b = xval.pow(i);
			b = b.multiply(aval);
			a0 = a0.add(b);
		}
		return a0;
	}
	
	private static volatile boolean ERASE_FILES_ON_RUN = true;
	static {
		if(ERASE_FILES_ON_RUN) {
			new File("prabhendu.hist").delete();
			new File("prabhendu.ab").delete();
		}
	}
	
	/**
	 * Attempt to log in
	 * @param lf Features for this login attempt
	 * @return Whether or not the login was successful
	 * @throws IOException 
	 */
	private static boolean loginAttempt(LoginFeatures lf, String password) throws Exception {
		
		// Forward declaration of common variables
		BigInteger[] alpha = new BigInteger[DIST_FEAT_CNT],
		             beta  = new BigInteger[DIST_FEAT_CNT];
		Random rand = new Random();
		BigInteger hpwd;
		
		// If this is the first time, create history file and alpha/beta
		if(!new File(lf.username + ".hist").exists()) {
			
			// Create new hardened password
			hpwd = new BigInteger(VAR_PREC, Integer.MAX_VALUE, rand);
			
			System.out.println("hpwd_org: " + hpwd);
			
			// Create coefficients for polynomial
			BigInteger[] coeff = new BigInteger[DIST_FEAT_CNT];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				coeff[i] = new BigInteger(VAR_PREC, 0, rand);
			}
			
			// Create new alpha and beta values
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				BigInteger gr_pwd1 = calculate_hash(password, (i + 1) << 1);
				BigInteger gr_pwd2 = calculate_hash(password, ((i + 1) << 1) + 1);
				BigInteger y1 = calculatePoly(hpwd, coeff, (i + 1) << 1);
				BigInteger y2 = calculatePoly(hpwd, coeff, ((i + 1) << 1) + 1);
				alpha[i] = y1.multiply(gr_pwd1.mod(q));
				beta[i]  = y2.multiply(gr_pwd2.mod(q));
			}
			
			// Create instruction table file
			PrintWriter pw = new PrintWriter(new File(lf.username + ".ab"));
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(alpha[i] + "\n");
				pw.write(beta[i] + "\n");
			}
			pw.close();
			
			// Create history file contents
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			pw = new PrintWriter(caw);
			pw.write(HIST_TEXT + "\n");
			pw.write(1 + "\n");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(lf.features[i] + "\n");
			}
			FileOutputStream fos = new FileOutputStream(lf.username + ".hist");
			
			// Encrypt history file contents
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE);
			byte[] hist_key = hpwd.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			SecretKeySpec secretkeyspec = new SecretKeySpec(hist_key,"AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] hist_encrypted = cipher.doFinal(new String(hist_contents).getBytes());
			
			// Write history file
			fos.write(hist_encrypted);
			fos.close();
			
		} else {
			
			// Retrieve alpha beta values for this login attempt
			Scanner scan = new Scanner(new File(lf.username + ".ab"));
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				alpha[i] = new BigInteger(scan.nextLine());
				beta[i]  = new BigInteger(scan.nextLine());
			}
			scan.close();
			
			// Calculate X and Y values
			BigInteger X[] = new BigInteger[DIST_FEAT_CNT],
			           Y[] = new BigInteger[DIST_FEAT_CNT];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				if(lf.features[i] < THRESH) {
					X[i] = BigInteger.valueOf((i + 1) << 1);
					BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
					Y[i] = alpha[i].divide(gr_pwd.mod(q));
				} else {
					X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
					BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
					Y[i] = beta[i].divide(gr_pwd.mod(q));
				}
			}
			
			// Calculate lambda
			BigInteger[] lambda = new BigInteger[DIST_FEAT_CNT];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				BigInteger lambda_num = new BigInteger("1"),
				           lambda_den = new BigInteger("1");
				lambda[i] = new BigInteger("1");
				for(int j = 0; j < DIST_FEAT_CNT; ++j) {
					if(i != j) {
						lambda_num = lambda_num.multiply(X[j]);
						lambda_den = lambda_den.multiply(X[j].subtract(X[i]));
					}
				}
				lambda[i] = lambda[i].multiply(Y[i]).multiply(lambda_num);
				lambda[i] = lambda[i].divide(lambda_den);
			}
			
			// Calculate hpwd'
			BigInteger hpwd_sum = new BigInteger("0");
			BigDecimal hpwd_sum_dec = new BigDecimal("0.0");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				hpwd_sum = hpwd_sum.add(lambda[i]).mod(q);
			}
			
			System.out.println("hpwd_new:     " + hpwd_sum);
			System.out.println("length of hpwd_new " + hpwd_sum.bitLength());
			System.out.println("hpwd_new_dec: " + hpwd_sum_dec);
			
			// Open the history file for this login attempt
			Path hist_path = Paths.get(lf.username + ".hist");
			byte[] hist_bytes = Files.readAllBytes(hist_path);
			System.out.printf("Hist_bytes size: %d\n", hist_bytes.length);
			byte[] hist_key = hpwd_sum.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			SecretKeySpec secretkeyspec = new SecretKeySpec(hist_key,"AES");
			Cipher cipher = Cipher.getInstance("AES");
			String hist_decrypted_string = null;
			try {
				cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
				byte[] hist_decrypted = cipher.doFinal(hist_bytes);
				hist_decrypted_string = new String(hist_decrypted);
			} catch (BadPaddingException e) {
				// Could not decrypt history file with hpwd'
				System.err.println("Could not decrypt history file with hpwd\'");
				return false;
			}
			
			// Verify that the password was correct
			Scanner hist_file_scanner = new Scanner(hist_decrypted_string);
			String hist_magic_text = hist_file_scanner.nextLine();
			if(!HIST_TEXT.equals(hist_magic_text)) {
				hist_file_scanner.close();
				return false;
			}
			
			// Read history file contents
			int login_count = Integer.parseInt(hist_file_scanner.nextLine());
			LoginFeatures[] feat_arr = new LoginFeatures[login_count];
			for(int i = 0; i < login_count; ++i) {
				String[] feat_args = new String[DIST_FEAT_CNT + 2];
				feat_args[0] = "" + lf.seqnum;
				feat_args[1] = lf.username;
				for(int j = 0; j < DIST_FEAT_CNT; ++j) {
					feat_args[j + 2] = hist_file_scanner.nextLine();
				}
				feat_arr[i] = new LoginFeatures(feat_args);
			}
			hist_file_scanner.close();
			new File(lf.username + ".hist").delete();
			
			// Calculate feature means
			double[] feat_means = new double[DIST_FEAT_CNT];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				int sum = 0;
				for(int j = 0; j < login_count; ++j) {
					sum += feat_arr[j].features[i];
				}
				feat_means[i] = (double) sum / login_count;
			}
			
			// Calculate feature standard deviations
			double[] feat_devs = new double[DIST_FEAT_CNT];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				double sqdif_sum = 0;
				for(int j = 0; j < login_count; ++j) {
					double dif = feat_arr[j].features[i] - feat_means[i];
					sqdif_sum += dif * dif;
				}
				feat_devs[i] = Math.sqrt(sqdif_sum);
			}
			
			// TODO Calculate new random values for alpha beta file
			
			// TEST
			System.out.println("Logins in history file: " + login_count + "\n");
			System.out.println("Logins:");
			for(int i = 0; i < login_count; ++i) {
				for(int j = 0; j < DIST_FEAT_CNT; ++j) {
					System.out.print("\t" + feat_arr[i].features[j]);
					System.out.print(j == DIST_FEAT_CNT - 1 ? "\n" : "");
				}
			}
			System.out.println("\nMeans:");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				System.out.print("\t" + (int) feat_means[i]);
				System.out.print(i == DIST_FEAT_CNT - 1 ? "\n" : "");
			}
			System.out.println("\nDevs:");
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				System.out.printf("\t%3.3f", feat_devs[i]);
				System.out.print(i == DIST_FEAT_CNT - 1 ? "\n" : "");
			}
			
			// Create new history file
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			PrintWriter pw = new PrintWriter(caw);
			pw.write(HIST_TEXT + "\n");
			pw.write(Math.min(login_count + 1, HIST_LIMIT) + "\n");
			if(login_count < HIST_LIMIT) {
				for(int i = 0; i < login_count; ++i) {
					for(int j = 0; j < DIST_FEAT_CNT; ++j) {
						pw.write(feat_arr[i].features[j] + "\n");
					}
				}
			} else {
				for(int i = 1; i < HIST_LIMIT; ++i) {
					for(int j = 0; j < DIST_FEAT_CNT; ++j) {
						pw.write(feat_arr[i].features[j] + "\n");
					}
				}
			}
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				pw.write(lf.features[i] + "\n");
			}
			FileOutputStream fos = new FileOutputStream(lf.username + ".hist");
			
			// Encrypt history file contents
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE);
			hist_key = hpwd_sum.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			secretkeyspec = new SecretKeySpec(hist_key,"AES");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
			byte[] hist_encrypted = cipher.doFinal(new String(hist_contents).getBytes());
			
			// Write history file
			fos.write(hist_encrypted);
			fos.close();
		}
		
		return true;
	}
	
	/**
	 * Object to contain the login features of one line in the input file
	 */
	private static class LoginFeatures {
		public int seqnum;
		public String username;
		public int[] features = new int[DIST_FEAT_CNT];
		public LoginFeatures(String[] args) {
			seqnum = Integer.parseInt(args[0]);
			username = args[1];
			for(int i = 0; i < DIST_FEAT_CNT; ++i) {
				features[i] = Integer.parseInt(args[i + 2]);
			}
		}
	}
}
