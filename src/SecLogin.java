import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;


public class SecLogin implements Runnable {
	
	/** Socket for the server to communicate with a client */
	private static Socket clientSocket = null;
	
	/** Size of user history files */
	private static final int HIST_SIZE = 20;
	
	/** Number of distinquishing features per user */
	private static final int DIST_FEAT_CNT = 15;
	
	/** Random used for generating values */
	private static Random rand = new Random();
	
	/**
	 * Main client function
	 * Connect to a server, authenticate
	 * @param args Contains destination IP in args[0], and port in args[1]
	 */
	private static void clientMain(String[] args) {
		try {
			// Connect to the server
			Socket serverSocket = new Socket(args[0], Integer.parseInt(args[1]));
			PrintWriter writeSock = new PrintWriter(serverSocket.getOutputStream(), true);
			BufferedReader readSock = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
			
			// Send login request to server
			System.out.printf("username: ");
			Scanner input = new Scanner(System.in);
			String loginRequest = input.next();
			writeSock.write(loginRequest);
			
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Calculate the polynomial given coefficients
	 * @param hpwd The constant for the polynomial
	 * @param coeff The coefficient values for the polynomial
	 * @param x The value of the polynomial variable
	 * @return The summed polynomial
	 */
	private BigInteger calculatePoly(BigInteger hpwd, int[] coeff, int x) {
		BigInteger a0 = new BigInteger(hpwd.toString());
		//System.out.println(a0);
		for(int i = 1; i < DIST_FEAT_CNT; ++i) {
			BigInteger xval = BigInteger.valueOf(x);
			BigInteger aval = BigInteger.valueOf(coeff[i - 1]);
			BigInteger b = xval.pow(i).multiply(aval);
			System.out.println(a0);
			a0.add(b);
			System.out.println(a0);
		}
		//System.out.println(a0);
		return a0;
	}
	
	/**
	 * Attempt to log in
	 * @param credentials CSV of the login credentials and feature vector
	 * @return Whether or not the user was authenticated
	 */
	private boolean loginAttempt(String credentials) {
		
		// Parse login string
		String[] vals = credentials.split(" ");
		int seqNum = Integer.parseInt(vals[0]);
		String name = vals[1];
		int[] features = new int[DIST_FEAT_CNT];
		for(int i = 0; i < DIST_FEAT_CNT; ++i) {
			features[i] = Integer.parseInt(vals[i + 2]);
		}
		
		// If new user, do init
		if(!new File(name + ".hist").exists()) {
			
			// Create random vector
			BigInteger q = new BigInteger(160, Integer.MAX_VALUE, new Random());
			BigInteger hpwd = new BigInteger(256, Integer.MAX_VALUE, new Random()).mod(q);
			int[] coefficients = new int[DIST_FEAT_CNT - 1];
			for(int i = 0; i < DIST_FEAT_CNT - 1; ++i) {
				coefficients[i] = Math.abs(rand.nextInt());
			}
			
			BigInteger y = calculatePoly(hpwd, coefficients, 2);
		}
		
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
			boolean attempt = loginAttempt(nextLine);
			System.out.println("Attempted login: " + (attempt ? "accept" : "failed"));
		}
	}
	
	/**
	 * Create a new SecLogin server object
	 * @param clientSocket The client who has already been connected to
	 */
	private SecLogin(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}
	
	/**
	 * Main server function
	 * Listen on a port, create a new thread per user
	 * @param args Contains the port number in args[1]
	 */
	private static void serverMain(String[] args) {
		
		new Thread(new SecLogin(null)).start();
		boolean b1 = false, b2 = false;
		while(b1 == b2);
		
		// Initialize server socket to listen on a port
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(Integer.parseInt(args[1]));
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		// Never stop accepting connections
		while(true) {
			
			// Create new thread per connecting user
			Socket clientSocket = null;
			try {
				clientSocket = serverSocket.accept();
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(1);
			}
			new Thread(new SecLogin(clientSocket)).start();
		}
	}
	
	/**
	 * Print details for failed program usage
	 * @param msg The message about the error
	 * @param details Details of the error
	 */
	private static void printErr(String msg, String details) {
		System.err.printf("%s: %s\n", msg, details);
		System.err.println("Usage:   java SecLogin <IP | -s> <port>");
		System.err.println("Example: java SecLogin 123.64.244.15 60005 (client)");
		System.err.println("         java SecLogin -s 60005            (server)");
		System.exit(1);
	}
	
	/**
	 * Make sure the user put in the command line arguments correctly
	 * @param args The command line arguments passed from main
	 */
	private static void validateArgs(String[] args) {
		
		// First, check for the correct number of arguments (2)
		if(args.length != 2) {
			printErr("Incorrect number of args", args.length + " args");
		
		// Next, if this is a client, check the IP format
		} else if(!args[0].equals("-s")) {
			boolean invalidIP = false;
			if(!Pattern.matches("\\d+.\\d+.\\d+.\\d+", args[0])) {
				invalidIP = true;
			} else {
				String[] IPfields = args[0].split("\\.");
				for(int i = 0; i < 4; ++i) {
					int n = Integer.parseInt(IPfields[i]);
					if(n < 0x00 || n > 0xFF) {
						invalidIP = true;
					}
				}
			}
			if(invalidIP) {
				printErr("Invalid IP", args[0]);
			}
		}
		
		// Finally, check the port format
		boolean invalidPort = false;
		if(!Pattern.matches("\\d+", args[1])) {
			invalidPort = true;
		} else {
			int n = Integer.parseInt(args[1]);
			if(n < 0x0000 || n > 0xFFFF) {
				invalidPort = true;
			}
		}
		if(invalidPort) {
			printErr("Invalid port", args[1]);
		}
	}
	
	/**
	 * Validate user input, and call the client or server main for SecLogin
	 * @param args Contains IP and port for client, or -s and port for server
	 */
	public static void main(String[] args) {
		
		// Make sure the arguments were typed in correctly
		validateArgs(args);
		
		// Run client or server main
		if(args[0].equals("-s")) {
			serverMain(args);
		} else {
			clientMain(args);
		}
	}
}
