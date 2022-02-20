import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Antivirus {
	static File reportFile = null;
	static File textFile = new File("status file.txt");
	static int numberOfLines = 0;
	static String[] HMACarray = null;
	static String[] filePaths = null;
	
	public static byte[] getHashMACOfOneFile(String inputFileName, byte[] secretKey, String algorithm) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		byte[] hashMac = null;
		
		File file = new File(inputFileName);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		
		//init the Mac object
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(secretKey, algorithm));
		
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		byte [] buffer = new byte[1024];
		int noBytesFromFile = bis.read(buffer);
		
		while(noBytesFromFile != -1) {
			mac.update(buffer, 0, noBytesFromFile);
			noBytesFromFile = bis.read(buffer);
		}
		
		hashMac = mac.doFinal();
		
		return hashMac;
	}
	
	public static String readMode() throws IOException {
		boolean correctStatus=false;
		System.out.println("Please specify the mode you want the antivirus to run on! (status update/integrity check)");
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		String mode = null; 
		while(correctStatus==false) {
			
		mode = reader.readLine();
		mode = mode.toLowerCase();
		
		if(mode.compareTo("status update")==0 || mode.compareTo("status")==0)
		{
			mode = "status";
			correctStatus = true;
			System.out.println("Starting the status update...");
		}
		else
			if(mode.compareTo("integrity check")==0 || mode.compareTo("integrity")==0)
			{
				mode = "integrity";
				correctStatus=true;
				System.out.println("Starting the integrity check...");
			}
			else
			{
				System.out.println("Please select one of those options!");
				System.out.println("Please specify the mode you want the antivirus to run on! (status update/integrity check)");
			}
		}
		return mode;
	}
	
	public static String getHex(byte[] array) {
		String output = "";
		for(byte value : array) {
			output += String.format("%02x", value);
		}
		return output;
	}
	
	public static void writePairToFile(byte[] HMAC, String path) throws IOException {
		FileWriter fileWriter = new FileWriter(textFile);
		fileWriter.append(getHex(HMAC));
		fileWriter.append(" ");
		fileWriter.append(path);
		fileWriter.close();
	}
	
	public static void WriteHMACFolderContent(String path, String secretKey) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		FileWriter fileWriter = new FileWriter(textFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		File folder = new File(path);
		if(folder.exists() && folder.isDirectory()) {
			File[] entries = folder.listFiles();
			for(File entry : entries) 
				if(entry.isDirectory()) {
					WriteHMACFolderContent(entry.getAbsolutePath(), secretKey);
				}
				else
				{
					printWriter.append(getHex(getHashMACOfOneFile(entry.getAbsolutePath(), secretKey.getBytes(), "HmacSHA256")));
					printWriter.append(" ");
					printWriter.append(entry.getAbsolutePath());
					printWriter.append("\n");
				}
		}
		fileWriter.close();
	}
	
	public static void countLines() throws IOException {
		FileReader fileReader = new FileReader(textFile);
		BufferedReader bufferReader = new BufferedReader(fileReader);
		String line  = bufferReader.readLine();
		while(line != null) {
			numberOfLines++;
			line = bufferReader.readLine();
		}
		fileReader.close();
		bufferReader.close();
	}
	
	public static void readStatusFile() throws IOException {
		FileReader fileReader = new FileReader(textFile);
		BufferedReader bufferReader = new BufferedReader(fileReader);
		
		HMACarray = new String[numberOfLines];
		filePaths = new String[numberOfLines];
		
		int index=0;

		String line  = bufferReader.readLine();
		while(line != null) {
			//process line:
			String[] splittedLine = line.split(" ", 2);
			HMACarray[index] = splittedLine[0];
			filePaths[index] = splittedLine[1];
			index++;
			line = bufferReader.readLine();
		}
		
		fileReader.close();
		bufferReader.close();
	}
	
	public static void checkHMAC(String path, String secretKey) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		
		FileWriter fileWriter = new FileWriter(reportFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);

		File folder = new File(path);
		if(folder.exists() && folder.isDirectory()) {
			File[] entries = folder.listFiles();
			for(File entry : entries) 
				if(entry.isDirectory()) {
					checkHMAC(entry.getAbsolutePath(), secretKey);
				}
				else
				{
					int i=0;
					for(i=0; i<numberOfLines; i++) {
						if(filePaths[i].compareTo(entry.getAbsolutePath())==0)
							break;
					}
					if(i<numberOfLines) {
						String HMAC = getHex(getHashMACOfOneFile(entry.getAbsolutePath(), secretKey.getBytes(), "HmacSHA256"));
						printWriter.append(entry.getAbsolutePath());
						printWriter.append("----->");
						if(HMACarray[i].compareTo(HMAC)==0)
							printWriter.append("OK");
						else
							printWriter.append("CORRUPTED");
						printWriter.append("\n");	
					}
				}
		}

		fileWriter.close();
	}
	
	
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		
		if(!(textFile.exists()))
			textFile.createNewFile();
		String mode = readMode();
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Please input your secret key: ");
		String secretKey = reader.readLine();
		
		System.out.println("Please input the path of the files you want to scan: ");
		String path = reader.readLine();
		
		if(mode.compareTo("status")==0) {
			PrintWriter printWriter = new PrintWriter(textFile);
			printWriter.write(""); //empty out the file
			printWriter.close();
			WriteHMACFolderContent(path, secretKey);
		}
		else
		{
			countLines();
			readStatusFile();
			SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH-mm-ss");
			Date date = new Date();
			reportFile = new File(formatter.format(date) + ".txt");
			PrintWriter printWriter = new PrintWriter(reportFile);
			printWriter.write(""); //empty out the file
			printWriter.close();
			checkHMAC(path, secretKey);
		}
		
		reader.close();
	}

}
