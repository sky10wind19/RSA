package RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.*;

public class R01 {
	
    final static private String File_name = "test.txt";
	final static private int Key_size = 3072;
	public static final int Cipher_block_size = (Key_size)/512 * 50;
	public static final int DE_Cipher_block_size = (Key_size)/512 * 64;
	final static private String Public_key_file_name = "public" + Key_size + ".key";
	final static private String Private_key_file_name = "private" + Key_size + ".key";
	public static final String Algorithm = "RSA";
	final static private int AES_Key_size = 256;
	final private BlockCipher AESCipher = new AESEngine();
	private PaddedBufferedBlockCipher pbbc;
	private static KeyParameter key;
	
	private byte[] AES(byte[] input, boolean encrypt) throws Exception {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		pbbc.init(encrypt, key);
		byte[] output = new byte[pbbc.getOutputSize(input.length)];
		int bytesWrittenOut = pbbc.processBytes(input,  0,  input.length,  output, 0);
		pbbc.doFinal(output,  bytesWrittenOut);
		logHandler(1, fun_name, "Operation finished");
		return output;
	}
	
	public void setPadding(BlockCipherPadding bcp) {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		logHandler(1, fun_name, "Creating padding");
		this.pbbc = new PaddedBufferedBlockCipher(AESCipher, bcp);
		logHandler(1, fun_name, "Padding created");
	}

	public void setKey(byte[] key) {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		logHandler(1, fun_name, "Creating key");
		this.key = new KeyParameter(key);
		logHandler(1, fun_name, "Key created");
	}
	public byte[] encrypt(byte[] input) throws Exception {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		logHandler(1, fun_name, "Encrypt.");
		return AES(input, true);
	}
	
	public byte[] decrypt(byte[] input) throws Exception {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		logHandler(1, fun_name, "Decrypt.");
		return AES(input, false);
	}
	
	public static long getCurrentTime(){
		Date today;
		today = new Date(0);
		return today.getTime();
	}
	
	public static void generate_key() {
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		try{
			final KeyPairGenerator Keygen = KeyPairGenerator.getInstance(Algorithm);
			Keygen.initialize(Key_size);
			final KeyPair keypair = Keygen.generateKeyPair();
			logHandler(1, fun_name, "KeyPair Generated");
			
			byte[] publickey = keypair.getPublic().getEncoded();
			logHandler(1, fun_name, "Public key Generated");
			
			byte[] privatekey = keypair.getPrivate().getEncoded();
			logHandler(1, fun_name, "Private key Generated");
			
			
			writeFile(publickey, Public_key_file_name);
			writeFile(privatekey, Private_key_file_name);
			}catch(Exception e){
				logHandler(4, fun_name, "Failed in key pair Generation");
				e.printStackTrace();
			}
	}
	
	public static boolean AreKeyPresent(){
		File privatekey = new File(Private_key_file_name);
		File publickey = new File(Public_key_file_name);
		
		if(privatekey.exists() && publickey.exists()){
			return true;
		}
		else{
			return false;
		}
	}
	
	public static void encrypt(PublicKey key) throws Exception{
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		final Cipher cipher = Cipher.getInstance(Algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		logHandler(1, fun_name, "Encryption started");
		try(FileInputStream fis = new FileInputStream(File_name)){
			try(FileOutputStream fos = new FileOutputStream(File_name + ".rsa")){
				int read;
				byte buffer[] = new byte[DE_Cipher_block_size];
				while((read = fis.read(buffer)) != -1){
					byte[] bufferCipher = cipher.doFinal(buffer);
					fos.write(bufferCipher);
				}
			}
		}
		logHandler(1, fun_name, "Decryption finished");
	}
	
	public static void decrypt(PrivateKey privatekey) throws Exception{
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		final Cipher cipher = Cipher.getInstance(Algorithm);
		cipher.init(Cipher.DECRYPT_MODE, privatekey);
		logHandler(1, fun_name, "Decryption started");
		try(FileInputStream fis = new FileInputStream(File_name + ".rsa")){
			try(FileOutputStream fos = new FileOutputStream(File_name)){
				int read;
				byte buffer[] = new byte[Cipher_block_size];
				while((read = fis.read(buffer)) != -1){
					byte[] bufferCipher = cipher.doFinal(buffer);
					fos.write(bufferCipher);
				}
			}
		}
		logHandler(1, fun_name, "Encryption finished");
	}
	
	public static byte[] readFile (File file) throws IOException{
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		
		byte[] data;
		if(file.length() > Integer.MAX_VALUE){
			logHandler(4, fun_name, "File size is too large.");
		}
		logHandler(1, fun_name, "Reading file" +  file.getName());
		data = new byte [(int) file.length()];
		FileInputStream fis = new FileInputStream(file);
		fis.read(data);
		fis.close();
		logHandler(1, fun_name, "File reading complete");
		
		return data;
	}
	
	private static void writeFile(byte[] data, String filename) throws IOException{
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		logHandler(1, fun_name, "Writing file" + filename);
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(data);
		fos.close();
		logHandler(1, fun_name, "File write complete");
	}
	
	private static void logHandler(int level, String fun_name, String message) {
		String curfun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		switch(level){
		case 1:
			System.out.print("Informative:\t");
			break;
		case 2:
			System.out.print("Warning:\t\t");
			break;
		case 3:
			System.out.print("Error:\t\t");
			break;
		case 4:
			System.out.print("Critical:\t\t");
			System.exit(1);
			break;
		default:
			logHandler(4, curfun_name, "Unspecified log level!");
		}
		if(fun_name.length() < 7){
			System.out.print(fun_name + ":\t\t");
		}
		else{
			System.out.print(fun_name + ":\t");
		}
		System.out.print(message + "\n");
	}
	
	public static void main(String[] args){
		String fun_name = Thread.currentThread().getStackTrace()[1].getMethodName();
		try{
			if(!AreKeyPresent()){
				generate_key();
			}
			byte[] encrypt;
			byte[] decrypt;
			byte[] original;
			File file= new File(File_name);
			original = readFile(file);
			
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(AES_Key_size);
			R01 AES = new R01();
			AES.setPadding(new PKCS7Padding());
			AES.setKey(key.getEncoded());
			SecretKey secretKey = keyGen.generateKey();
			File public_key_file = new File (Public_key_file_name);
			File private_key_file = new File (Private_key_file_name);
			final PublicKey publickey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(readFile(public_key_file)));
			final PrivateKey privatekey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(readFile(private_key_file)));
			long msbefore = 0;
			long msafter = 0;
			
			msbefore = getCurrentTime();
			encrypt(publickey);
			msafter = getCurrentTime();
			logHandler(1, fun_name, "It takes " + (msafter -msbefore) + "ms to encrypt");
			
			msbefore = getCurrentTime();
			decrypt(privatekey);
			msafter = getCurrentTime();
			logHandler(1, fun_name, "It takes " + (msafter -msbefore) + "ms to decrypt");
		}catch (Exception e){
			e.printStackTrace();
			logHandler(4, fun_name, "Critical error!");
		}
	}

}
