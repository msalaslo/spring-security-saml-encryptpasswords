package com.msl.security.cipher;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESCipher {
	
	private static String secretKey = "thesecretkey";
	private static final String ENCODING = "utf-8";
	private static final String CIPHER = "DESede";
	private static final String DIGEST = "MD5";

	public static String encrypt(String text) throws CipherException{

		String base64EncryptedString = "";

		try {

			MessageDigest md = MessageDigest.getInstance(DIGEST);
			byte[] digestOfPassword = md.digest(secretKey.getBytes(ENCODING));
			byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

			SecretKey key = new SecretKeySpec(keyBytes, CIPHER);
			Cipher cipher = Cipher.getInstance(CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] plainTextBytes = text.getBytes(ENCODING);
			byte[] buf = cipher.doFinal(plainTextBytes);
			byte[] base64Bytes = Base64.getEncoder().encode(buf);
			base64EncryptedString = new String(base64Bytes);

		} catch (Exception e) {
			throw new CipherException("Error encrypting text:" + text + ", cause:" + e.getMessage());
		}
		return base64EncryptedString;
	}
	
	public static String decrypt(String encryptedText) throws CipherException {

        String base64EncryptedString = "";
 
        try {
            byte[] message = Base64.getDecoder().decode(encryptedText.getBytes(ENCODING));
            MessageDigest md = MessageDigest.getInstance(DIGEST);
            byte[] digestOfPassword = md.digest(secretKey.getBytes(ENCODING));
            byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            SecretKey key = new SecretKeySpec(keyBytes, CIPHER);
 
            Cipher decipher = Cipher.getInstance(CIPHER);
            decipher.init(Cipher.DECRYPT_MODE, key);
 
            byte[] plainText = decipher.doFinal(message);
 
            base64EncryptedString = new String(plainText, ENCODING);
 
        } catch (Exception e) {
        	throw new CipherException("Error decrypting text:" + encryptedText + ", cause:" + e.getMessage());
        }
        return base64EncryptedString;
	}
	
	public static void main(String[] args){
		try{			
			if(args == null || args.length < 1){				
				System.out.println("Please pass a text to encrypt as a parameter of this program.");				
			}else{
				String param = args[0];
				String res = encrypt(param);
				System.out.println("Encrypted value:" + res + " for parameter:" + param);
			}
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
