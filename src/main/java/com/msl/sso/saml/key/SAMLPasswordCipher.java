package com.msl.sso.saml.key;

import java.io.UnsupportedEncodingException;

import com.msl.security.cipher.CipherException;
import com.msl.security.cipher.DESCipher;

public class SAMLPasswordCipher {
    
    public String decrypt (String passwordValue) throws SAMLPasswordCipherException{

        String decryptedPass=null;
        byte[] decryptedPassBytes;
        try{
        	decryptedPassBytes = DESCipher.decrypt(passwordValue).getBytes();
        	decryptedPass =new String(decryptedPassBytes, "UTF-8");
        }catch(CipherException e){
        	throw new SAMLPasswordCipherException("Error decrypting:" + e.getMessage());
        }catch(UnsupportedEncodingException e1){
        	throw new SAMLPasswordCipherException("Encoding not supported:" + e1.getMessage());
        }
        return decryptedPass;
    }
    
    public String encrypt (String passwordValue) throws SAMLPasswordCipherException {

        String encryptedKeyValue=null;
        try {
			encryptedKeyValue = DESCipher.encrypt(passwordValue);
		} catch (CipherException e) {
			throw new SAMLPasswordCipherException("Error encrypting:" + e.getMessage());
		}     
        return encryptedKeyValue;
    }
}
