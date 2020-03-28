/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bg;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 *
 * @author someo
 */
public class soru1 {

    public static void main(String[] args) throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        //System.out.println(keys.getPublic());
        //System.out.println(" ");
        // System.out.println(keys.getPrivate());
        //2)Generate two symmetric keys: 128 bit K1 and 256 bit K2. Print values of the keys on the screen. 
        //Encypt them with KA+, print the results, and then decrypt them with KA-. Again print the results. 
        //Provide a screenshot showing your results.
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        String key128 = "", key256 = "";
        for (int i = 0; i < secretKey.getEncoded().length; i++) {
            key128 += String.format("%8s", Integer.toBinaryString(secretKey.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }
        kg.init(256);
        SecretKey secretKey2 = kg.generateKey();

        for (int i = 0; i < secretKey2.getEncoded().length; i++) {
            key256 += String.format("%8s", Integer.toBinaryString(secretKey2.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }
        // System.out.println(key128);
        // System.out.println(key256);
        
        //m=k- ( k+ (m))
        byte[] encryptedByte = cipher.doFinal(secretKey.getEncoded()); // encruypt with public key 
        
        System.out.println(Arrays.toString(secretKey.getEncoded())); 
        
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());// public key to pirvte key 

        byte[] encodedbyte =  cipher.doFinal(encryptedByte);// 
        System.out.println(Arrays.toString(encodedbyte));
     
        
    }
}
