/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author 572G
 */
public class Security {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, InvalidAlgorithmParameterException, IOException {
        //1-
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");//In this part, generating 512(default) bit public and private keys
        KeyPair keys = kpg.generateKeyPair();
        
        
//-------------------------------------------------
        //2-
        String k128 = "";
        KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
        
        keyGen1.init(128);
        SecretKey secretKey1 = keyGen1.generateKey();//Generating 128 bit AES key
        
        System.out.println("RSA");
        System.out.println("128 bit K1 = "+secretKey1.getEncoded());

        
        KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
        keyGen2.init(256);
        SecretKey secretKey2 = keyGen2.generateKey();//Generating 256 bit AES key

        System.out.println("256 bit K2 = "+secretKey2.getEncoded());
        System.out.println("----------");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        
        
        byte[] en_aes_128 = cipher.doFinal(secretKey1.getEncoded());//Encrypting AES 128 with KA+

        System.out.println("128 bit Encrypted KA+ = "+Arrays.toString(secretKey1.getEncoded()));
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

        byte[] dec_aes_128 = cipher.doFinal(en_aes_128);//Decrypting with KA-
        System.out.println("128 bit Decrypted KA- = "+Arrays.toString(dec_aes_128));
        
        
        
        
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.ENCRYPT_MODE, keys.getPublic());
        byte[] en_aes_256 = cipher2.doFinal(secretKey2.getEncoded()); //Encrypting AES 256 with KA+

        System.out.println("256 bit Encrypted KA+  = "+Arrays.toString(secretKey2.getEncoded()));
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

        byte[] encodedbyte2 = cipher.doFinal(en_aes_256);//Decrypting with KA-
        System.out.println("256 bit Decrypted KA- = "+Arrays.toString(encodedbyte2));

       
        //---SORU 3---
        System.out.println("----------");
        
        
        String m = "Lorem ipsum sunt in culpa qui officia deserunt mollit anim id est laborum, excepteur sint occaecat cupidatat non proident, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte digestarray[] = md.digest(m.getBytes());//Applying hash algorithm (H(m))
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());
        byte[] encodedDigestPrivate = cipher.doFinal(digestarray);//Encripting with KA-  -> Generating digital signature

        cipher.init(Cipher.DECRYPT_MODE, keys.getPublic());
        byte[] decodedDigestPublic = cipher.doFinal(encodedDigestPrivate); //Decrypting with KA+
        System.out.println("m = "+m);
        System.out.println("H(m) = "+Arrays.toString(digestarray));
        System.out.println("Digital signature = "+Arrays.toString(encodedDigestPrivate));
        System.out.println("-----------------------------------");
        //System.out.println(Arrays.toString(decodedDigestPublic));//verifying  
        
        
        //---SORU 4---
        System.out.println("-------------");
        //---AES 256---
        
        
        
        File myObj = new File("C:\\Users\\572G\\Desktop\\1mb.txt");
        String text = "";
 
        Scanner myReader = new Scanner(myObj);
        while (myReader.hasNextLine()) {
            String data = myReader.nextLine();
          text += data;//Reading 1mb file and transferring words to text variable
        }
        myReader.close();

        SecureRandom randomSecureRandom2 = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv2 = new byte[16];
        byte[] iv3 = new byte[16];
        randomSecureRandom2.nextBytes(iv2);//Generating random Initialization Vector
        randomSecureRandom2.nextBytes(iv3);//4.d için
        
        long start256 = System.currentTimeMillis(); //Holding time to measure time elapsed
        
        IvParameterSpec ivParams1 = new IvParameterSpec(iv2);
        IvParameterSpec ivParams11 = new IvParameterSpec(iv3);//4.d için
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey2.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams1);
        
        byte[] en_txt = cipher.doFinal(text.getBytes()); //Text file encrypting with AES 256
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams11);
        byte[] en_txt_iv2 = cipher.doFinal(text.getBytes());//4.d için
        
        File myObj3 = new File("C:\\Users\\572G\\Desktop\\en_aes_256.txt");
        if (myObj3.createNewFile()) {
            System.out.println("File created: " + myObj3.getName());
        } else {
            System.out.println("File already exists.");
        }
        
        
        File myObj33 = new File("C:\\Users\\572G\\Desktop\\en_aes_256_iv2.txt");
        if (myObj33.createNewFile()) {
            System.out.println("File created: " + myObj33.getName());
        } else {
            System.out.println("File already exists.");
        }
        
        FileOutputStream fos256 = new FileOutputStream(myObj3);
        fos256.write(en_txt);//Writing encrypted text
        
        FileOutputStream fos256_iv2 = new FileOutputStream(myObj33);
        fos256_iv2.write(en_txt_iv2);//4.d sonuç

        Path path1 = Paths.get("C:\\Users\\572G\\Desktop\\en_aes_256.txt");
        byte[] en_txt_256 = Files.readAllBytes(path1);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParams1);
        byte[] dec_txt2 = cipher.doFinal(en_txt_256);//Decrypting encrpted text


        File myObj4 = new File("C:\\Users\\572G\\Desktop\\dec_aes_256.txt");
        if (myObj4.createNewFile()) {
            System.out.println("File created: " + myObj4.getName());
        } else {
            System.out.println("File already exists.");
        }

        
        FileOutputStream fos5 = new FileOutputStream(myObj4);
        
        fos5.write(dec_txt2);//Writing decrypted text
        
        
        
        long finish256 = System.currentTimeMillis();
        long timeElapsed = finish256 - start256;//Elapsed time for AES 256 
        System.out.println("AES-256 Time ="+ timeElapsed + " ms");
        
        
        System.out.println("-------------");
        
        
        //---AES 128---
        
        
        
        
        long start128 = System.currentTimeMillis();
        
       

        
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[16];
        randomSecureRandom.nextBytes(iv);//Generating random Initialization Vector

        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey1, ivParams);

        byte[] encrypted_file_txt = cipher.doFinal(text.getBytes());//Text file encrypting with AES 128

  
             File myObj1 = new File("C:\\Users\\572G\\Desktop\\en_aes_128.txt");
             if (myObj1.createNewFile()) {
               System.out.println("File created: " + myObj1.getName());
             } else {
               System.out.println("File already exists.");
             }

        
        FileOutputStream fos = new FileOutputStream(myObj1);

        fos.write(encrypted_file_txt);//Writing encrypted text

        Path path = Paths.get("C:\\Users\\572G\\Desktop\\en_aes_128.txt");
        byte[] en_txt_128 = Files.readAllBytes(path);


        
        cipher.init(Cipher.DECRYPT_MODE, secretKey1, ivParams); 
        byte[] dec_txt  = cipher.doFinal(en_txt_128);//Decrypting encrpted text


        File myObj2 = new File("C:\\Users\\572G\\Desktop\\dec_aes_128.txt");
        if (myObj2.createNewFile()) {
            System.out.println("File created: " + myObj2.getName());
        } else {
            System.out.println("File already exists.");
        }
        FileWriter myWriter2 = new FileWriter("dec_aes_128.txt");
        FileOutputStream fos2 = new FileOutputStream(myObj2);
 
        fos2.write(dec_txt);//Writing decrypted text
        myWriter2.close();
        
        
        long finish128 = System.currentTimeMillis();
         timeElapsed = finish128 - start128;
        System.out.println("AES-128 Time = "+ timeElapsed + " ms");
        
        
        System.out.println("-------------");

        
        //---DES 56---
        
        
      
        
        KeyGenerator kg1 = KeyGenerator.getInstance("DES");
        kg1.init(56);
        SecretKey secretKey3 = kg1.generateKey();
         long start56 = System.currentTimeMillis();
        byte[] iv4 = new byte[8];

        randomSecureRandom.nextBytes(iv4);//Generating random Initialization Vector
        IvParameterSpec ivParams2 = new IvParameterSpec(iv4);
        cipher = Cipher.getInstance("DES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey3, ivParams2);

        byte[] en_txt_dec = cipher.doFinal(text.getBytes()); //Text file encrypting with DES 56



        File encrypted56File = new File("C:\\Users\\572G\\Desktop\\en_des_56.txt");
        if (encrypted56File.createNewFile()) {
            System.out.println("File created: " + encrypted56File.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter3 = new FileWriter("C:\\Users\\572G\\Desktop\\en_des_56.txt");
        FileOutputStream fos3 = new FileOutputStream(encrypted56File);
        
        fos3.write(en_txt_dec);
        myWriter3.close();

        
        Path path2 = Paths.get("C:\\Users\\572G\\Desktop\\en_des_56.txt");
        byte[] en_txt_56 = Files.readAllBytes(path2);
        

        cipher.init(Cipher.DECRYPT_MODE, secretKey3, ivParams2);
        byte[] dec_des = cipher.doFinal(en_txt_56);
        
        

        File myObj5 = new File("C:\\Users\\572G\\Desktop\\dec_des_56.txt");
        if (myObj5.createNewFile()) {
            System.out.println("File created: " + myObj5.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter4 = new FileWriter("C:\\Users\\572G\\Desktop\\dec_des_56.txt");
        FileOutputStream fos4 = new FileOutputStream(myObj5);
        
        fos4.write(dec_des);
        myWriter4.close();
        
        
        long finish56 = System.currentTimeMillis();
        timeElapsed = finish56 - start56;
        System.out.println("DES-56 Time = "+ timeElapsed + " ms");
        
        
        
        
        
        
        
        
        
        


    }
}
