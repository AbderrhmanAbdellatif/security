/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bg;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author someo
 */
public class soru1 {

    public static void main(String[] args) throws Exception {
        long l = System.nanoTime();

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

        // System.out.println(Arrays.toString(secretKey.getEncoded()));
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());// public key to pirvte key 

        byte[] encodedbyte = cipher.doFinal(encryptedByte);// 
        //  System.out.println(Arrays.toString(encodedbyte));

        //3)Consider a long text m. Apply SHA256 Hash algorithm (Obtain the message digest, H(m)). 
        //Then encrypt it with KA-. (Thus generate a digital signature.) Then verify the digital signature. 
        //(Decrypt it with KA+ ,apply Hash algorithm to the message, compare). Print m, H(m) and digital signature on the screen. 
        //Provide a screenshot. (Or you may print in a file and provide the file).
        // Static getInstance method is called with hashing SHA
        // m
        String inputtxt = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                + "Sed sit amet dui in eros consequat ullamcorper. Nullam a felis in sapien porta porttitor sit amet at tortor."
                + " Pellentesque convallis lectus quis ante lacinia mattis. Pellentesque ut sapien eu dui vulputate euismod."
                + " Suspendisse finibus feugiat fermentum. Sed pretium bibendum vulputate. Nullam consequat nisl in felis finibus,"
                + " non consequat quam interdum. Nullam dictum viverra diam, tincidunt semper elit ultricies in. Donec cursus vitae "
                + "purus ac maximus. Sed porta faucibus rutrum. Phasellus bibendum posuere leo nec placerat. Maecenas porttitor aliquet ipsum,"
                + " ac facilisis felis placerat sed. Nullam et lobortis mi, quis eleifend enim.";
        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte digestarray[] = md.digest(inputtxt.getBytes());//Apply SHA256 Hash algorithm 
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());
        byte[] encodedDigestPrivate = cipher.doFinal(digestarray);//Then encrypt it with KA-.
        //System.out.println(Arrays.toString(encodedDigestPrivate));

        cipher.init(Cipher.DECRYPT_MODE, keys.getPublic());
        byte[] decodedDigestPublic = cipher.doFinal(encodedDigestPrivate);//Decrypt it with KA+
        // System.out.println(inputtxt);// Print m
        // System.out.println(Arrays.toString(decodedDigestPublic));
        // System.out.println(Arrays.toString(encodedDigestPrivate)); //digital signature
        //  System.out.println(Arrays.toString(digestarray)); //H(m)

        ///Generate or find any file of size 1MB. Now consider following three algorithms:
        //i) AES (128 bit key) in CBC mode.
        //ii) AES (256 bit key) in CBC mode.
        //iii) DES in CBC mode (you need to generate a 56 bit key for this).  
        //  a) Encrypt the file of size 1MB. Store the result (and submit it with the homework) 
        //(Note: IV should be randomly generated, Key = K1 or K2).
        //b) Decrypt the file and store the result. Show that it is the same as the original file.
        //c) Measure the time elapsed for encryption. Write it in your report. Comment on the result.
        //d) For the first algorithm, change Initialization Vector (IV) and show that the corresponding 
        //ciphertext chages for the same plaintext (Give the result for both).
        String MB = "";
        File myObj = new File("temp.txt");
        Scanner myReader = new Scanner(myObj);
        while (myReader.hasNextLine()) {
            String data = myReader.nextLine();
            // System.out.println(data);
            MB += data;
        }
        myReader.close();

        // IV  randomly generated java
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        //   System.out.println(Arrays.toString(ivParams.getIV()));

        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);// 128 bit key 

        byte[] encrypted_file_txt = cipher.doFinal(MB.getBytes());
        // System.out.println(Arrays.toString(encrypted_file_txt));

        double elapsedTimeInSecond = (double) (System.nanoTime() - l) / 1_000_000_000;
        // System.out.println(elapsedTimeInSecond);

        File encrypted128File = new File("encrypted128.txt");
        if (encrypted128File.createNewFile()) {
            System.out.println("File created: " + encrypted128File.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter = new FileWriter("encrypted128.txt");
        FileOutputStream fos = new FileOutputStream(encrypted128File);
        // Writes bytes from the specified byte array to this file output stream 
        fos.write(encrypted_file_txt);
        myWriter.close();

        //Java read file to byte[] array
        Path path = Paths.get("encrypted128.txt");
        byte[] encryptedtxt128 = Files.readAllBytes(path);
        // System.out.println(Arrays.toString(dataec));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams); // DECRYPT_MODE , 128bit , iv
        byte[] DECRYPT_128file_txt = cipher.doFinal(encryptedtxt128);// DECRYPT_MODE
        //System.out.println(Arrays.toString(MB.getBytes()));
        //System.out.println(Arrays.toString(DECRYPT_128file_txt));

        File decrypted128File = new File("decrypted128.txt");
        if (decrypted128File.createNewFile()) {
            System.out.println("File created: " + decrypted128File.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter2 = new FileWriter("decrypted128.txt");
        FileOutputStream fos2 = new FileOutputStream(decrypted128File);
        // Writes bytes from the specified byte array to this file output stream 
        fos2.write(DECRYPT_128file_txt);
        myWriter2.close();

        ///////////////////////////////                            256 key                     //////////////////////////////////////
        byte[] iv2 = new byte[16];
        randomSecureRandom.nextBytes(iv2);
        IvParameterSpec ivParams256 = new IvParameterSpec(iv2);
        //   System.out.println(Arrays.toString(ivParams.getIV()));
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        SecretKeySpec keySpec = new SecretKeySpec(secretKey2.getEncoded(), "AES");
        
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams256);// 256 bit key 
        
        l = System.nanoTime();
        byte[] encrypted_256_file_txt = cipher.doFinal(MB.getBytes());
        // System.out.println(Arrays.toString(encrypted_file_txt));

        elapsedTimeInSecond = (double) (System.nanoTime() - l) / 1_000_000_000;
        System.out.println("256 bit : " + elapsedTimeInSecond);

        File encrypted256File = new File("encrypted256.txt");
        if (encrypted256File.createNewFile()) {
            System.out.println("File created: " + encrypted256File.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter256 = new FileWriter("encrypted256.txt");
        FileOutputStream fos256 = new FileOutputStream(encrypted256File);
        // Writes bytes from the specified byte array to this file output stream 
        fos256.write(encrypted_256_file_txt);
        myWriter256.close();

        //Java read file to byte[] array
        Path path256 = Paths.get("encrypted256.txt");
        byte[] encryptedtxt256 = Files.readAllBytes(path256);
        // System.out.println(Arrays.toString(dataec));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParams256); // DECRYPT_MODE , 128bit , iv
        byte[] DECRYPT_256file_txt = cipher.doFinal(encryptedtxt256);// DECRYPT_MODE
        //System.out.println(Arrays.toString(MB.getBytes()));
        //System.out.println(Arrays.toString(DECRYPT_256file_txt));

        File decrypted256File = new File("decrypted256.txt");
        if (decrypted256File.createNewFile()) {
            System.out.println("File created: " + decrypted256File.getName());
        } else {
            System.out.println("File already exists.");
        }

        FileWriter myWriter3 = new FileWriter("decrypted256.txt");
        FileOutputStream fos3 = new FileOutputStream(decrypted256File);
        // Writes bytes from the specified byte array to this file output stream
        fos3.write(DECRYPT_256file_txt);
        myWriter3.close();
        /////////////////////////////////////////////////////     DES in CBC mode (you need to generate a 56 bit key for this). ///////////////////////

        //https://stackoverflow.com/questions/4985591/create-des-key-from-56-bit-binary-string
//        KeyGenerator kgdes = KeyGenerator.getInstance("DES");
//        kgdes.init(56);
//        SecretKey secretKey3 = kgdes.generateKey();
//        String key56 = "";
//        for (int i = 0; i < secretKey3.getEncoded().length; i++) {
//            key56 += String.format("%8s", Integer.toBinaryString(secretKey3.getEncoded()[i] & 0xFF)).replace(' ', '0');
//        }
//        System.out.println(key56);
//        
//        //The key ostensibly consists of 64 bits; however, only 56 of these are actually used by the algorithm. 
//        // Eight bits are used solely for checking parity, and are thereafter discarded. Hence the effective key length is 56 bits,
//        // and it is never quoted as such. Every 8th bit of the selected key is discarded, i.e. positions 8, 16, 24, 32, 40, 48, 56, 64 are removed
//        //from the 64 bit key leaving behind only the 56 bit key.
//       
//        byte[] iv3 = new byte[8];
//
//        randomSecureRandom.nextBytes(iv3);
//        IvParameterSpec ivParams3 = new IvParameterSpec(iv3);
//        cipher = Cipher.getInstance("DES/CBC/NoPadding");
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey3, ivParams3);// 56 bit key 
//        l = System.nanoTime();
//
//        byte[] encrypted_des_file_txt = cipher.doFinal(MB.getBytes());
//        elapsedTimeInSecond = (double) (System.nanoTime() - l) / 1_000_000_000;
//        // System.out.println(elapsedTimeInSecond);
//
//        File encrypted56File = new File("encrypted56.txt");
//        if (encrypted56File.createNewFile()) {
//            System.out.println("File created: " + encrypted56File.getName());
//        } else {
//            System.out.println("File already exists.");
//        }
//
//        FileWriter myWriter3 = new FileWriter("encrypted56.txt");
//        FileOutputStream fos3 = new FileOutputStream(encrypted56File);
//        // Writes bytes from the specified byte array to this file output stream 
//        fos3.write(encrypted_des_file_txt);
//        myWriter3.close();
//
//        //Java read file to byte[] array
//        Path path2 = Paths.get("encrypted56.txt");
//        byte[] encryptedtxt56 = Files.readAllBytes(path2);
//        // System.out.println(Arrays.toString(dataec));
//
//        cipher.init(Cipher.DECRYPT_MODE, secretKey3, ivParams3); // DECRYPT_MODE , 56bit , iv
//        byte[] DECRYPT_des_file_txt = cipher.doFinal(encryptedtxt56);// DECRYPT_MODE
//        //System.out.println(Arrays.toString(MB.getBytes()));
//        //System.out.println(Arrays.toString(DECRYPT_128file_txt));
//
//        File decrypted56File = new File("decrypted56.txt");
//        if (decrypted56File.createNewFile()) {
//            System.out.println("File created: " + decrypted56File.getName());
//        } else {
//            System.out.println("File already exists.");
//        }
//
//        FileWriter myWriter4 = new FileWriter("decrypted56.txt");
//        FileOutputStream fos4 = new FileOutputStream(decrypted56File);
//        // Writes bytes from the specified byte array to this file output stream 
//        fos4.write(DECRYPT_des_file_txt);
//        myWriter4.close();
    }
}
