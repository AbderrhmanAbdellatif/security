/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bg;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Mehmet Fatih GEZEN
 */
public class Homework {

    private static SecretKey GetKey(String algorithm, int size) throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm);
        kg.init(size);
        SecretKey secretKey = kg.generateKey();
        return secretKey;
    }

    private static String ByteToBinary(byte[] data) {
        String encryptedByteString = "";
        for (int i = 0; i < data.length; i++) {
            encryptedByteString += String.format("%8s", Integer.toBinaryString(data[i] & 0xFF)).replace(' ', '0');
        }
        return encryptedByteString;
    }

    private static String ReadFile(String fileName) throws Exception {
        String fileString = "";
        File file = new File(fileName);
        Scanner scanner = new Scanner(file);
        while (scanner.hasNextLine()) {
            String data = scanner.nextLine();
            fileString += data;
        }
        scanner.close();
        return fileString;
    }

    private static IvParameterSpec GenerateIV(int size) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        return ivParams;
    }

    public static void WriteFile(String FileName, byte[] data) throws IOException {
        File file = new File(FileName);

        FileWriter fileWriter = new FileWriter(FileName);
        FileOutputStream fos = new FileOutputStream(file);

        fos.write(data);
        fileWriter.close();
    }

    public static void main(String[] args) throws Exception {
        long time = System.nanoTime();

        KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        String key128 = "", key256 = "";
        SecretKey secretKey128 = GetKey("AES", 128);

        SecretKey secretKey256 = GetKey("AES", 256);

        for (int i = 0; i < secretKey128.getEncoded().length; i++) {
            key128 += String.format("%8s", Integer.toBinaryString(secretKey128.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }

        for (int i = 0; i < secretKey256.getEncoded().length; i++) {
            key256 += String.format("%8s", Integer.toBinaryString(secretKey256.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }

        System.out.println("128 bit Key: " + key128);
        System.out.println("256 bit Key: " + key256);

        byte[] encryptedByte = cipher.doFinal(secretKey128.getEncoded());

        System.out.println("128 bit Key encrypted: " + ByteToBinary(encryptedByte));

        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

        byte[] decryptedByte = cipher.doFinal(encryptedByte);// 
        System.out.println("128 bit Key decrypted: " + ByteToBinary(decryptedByte));
        System.out.println(" ");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        byte[] encryptedByte256 = cipher.doFinal(secretKey256.getEncoded());

        System.out.println("256 bit Key encrypted: " + ByteToBinary(encryptedByte256));

        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

        byte[] decryptedByte256 = cipher.doFinal(encryptedByte256);
        System.out.println("256 bit Key decrypted: " + ByteToBinary(decryptedByte256));

        String text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                + "Sed sit amet dui in eros consequat ullamcorper. Nullam a felis in sapien porta porttitor sit amet at tortor."
                + " Pellentesque convallis lectus quis ante lacinia mattis. Pellentesque ut sapien eu dui vulputate euismod."
                + " Suspendisse finibus feugiat fermentum. Sed pretium bibendum vulputate. Nullam consequat nisl in felis finibus,"
                + " non consequat quam interdum. Nullam dictum viverra diam, tincidunt semper elit ultricies in. Donec cursus vitae "
                + "purus ac maximus. Sed porta faucibus rutrum. Phasellus bibendum posuere leo nec placerat. Maecenas porttitor aliquet ipsum,"
                + " ac facilisis felis placerat sed. Nullam et lobortis mi, quis eleifend enim.";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digestArray = digest.digest(text.getBytes());

        cipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());
        byte[] digitalSignature = cipher.doFinal(digestArray);
        System.out.println(" ");
        System.out.println("m: " + text);
        System.out.println("digest: " + ByteToBinary(digestArray));
        System.out.println("digital signature: " + ByteToBinary(digitalSignature));
        cipher.init(Cipher.DECRYPT_MODE, keys.getPublic());
        byte[] decodedDigest = cipher.doFinal(digitalSignature);

        String file = ReadFile("demo.txt");

        IvParameterSpec ivParams = GenerateIV(16);

        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey128, ivParams);
        System.out.println(" ");
        time = System.nanoTime();
        byte[] encryptedFile = cipher.doFinal(file.getBytes());

        double elapsedTimeInSecond = (double) (System.nanoTime() - time) / 1_000_000_000;
        System.out.println("128 bit key time: " + elapsedTimeInSecond);

        WriteFile("fileencrypted128bit.txt", encryptedFile);

        Path path = Paths.get("fileencrypted128bit.txt");
        byte[] encryptedText128Bit = Files.readAllBytes(path);

        cipher.init(Cipher.DECRYPT_MODE, secretKey128, ivParams);
        byte[] decrypted128BitFile = cipher.doFinal(encryptedText128Bit);

        WriteFile("filedecrypted128bit.txt", decrypted128BitFile);
        IvParameterSpec ivParams2 = GenerateIV(16);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey128, ivParams2);
        byte[] encryptedText128Bit2 = cipher.doFinal(file.getBytes());
        //  System.out.println("Encrypted with First Initialization Vector: " + ByteToBinary(encryptedText128Bit));
        //  System.out.println("Encrypted with Second Initialization Vector: " + ByteToBinary(encryptedText128Bit2));

        IvParameterSpec ivParams256 = GenerateIV(16);
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        SecretKeySpec keySpec = new SecretKeySpec(secretKey256.getEncoded(), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams256);

        time = System.nanoTime();
        byte[] encrypted256BitFile = cipher.doFinal(file.getBytes());

        elapsedTimeInSecond = (double) (System.nanoTime() - time) / 1_000_000_000;

        System.out.println("256 bit key time: " + elapsedTimeInSecond);
        WriteFile("fileencrypted256bit.txt", encrypted256BitFile);

        Path path256 = Paths.get("fileencrypted256bit.txt");
        byte[] encryptedText256Bit = Files.readAllBytes(path256);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParams256);
        byte[] decrypted256BitFile = cipher.doFinal(encryptedText256Bit);

        WriteFile("filedecrypted256bit.txt", decrypted256BitFile);

        SecretKey secretKey3 = GetKey("DES", 56);
        String key56 = "";

        for (int i = 0; i < secretKey3.getEncoded().length; i++) {
            key56 += String.format("%8s", Integer.toBinaryString(secretKey3.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }
        IvParameterSpec ivParams3 = GenerateIV(8);

        cipher = Cipher.getInstance("DES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey3, ivParams3);
        time = System.nanoTime();

        byte[] encryptedDesFile = cipher.doFinal(file.getBytes());
        elapsedTimeInSecond = (double) (System.nanoTime() - time) / 1_000_000_000;
        System.out.println("56 bit key time: " + elapsedTimeInSecond);

        WriteFile("fileencrypted56bit.txt", encryptedDesFile);

        Path path2 = Paths.get("fileencrypted56bit.txt");
        byte[] encryptedText56Bit = Files.readAllBytes(path2);

        cipher.init(Cipher.DECRYPT_MODE, secretKey3, ivParams3);
        byte[] decryptedDesFile = cipher.doFinal(encryptedText56Bit);

        WriteFile("filedecrypted56bit.txt", decryptedDesFile);
    }

}
