/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bg;

import java.io.BufferedReader;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
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
public class HWorkCS {

    static String toBinaryString(byte[] data) {
        String bString = "";
        for (int i = 0; i < data.length; i++) {
            bString += String.format("%8s", Integer.toBinaryString(data[i] & 0xFF)).replace(' ', '0'); //toBinaryString
        }
        return bString;
    }

    static String ToBinary(SecretKey secretKey) {
        String keyString = "";
        for (int i = 0; i < secretKey.getEncoded().length; i++) {
            keyString += String.format("%8s", Integer.toBinaryString(secretKey.getEncoded()[i] & 0xFF)).replace(' ', '0');
        }
        return keyString;
    }

    static byte[] HASH(String name, String inputtxt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(name);
        byte digestarray[] = md.digest(inputtxt.getBytes());//Apply SHA256 Hash algorithm 
        return digestarray;
    }

    static IvParameterSpec InitializeVector(int size) {
        // IV  randomly generated java
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[size];// size 
        randomSecureRandom.nextBytes(iv);// byteler
        IvParameterSpec iv_par = new IvParameterSpec(iv);
        return iv_par;

    }

    public static void main(String[] args) throws Exception {
        long time = System.nanoTime(); // timer
        //1)	Generate an RSA public-private key pair. KA+ and KA-.

        Map RSAkeys = new HashMap();
        KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        RSAkeys.put("Public", keys.getPublic()); // public key 
        RSAkeys.put("Private", keys.getPrivate()); // private key 
        System.out.println(RSAkeys);

        //2)Generate two symmetric keys: 128 bit K1 and 256 bit K2. Print values of the keys on the screen. 
        //Encypt them with KA+, print the results, and then decrypt them with KA-. Again print the results. 
        //Provide a screenshot showing your results.
        String key128 = "", key256 = ""; // string for print key128 &  key259
        Map AESkeys = new HashMap();
        SecretKey secretKey128 = Get_SecKey(128, "AES"); // get key in aes 128 bit
        key128 = ToBinary(secretKey128);

        SecretKey secretKey256 = Get_SecKey(256, "AES");
        key256 = ToBinary(secretKey256);
        AESkeys.put("128 Bit KEY: ", key128);
        AESkeys.put("256 bit KEY: ", key256);
        System.out.println(AESkeys);

        byte[] encryptedByte = cipher.doFinal(secretKey128.getEncoded()); // encruypt with public key 

        System.out.println("128 bit Key encrypted: " + toBinaryString(encryptedByte));

        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());// public key to pirvte key 

        byte[] decryptedByte = cipher.doFinal(encryptedByte);// 
        System.out.println("128 bit Key decrypted: " + toBinaryString(decryptedByte));
        System.out.println(" ");
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());

        byte[] encryptedByte256 = cipher.doFinal(secretKey256.getEncoded()); // encruypt with public key 
        System.out.println("256 bit Key encrypted: " + toBinaryString(encryptedByte256));
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());// public key to pirvte key 
        byte[] decryptedByte256 = cipher.doFinal(encryptedByte256);// 
        System.out.println("256 bit Key decrypted: " + toBinaryString(decryptedByte256));

        //3)Consider a long text m. Apply SHA256 Hash algorithm (Obtain the message digest, H(m)). 
        //Then encrypt it with KA-. (Thus generate a digital signature.) Then verify the digital signature. 
        //(Decrypt it with KA+ ,apply Hash algorithm to the message, compare). Print m, H(m) and digital signature on the screen. 
        //Provide a screenshot. (Or you may print in a file and provide the file).
        // Static getInstance method is called with hashing SHA
        String m = "هنالك العديد من الأنواع المتوفرة لنصوص لوريم إيبسوم، ولكن الغالبية"
                + " تم تعديلها بشكل ما عبر إدخال بعض النوادر أو الكلمات العشوائية إلى النص. إن كنت تريد أن تستخدم نص لوريم إيبسوم ما،"
                + " عليك أن تتحقق أولاً أن ليس هناك أي كلمات أو عبارات محرجة أو غير لائقة مخبأة في هذا النص."
                + " بينما تعمل جميع مولّدات نصوص لوريم إيبسوم على الإنترنت على إعادة تكرار مقاطع من نص لوريم إيبسوم نفسه عدة مرات بما تتطلبه الحاجة،"
                + " يقوم مولّدنا هذا باستخدام كلمات من قاموس يحوي على أكثر من 200 كلمة لا تينية، مضاف إليها مجموعة من الجمل النموذجي"
                + "ة، لتكوين نص لوريم إيبسوم ذو شكل منطقي قريب إلى النص الحقيقي. وبالتالي يكون النص الناتح خالي من التكرار، أو أي كلمات أو عبارات غير لائقة أو ما شاب"
                + "ه. وهذا ما يجعله أول مولّد نص لوريم إيبسوم حقيقي على الإنترنت";
        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 

        byte[] digestArray = HASH("SHA-256", m); // apply hashing algorithm
        cipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());// encrypt with private key 
        byte[] digitalSignature = cipher.doFinal(digestArray);//(digital signature.) (KA-(hash(M)) .
        System.out.println("m: " + m);// print m 
        System.out.println("digest: " + toBinaryString(digestArray));// print hashed
        System.out.println("digital signature: " + toBinaryString(digitalSignature));// print digital signature
        cipher.init(Cipher.DECRYPT_MODE, keys.getPublic());// decrypt with public key
        cipher.doFinal(digitalSignature);//Decrypt it with KA+
        /**
         * *****************************************************************************
         * Generate or find any file of size 1MB. Now consider following three
         * algorithms: i) AES (128 bit key) in CBC mode. ii) AES (256 bit key)
         * in CBC mode. iii) DES in CBC mode (you need to generate a 56 bit key
         * for this). a) Encrypt the file of size 1MB. Store the result (and
         * submit it with the homework) (Note: IV should be randomly generated,
         * Key = K1 or K2). b) Decrypt the file and store the result. Show that
         * it is the same as the original file. c) Measure the time elapsed for
         * encryption. Write it in your report. Comment on the result. d) For
         * the first algorithm, change Initialization Vector (IV) and show that
         * the corresponding ciphertext chages for the same plaintext (Give the
         * result for both).
         * ******************************************************
         */
        String file1MBsize = ReadFile("temp.txt");

        IvParameterSpec ivParams = InitializeVector(16);

        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey128, ivParams);// 128 bit key 
        time = System.nanoTime();
        byte[] encrypted128_txt = cipher.doFinal(file1MBsize.getBytes());
        // System.out.println(Arrays.toString(encrypted_file_txt));

        double elapsedTimeInSecond = (double) (System.nanoTime() - time) / 1_000_000_000;
        System.out.println("128 bit key time: " + elapsedTimeInSecond);

        WrFile("encrypted128.txt", encrypted128_txt);
        Path path = Paths.get("encrypted128.txt");
        byte[] encryptedtxt128 = Files.readAllBytes(path);
        cipher.init(Cipher.DECRYPT_MODE, secretKey128, ivParams); // DECRYPT_MODE , 128bit , iv
        byte[] DECRYPT_128file_txt = cipher.doFinal(encryptedtxt128);// DECRYPT_MODE
        WrFile("decrypted128.txt", DECRYPT_128file_txt);
        IvParameterSpec ivParams2 = InitializeVector(16);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey128, ivParams2);// 128 bit key 
        byte[] encrypted128_txt2 = cipher.doFinal(file1MBsize.getBytes());
        System.out.println(" First Initialization Vector: " + Arrays.toString(encrypted128_txt));
        System.out.println(" Second Initialization Vector: " + Arrays.toString(encrypted128_txt2));

        IvParameterSpec ivParams256 = InitializeVector(16);
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        SecretKeySpec keySpec = new SecretKeySpec(secretKey256.getEncoded(), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams256);// 256 bit key 

        time = System.nanoTime();
        byte[] encrypted_256_txt = cipher.doFinal(file1MBsize.getBytes());
        // System.out.println(Arrays.toString(encrypted_file_txt));

        elapsedTimeInSecond = (double) (System.nanoTime() - time) / 1_000_000_000;
        System.out.println("timer with 256 bit : " + elapsedTimeInSecond);

        WrFile("encrypted256.txt", encrypted_256_txt);

        //Java read file to byte[] array
        Path path256 = Paths.get("encrypted256.txt");
        byte[] encryptedtxt256 = Files.readAllBytes(path256);
        // System.out.println(Arrays.toString(dataec));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParams256); // DECRYPT_MODE , 256bit , iv
        byte[] decrypt_256file_txt = cipher.doFinal(encryptedtxt256);// DECRYPT_MODE
        WrFile("decrypted256.txt", decrypt_256file_txt);

        /////////////////////////////////////////////////////     DES in CBC mode (you need to generate a 56 bit key for this). ///////////////////////
        //https://stackoverflow.com/questions/4985591/create-des-key-from-56-bit-binary-string
        SecretKey DesKey = Get_SecKey(56, "DES");
        

        //The key ostensibly consists of 64 bits; however, only 56 of these are actually used by the algorithm. 
        // Eight bits are used solely for checking parity, and are thereafter discarded. Hence the effective key length is 56 bits,
        // and it is never quoted as such. Every 8th bit of the selected key is discarded, i.e. positions 8, 16, 24, 32, 40, 48, 56, 64 are removed
        //from the 64 bit key leaving behind only the 56 bit key.
        IvParameterSpec ivParams3 = InitializeVector(8);

        cipher = Cipher.getInstance("DES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, DesKey, ivParams3);// 56 bit key 
        long Time = System.nanoTime();
        byte[] encrypted_des_txt = cipher.doFinal(file1MBsize.getBytes());
        double TimeInSecond = (double) (System.nanoTime() - Time) / 1_000_000_000;
        System.out.println("Des timer: " + TimeInSecond);

        WrFile("en56.txt", encrypted_des_txt);

        Path path2 = Paths.get("en56.txt");
        byte[] entext_56 = Files.readAllBytes(path2);

        cipher.init(Cipher.DECRYPT_MODE, DesKey, ivParams3); // DECRYPT_MODE , 56bit , iv
        byte[] DECRYPT_des_file_txt = cipher.doFinal(entext_56);// DECRYPT_MODE

        WrFile("de56.txt", DECRYPT_des_file_txt);

    }

    static SecretKey Get_SecKey(int size, String Model) throws IOException, NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(Model); // getinstance of key 
        kg.init(size);// the size of key 
        SecretKey secretKey = kg.generateKey(); // secretKey
        return secretKey;
    }

    static String ReadFile(String fileName) throws Exception {
        String tempstring = "";
        File file = new File(fileName);
        Scanner re = new Scanner(file);
        while (re.hasNextLine()) {
            String data = re.nextLine();
            // System.out.println(data);
            tempstring += data;
        }
        re.close();
        return tempstring;
    }

    static void WrFile(String FileName, byte[] data) throws IOException {

        File filename = new File(FileName);

        FileWriter wr = new FileWriter(FileName);
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        wr.close();

    }
}
