/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.json.Json;
import sun.security.x509.X500Name;
import sun.security.tools.keytool.CertAndKeyGen;

public class Peer {

    enum PeerType {
        ALICE, BOB
    }
    public PeerType peerType;
    public static ServerThread serverThread;

    public KeyPair keys;

    public X509Certificate rootCertificate;
    public PublicKey targetPublicKey;
    public int authenticationNonce;

    Socket socket = null;

    SecretKey kA;
    SecretKey kB;
    Mac macA;
    Mac macB;
    byte[] ivA;
    byte[] ivB;

    String username;
    static Object[] carrierObject = new Object[3];

    int sequenceNumber;
    int messageNonce;

    ArrayList<String> macList = new ArrayList<String>();

    public static void main(String[] args) throws IOException, Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("> enter username & port # for this peer:");
        String[] setupValues = bufferedReader.readLine().split(" ");

        serverThread = new ServerThread(Integer.parseInt(setupValues[1]));
        serverThread.start();

        carrierObject[0] = bufferedReader;
        carrierObject[1] = setupValues[0];
        carrierObject[2] = serverThread;
        new Peer().listenToPeer(bufferedReader, setupValues[0], serverThread);
    }

    public void sendHandshake() {
        serverThread.sendHandshake(keys.getPublic());
    }

    public void sendCertificate() throws CertificateEncodingException, UnsupportedEncodingException {
        authenticationNonce = sun.security.krb5.Confounder.intValue() & 0x7fffffff; 
        messageNonce = authenticationNonce;
        serverThread.sendCertificate(rootCertificate, authenticationNonce);
    }

    public void sendNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        serverThread.sendNonceBack(keys.getPrivate(), authenticationNonce);
    }

    public void decryptNonce(byte encryptedNonce[]) throws UnsupportedEncodingException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, targetPublicKey);
            byte[] decryptedNonceBytes = cipher.doFinal(encryptedNonce);
            BigInteger noncebigInteger = new BigInteger(decryptedNonceBytes);
            compareNonce(noncebigInteger.intValue());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void compareNonce(int receivedNonce) throws UnsupportedEncodingException {
        if (authenticationNonce == receivedNonce) {
            System.out.println("iyi bayramlar (:");
            serverThread.sendAcknowledgement();
        } else {
            System.out.println("imamoglu ):");
        }
    }

    public void generateKeysAndCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, InvalidKeyException, SignatureException, ClassNotFoundException {
        //Generate ROOT certificate

        CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
        keyGen.generate(2048);
        PublicKey publicKey = keyGen.getPublicKey();
        PrivateKey rootPrivateKey = keyGen.getPrivateKey();
        keys = new KeyPair(publicKey, rootPrivateKey);
        rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);
        System.out.println(" generate Certificate ");
        String s = new String(rootCertificate.getEncoded(), Constants.charsetName);
    }

    public void generateKeysAndMacs() throws UnsupportedEncodingException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            kA = keyGenerator.generateKey();//Generating 128 bit AES key

            KeyGenerator keyGenerator2 = KeyGenerator.getInstance("AES");
            keyGenerator2.init(128);
            kB = keyGenerator2.generateKey();//Generating 128 bit AES key

            macA = Mac.getInstance("HmacSHA256");
            macA.init(kA);

            macB = Mac.getInstance("HmacSHA256");
            macB.init(kB);

            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            ivA = new byte[16];
            ivB = new byte[16];
            secureRandom.nextBytes(ivA);
            secureRandom.nextBytes(ivB);
            serverThread.sendKeys(kA, kB, ivA, ivB);

        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void SetKeys(SecretKey kA, SecretKey kB, byte ivA[], byte ivB[]) {
        try {
            this.kA = kA;
            this.kB = kB;
            this.ivA = ivA;
            this.ivB = ivB;
            macA = Mac.getInstance("HmacSHA256");
            macA.init(kA);

            macB = Mac.getInstance("HmacSHA256");
            macB.init(kB);
            serverThread.sendCommunicationSignal();

        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    byte[] concatByteArray(byte a[], byte b[]) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public void listenToPeer(BufferedReader bufferedReader, String username, ServerThread serverThread) throws Exception {

        System.out.println("> enter (space seperated) hostname:port#");
        System.out.println(" peers to receive messages from");

        String input = bufferedReader.readLine();
        String[] inputValues = input.split(" ");
        if (!input.equals("s")) {
            for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");

                try {
                    socket = new Socket(address[0], Integer.valueOf(address[1]));
                    if (serverThread.peerCount == 0) {
                        peerType = PeerType.ALICE;
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                        kpg.initialize(2048);
                        keys = kpg.generateKeyPair();
                    } else {
                        peerType = PeerType.BOB;

                        System.out.println("bob");
                        serverThread.sendSignal();
                        generateKeysAndCertificate();
                    }
                    new PeerThread(socket, this).start();

                } catch (IOException | NumberFormatException e) {
                    if (socket != null) {
                        socket.close();
                        System.out.println("buraya girdi");
                    } else {
                        System.out.println("invalid input");
                    }
                }
            }
        }
        communicate(bufferedReader, username, serverThread);
    }

    public void communicate(BufferedReader bufferedReader, String username, ServerThread serverThread) {

        try {
            System.out.println("you can communicate");
            boolean flag = true;
            while (flag) {

                String mesaage = bufferedReader.readLine();
                if (mesaage.equals("exit")) {
                    flag = false;
                    break;
                } else if (mesaage.equals("new peer")) {
                    listenToPeer(bufferedReader, username, serverThread);
                } else {

                    String mac = "";
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    byte[] encryptedNonceBytes = null;
                    String encryptedNonceString = "";
                    if (peerType == PeerType.ALICE) {
                        
                        IvParameterSpec ivParamsA = new IvParameterSpec(ivA);
                        cipher.init(Cipher.ENCRYPT_MODE, kA, ivParamsA);

                        mesaage = new String(cipher.doFinal(mesaage.getBytes(Constants.charsetName)), Constants.charsetName);
                        sequenceNumber++;
                        messageNonce = messageNonce + sequenceNumber;

                        

                        BigInteger bigInt = BigInteger.valueOf(messageNonce); 
                        byte nonceByteArray[] = bigInt.toByteArray();
                        
                        encryptedNonceBytes = cipher.doFinal(nonceByteArray);
                        
                        encryptedNonceString = new String(encryptedNonceBytes, Constants.charsetName);

                        byte concatanatedMessage[] = concatByteArray(mesaage.getBytes(Constants.charsetName), nonceByteArray);

                        mac = Arrays.toString(macA.doFinal(concatanatedMessage));

                    } else if (peerType == PeerType.BOB) {
                        
                        IvParameterSpec ivParamsB = new IvParameterSpec(ivB);

                        cipher.init(Cipher.ENCRYPT_MODE, kB, ivParamsB);//TODO: ORTAK DEGER GİRİLEBİLİR 
                        mesaage = new String(cipher.doFinal(mesaage.getBytes(Constants.charsetName)), Constants.charsetName);
                        sequenceNumber++;
                        messageNonce = messageNonce + sequenceNumber;

                        BigInteger bigInt = BigInteger.valueOf(messageNonce);
                        byte nonceByteArray[] = bigInt.toByteArray();
                        
                        encryptedNonceBytes = cipher.doFinal(nonceByteArray);
                        
                        encryptedNonceString = new String(encryptedNonceBytes, Constants.charsetName);

                        byte concatanatedMessage[] = concatByteArray(mesaage.getBytes(Constants.charsetName), nonceByteArray);
                        mac = Arrays.toString(macB.doFinal(concatanatedMessage));

                    }

                    StringWriter stringWriter = new StringWriter();
                    Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                            .add("username", username)
                            .add("message", mesaage)
                            .add("mac", mac)
                            .add("nonce", encryptedNonceString)
                            .build());
                    serverThread.sendMessage(stringWriter.toString());
                }
            }
            System.exit(0);

        } catch (IOException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
