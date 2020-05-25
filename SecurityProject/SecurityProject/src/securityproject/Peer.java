/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;
import sun.security.x509.X500Name;
import sun.security.tools.keytool.CertAndKeyGen;

public class Peer {

    private enum PeerType {

        ALICE, BOB
    }
    private PeerType peerType;
    public static ServerThread serverThread;
    public KeyPair keys;
    public X509Certificate rootCertificate;
    public PublicKey targetPublicKey;
    public int nonce;
    Socket socket = null;

    public static void main(String[] args) throws IOException, Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("> enter username & port # for this peer:");
        String[] setupValues = bufferedReader.readLine().split(" ");
        serverThread = new ServerThread(Integer.parseInt(setupValues[1]));
        serverThread.start();
        new Peer().listenToPeer(bufferedReader, setupValues[0], serverThread);

    }

    public void sendHandshake() {

        serverThread.sendHandshake(keys.getPublic());
    }

    public void sendNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        serverThread.sendNonceBack(keys.getPrivate(), nonce);
    }

    public void sendCertificate() throws CertificateEncodingException, UnsupportedEncodingException {
        nonce = sun.security.krb5.Confounder.intValue() & 0x7fffffff;
        serverThread.sendCertificate(rootCertificate, nonce);
    }

    public void decryptNonce(byte encryptedNonce[]) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, targetPublicKey);
            byte[] decryptedNonceBytes = cipher.doFinal(encryptedNonce);
            BigInteger noncebigInteger = new BigInteger(decryptedNonceBytes);
            compareNonce(noncebigInteger.intValue());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Peer.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }

    public void compareNonce(int receivedNonce) {
        //System.out.println("bu bizdeki nonce :" + nonce);
        //System.out.println("bu de gel nonce diye koy :" + receivedNonce);
        if (nonce == receivedNonce) {
            System.out.println("iyi bayramlar (:");
        } else {
            System.out.println("imamoglu ):");
        }
    }

    public void generateKeysAndCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, InvalidKeyException, SignatureException, ClassNotFoundException {
        //Generate ROOT certificate
        String charsetName = "ISO-8859-1";
//            String certAndKeyGen = "sun.security" + ".tools.keytool" + ".CertAndKeyGen";
//            Class c = Class.forName(certAndKeyGen);c.getDeclaredConstructors()[0]
        CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
        keyGen.generate(2048);
        PublicKey publicKey = keyGen.getPublicKey();
        PrivateKey rootPrivateKey = keyGen.getPrivateKey();
        keys = new KeyPair(publicKey, rootPrivateKey);
        rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);
        System.out.println(" generate Certificate ");
        String s = new String(rootCertificate.getEncoded(), charsetName); // TODO: mustafa base64 kullanmasi D:"  https://gist.github.com/RevenueGitHubAdmin/90d3af2f4fbe13fec85a763066e7bab0
        //System.out.println("is equals yaz : "+rootCertificate.getEncoded().equals(s.getBytes()));
        // System.out.println("bunu anlayailm (: " + cert.equals(rootCertificate));
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
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");//In this part, generating 512(default) bit public and private keys
                        kpg.initialize(2048);
                        keys = kpg.generateKeyPair();
                    } else {
                        peerType = PeerType.BOB;
                        //TODO: ONAY MESAJI YOLLA
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
                if (mesaage.equals("e")) {
                    flag = false;
                    break;
                } else if (mesaage.equals("c")) {
                    listenToPeer(bufferedReader, username, serverThread);
                } else {

                    StringWriter stringWriter = new StringWriter();
                    Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                            .add("username", username)
                            .add("message", mesaage)
                            .build());
                    serverThread.sendMessage(stringWriter.toString());
                }
            }
            System.exit(0);
        } catch (Exception e) {

        }
    }
}
