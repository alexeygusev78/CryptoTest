package ru.alfabank.test.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.Entry.Attribute;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.Set;

import org.apache.log4j.Logger;

import ru.alfabank.server.backend.encoding.Base64Best;
import ru.alfabank.useful.utils.StringUtils;

public class CryptoClient {

    private static Logger log = Logger.getLogger(CryptoClient.class);

    public static void main(String[] args) {

        try {
            CryptoClient t = new CryptoClient();
            t.start();
        } catch (Exception e) {
            log.error(e);
        }

    }

    private void start() throws Exception {

        log.debug("CryptoClient is here...");

        messageDigestTest();
        securityConfiguration();
        readCertificateTest();
        signMessage();
        verifySignedMessage();
    }

    private String calcDigest(String message, MessageDigest md) {

        byte[] digestRaw = md.digest(message.getBytes());

        String digest = StringUtils.bytesToString(digestRaw);
        return digest;
    }

    private void messageDigestTest() throws Exception {

        log.debug("--- messageDigestTest");
        String message = "Hello world";

        String digest = calcDigest(message, MessageDigest.getInstance("MD5"));
        log.debug("digest(MD5)=" + digest);

        digest = calcDigest(message, MessageDigest.getInstance("SHA-1"));
        log.debug("digest(SHA-1)=" + digest);

        digest = calcDigest(message, MessageDigest.getInstance("SHA-256"));
        log.debug("digest(SHA-256)=" + digest);

        digest = calcDigest(message, MessageDigest.getInstance("SHA-512"));
        log.debug("digest(SHA-512)=" + digest);
    }

    /**
     * Отображает текущую конфигурацию криптографии
     * @throws Exception
     */
    private void securityConfiguration() throws Exception {

        log.debug("--- securityTest");

        Provider[] providers = Security.getProviders();
        for (Provider p: providers) {
            log.debug("  p: name=" + p.getName() + " info=" + p.getInfo());
            Set<Service> services = p.getServices();
            for (Service s: services) {
                log.debug("    s:" + " type=" + s.getType() + " algorithm=" + s.getAlgorithm());
            }
        }
    }

    /**
     * Пытаемся прочитать сертификат из хранилища
     * @throws Exception
     */
    private void readCertificateTest() throws Exception {

        log.debug("--- readCertificateTest");

        String jksFile = "/home/alexey/Documents/security/gusev_ul/gusev_ul.jks";
        String msgFile = "msg1.txt";
        String certFile = "gusev_ul.cer";
        String certAlias = "gusev_ul";

        byte[] msg = readFile(msgFile);

        // получить sha-256 для сообщения
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digestRaw = md.digest(msg);
        log.debug("get MessageDigest OK md=" + StringUtils.bytesToString(digestRaw));

        // открыть jks-файл
        // byte[] jks = readFile(jksFile);

        // открыть хранилище сертификатов
        KeyStore ks = openKeyStore(jksFile);

        // посмотреть что находится в хранилище
        log.debug("aliases:");
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            log.debug("  " + alias);
        }

        Certificate cert = ks.getCertificate(certAlias);
        if (cert == null) {
            throw new Exception("Certificate for alias=" + certAlias + " is not found");
        }
        log.debug("get cert OK alias=" + certAlias);
        log.debug("Certificate alias=" + certAlias + " information");
        log.debug("  type=" + cert.getType());
        log.debug("  cert={" + cert.toString() + "}");

        // сохранить сертификат
        FileOutputStream fos = new FileOutputStream(certFile);
        PrintWriter pw = new PrintWriter(fos);
        pw.write("-----BEGIN CERTIFICATE-----\n");
        pw.write(Base64Best.encodeToString(cert.getEncoded(), true));
        pw.write("-----END CERTIFICATE-----\n");
        pw.close();
        fos.close();
        log.debug("write cert OK name=" + certFile);

        log.debug("SUCCEEDED");
    }

    /**
     * Подписать сообщение
     * @throws Exception
     */
    private void signMessage() throws Exception {

        log.debug("--- signMessage");

        String jksFile = "/home/alexey/Documents/security/gusev_ul/gusev_ul.jks";
        String msgFile = "msg1.txt";
        String signFile = "msg1.sign";
        String certAlias = "gusev_ul";

        byte[] msg = readFile(msgFile);
        KeyStore ks = openKeyStore(jksFile);

        // получаем Private Key для заданного алиаса
        Entry e = ks.getEntry(certAlias, new KeyStore.PasswordProtection("1".toCharArray()));
        log.debug("get entry OK alias=" + certAlias + " class=" + e.getClass().getName());

        Key key = ks.getKey(certAlias, "1".toCharArray());
        log.debug("get key OK class=" + key.getClass().getName());

        log.debug("Entry attributes:");
        Set<Attribute> attributes = e.getAttributes();
        for (Attribute a: attributes) {
            log.debug("  " + a.getName() + "=" + a.getValue());
        }

        // подписать сообщение
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign((PrivateKey) key);
        rsa.update(msg);
        byte[] sign = rsa.sign();
        log.debug("Sign OK sign=" + StringUtils.bytesToString(sign));

        FileOutputStream fos = new FileOutputStream(signFile);
        fos.write(sign);
        fos.close();

        log.debug("SUCCEEDED");
    }

    /**
     * Верифицировать подписанное ранее сообщение.
     * @throws Exception
     */
    private void verifySignedMessage() throws Exception {

        log.debug("--- verifySignedMessage");

        String jksFile = "/home/alexey/Documents/security/gusev_ul/gusev_ul.jks";
        String msgFile = "msg1.txt";
        String signFile = "msg1.sign";
        String certAlias = "gusev_ul";
        String certFile = "gusev_ul.cer";

        Certificate cert = null;
        // загружаем сертификат из KeyStore
        // cert = openKeyStore(jksFile).getCertificate(certAlias);
        log.debug("get cert OK");

        // ... или загружаем сертификат из файла *.cer
        cert = this.loadCertFromFile(certFile);

        // получаем открытый ключ из сертификата
        PublicKey pubKey = cert.getPublicKey();
        log.debug("get publicKey OK");

        // загрузить файл и цифровую подпись
        byte[] msg = readFile(msgFile);
        byte[] sign = readFile(signFile);

        // верифицировать сообщение
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(pubKey);
        rsa.update(msg);
        boolean result = rsa.verify(sign);
        log.debug("verified=" + result);

        log.debug("SUCCEEDED");
    }

    /**
     * Открыть хранилище сертификатов
     * @param jksFile
     * @return
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    private KeyStore openKeyStore(String jksFile) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {

        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream jksFis = new FileInputStream(jksFile);
        ks.load(jksFis, "1".toCharArray());
        jksFis.close();
        log.debug("open JKS OK name=" + jksFile);
        return ks;
    }

    /**
     * Загрузить сертификат из файла
     * @param certFilename
     * @return
     * @throws Exception
     */
    private Certificate loadCertFromFile(String certFilename) throws Exception {

        try (FileInputStream fis = new FileInputStream(certFilename);) {
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(bis);
            if (cert == null) {
                throw new Exception("Failed to load Certificate");
            }

            return cert;
        }
    }

    /**
     * Считать файл в буфер
     * @param filename
     * @return
     * @throws Exception
     */
    private byte[] readFile(String filename) throws Exception {

        final int BUFFER_SIZE = 0x400;

        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte buffer[] = new byte[BUFFER_SIZE];
        int count = 0;
        while ((count = fis.read(buffer)) > 0) {
            baos.write(buffer, 0, count);
        }
        fis.close();

        byte out[] = baos.toByteArray();
        baos.close();

        log.debug("readFile OK name=" + filename + " size=" + out.length);

        return out;
    }
}
