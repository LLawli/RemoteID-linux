// Critério de aceitação executável da issue #10, só com o JDK (sem o jar do
// PJeOffice): o SunPKCS11 registra o `Cipher.RSA/ECB/PKCS1Padding` para este
// token e aceita `init(ENCRYPT_MODE, chavePrivada)`?
//
// É a única porta JCA para RSA cru num token PKCS#11. Desde o JDK-8176837
// (11.0.6) o SunPKCS11 só a registra se `C_GetMechanismInfo(CKM_RSA_PKCS)`
// anunciar `CKF_ENCRYPT`; e, com a chave PRIVADA em `ENCRYPT_MODE`, o
// `P11RSACipher` faz `C_SignInit(CKM_RSA_PKCS)` + `C_Sign` de uma parte só,
// com o bloco (o DigestInfo pronto) que o `doFinal` recebeu. É exatamente o
// que o `ANYwithRSASignature` do signer4j precisa por baixo.
//
// A prova vai além do `init`: assina um DigestInfo pelo `Cipher` e verifica
// com `Signature.<hash>withRSA` contra a chave pública do certificado. Com o
// módulo em modo de produção, isso atravessa módulo, socket, `servidor-fixo`
// e mock; é o passo de Java do `tools/teste-integracao-pkcs11.sh`.
//
// Uso (lançador de arquivo único, Java 11+):
//   TEST_URL=http://localhost:<porta> java ProvaCipher.java <modulo.so> [--md5]
//
// `--md5` liga o segundo passo, o que o `PjeAuthenticatorTask` faz de fato:
// `DigestInfo(MD5)` de 34 bytes assinado cru e verificado como `MD5withRSA`.
// Só passa com o modo cru do caminho de produção (issue #11).
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.Cipher;

public class ProvaCipher {
    // Prefixos DER do DigestInfo (RFC 8017 §9.2, nota 1).
    static final byte[] PREFIXO_SHA256 = hex("3031300d060960864801650304020105000420");
    static final byte[] PREFIXO_MD5 = hex("3020300c06082a864886f70d020505000410");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("uso: java ProvaCipher.java <modulo.so> [--md5]");
            System.exit(2);
        }
        boolean md5 = Arrays.asList(args).contains("--md5");

        Provider p11 = Security.getProvider("SunPKCS11")
            .configure("--name=remoteid\nlibrary=" + args[0] + "\n");
        Security.addProvider(p11);

        // O token não anuncia CKF_LOGIN_REQUIRED, então o load sem senha já
        // enxerga a chave privada pareada ao certificado por CKA_ID.
        KeyStore ks = KeyStore.getInstance("PKCS11", p11);
        ks.load(null, null);
        String alias = null;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String x = e.nextElement();
            if (ks.isKeyEntry(x)) {
                alias = x;
                break;
            }
        }
        if (alias == null) {
            falhar("o KeyStore do SunPKCS11 não enxergou nenhuma chave privada no token");
        }
        PrivateKey privada = (PrivateKey) ks.getKey(alias, null);
        PublicKey publica = ks.getCertificate(alias).getPublicKey();
        ok("KeyStore PKCS11 carregado, entrada de chave '" + alias + "'");

        // 1) O gate. Sem CKF_ENCRYPT no mecanismo isto lança
        //    NoSuchAlgorithmException: é o item 3 do reprodutor da issue.
        Cipher cifra = Cipher.getInstance("RSA/ECB/PKCS1Padding", p11);
        cifra.init(Cipher.ENCRYPT_MODE, privada);
        ok("Cipher.RSA/ECB/PKCS1Padding registrado por '" + cifra.getProvider().getName()
            + "' e init(ENCRYPT_MODE, chave privada do token) aceito");

        // 2) O que o signer4j faz por dentro: DigestInfo pronto, RSA cru, e a
        //    saída tem de verificar como <hash>withRSA.
        byte[] mensagem = "prova do caminho Cipher do SunPKCS11".getBytes(StandardCharsets.UTF_8);
        provar(cifra, privada, publica, "SHA-256", PREFIXO_SHA256, "SHA256withRSA", mensagem);
        if (md5) {
            provar(cifra, privada, publica, "MD5", PREFIXO_MD5, "MD5withRSA", mensagem);
        }
        System.out.println("PROVA JCA: tudo verde.");
    }

    static void provar(Cipher cifra, PrivateKey privada, PublicKey publica, String hash,
                       byte[] prefixo, String algoritmoAssinatura, byte[] mensagem)
        throws Exception {
        byte[] digest = MessageDigest.getInstance(hash).digest(mensagem);
        byte[] digestInfo = new byte[prefixo.length + digest.length];
        System.arraycopy(prefixo, 0, digestInfo, 0, prefixo.length);
        System.arraycopy(digest, 0, digestInfo, prefixo.length, digest.length);

        cifra.init(Cipher.ENCRYPT_MODE, privada);
        byte[] assinatura = cifra.doFinal(digestInfo);
        if (assinatura.length != 256) {
            falhar("o Cipher devolveu " + assinatura.length + " bytes; RSA-2048 dá 256");
        }

        // Verificação por software (SunRsaSign), contra a pública do
        // certificado: prova que o servidor só aplicou o padding ao DigestInfo
        // que mandamos, e que o hash embutido é o que dissemos.
        Signature verificador = Signature.getInstance(algoritmoAssinatura);
        verificador.initVerify(publica);
        verificador.update(mensagem);
        if (!verificador.verify(assinatura)) {
            falhar("a assinatura feita pelo Cipher com DigestInfo(" + hash
                + ") NÃO verifica como " + algoritmoAssinatura);
        }
        ok("doFinal(DigestInfo(" + hash + "), " + digestInfo.length + " bytes) verifica como "
            + algoritmoAssinatura);
    }

    static void ok(String msg) {
        System.out.println("  ✓ " + msg);
    }

    static void falhar(String msg) {
        System.err.println("FALHOU: " + msg);
        System.exit(1);
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
