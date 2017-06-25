package complete;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptUtil {
    public static final String ISO_8859_1 = "ISO-8859-1";
    public static final String UTF_8 = "UTF-8";
    public static final char PADDING_CHAR = '\0';
    static String IV = "abababababababab";
    static String encryptionKey = "abcdef0123456789";

    public static String encrypt(String plainText) throws Exception {
        plainText = padding(plainText);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes(UTF_8)));
        byte[] bytes = cipher.doFinal(plainText.getBytes(UTF_8));
        String s = new String(bytes, ISO_8859_1);
        return s;
    }

    public static String decrypt(String cipherText) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes(UTF_8)));
        byte[] decoded = cipherText.getBytes(ISO_8859_1);
        String s = new String(cipher.doFinal(decoded), UTF_8);
        return unpadding(s);
    }

    static String padding(String data){
        StringBuilder sb = new StringBuilder(data);
        int lengthFactor = 16; // length has to be multiple of 16
        while(sb.length()% lengthFactor != 0){
            sb.append(PADDING_CHAR);
        }
        return sb.toString();
    }

    static String unpadding(String data){
        StringBuilder sb = new StringBuilder(data);
        while(sb.length()>0 && sb.charAt(sb.length()-1) == PADDING_CHAR){
            sb.deleteCharAt(sb.length()-1);
        }
        return sb.toString();
    }
}