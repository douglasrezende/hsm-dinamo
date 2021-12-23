package br.douglas.hsm.dinamo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import br.douglas.hsm.properties.Propertie;

public class HSM {

    static final String USER_PASSWORD_SEPARATOR =":";
    static final String PASSWORD_HOST_SEPARATOR ="@";
    static final String B2BWORKFLOWID_FILENAME_SEPARATOR = "_";

    public static void main( String[] args ) throws
    KeyStoreException, NoSuchProviderException,
    NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, TacException
    {
        String b2bWorkFlowId = "";
        if(args.length > 0){
            b2bWorkFlowId = B2BWORKFLOWID_FILENAME_SEPARATOR + args[0];
            b2bWorkFlowId = b2bWorkFlowId.trim();
        }
    
        String keyAlias = Propertie.getParameter("KEY_ALIAS");
        String hsmUser = Propertie.getParameter("HSM_USER");
        String hsmPassword = Propertie.getParameter("HSM_PASSWORD");
        String hsmHost = Propertie.getParameter("HSM_HOST");
        String encryptedFileSource = Propertie.getParameter("ENCRYPTED_FILENAME_AND_PATH");
        String decryptedFileDestination = Propertie.getParameter("DECRYPTED_FILENAME_AND_PATH");

        sendKeyToDecrypt(keyAlias, hsmUser,hsmPassword,hsmHost,encryptedFileSource,decryptedFileDestination,
                b2bWorkFlowId );
    }


    static void FilterKeyStore(String keyAlias, KeyStore keyStore) throws
    UnrecoverableKeyException, NoSuchAlgorithmException, FileNotFoundException, IOException, TacException
    {

        String hsmUser = Propertie.getParameter("HSM_USER");
        String hsmPassword = Propertie.getParameter("HSM_PASSWORD");
        String hsmHost = Propertie.getParameter("HSM_PASSWORD");

        try {

            Enumeration<String> keysInHSM = keyStore.aliases();
            //System.out.println(keysInHSM);

            while(keysInHSM.hasMoreElements())
            {
                String nextKey = (String)keysInHSM.nextElement();
                //System.out.println("ALIAS: "+nextKey );

                //    Certificate cer = (Certificate) keyStore.getCertificate(nextKey);

                //String nextKey = (String)keysInHSM.nextElement();

                if(0 != nextKey.compareTo(keyAlias))
                {
                    keyStore.deleteEntry(nextKey);
                }else {
                    //System.out.println("alias name: "+ nextKey );
                    keyStore.getCertificate(keyAlias);
                    keyStore.getCertificateChain(keyAlias);
                    Key key = keyStore.getKey(keyAlias, null);
                    //System.out.println("PK " + keyStore.getCertificate(keyAlias));
                    //System.out.println(key);
                    //System.out.println("--------------");
                    //System.out.println(key.getEncoded());

                    System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));

                    //sendKeyToDecrypt(keyAlias, hsmUser,hsmPassword,hsmHost);

                }
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }



    private static void sendKeyToDecrypt(String keyAlias, String hsmUser
            ,String hsmPassword,String hsmHost,
            String encryptedFileSource, String decryptedFileDestination,String b2bWorkFlowId ) throws TacException, IOException {

        Dinamo api = new Dinamo();
        try{
            api.openSession(hsmHost, hsmUser, hsmPassword, false);

            byte[] encBlock = Files
                    .readAllBytes(Paths.get(encryptedFileSource+b2bWorkFlowId));

            byte[] decBlock = api.decrypt(keyAlias, encBlock, TacNDJavaLib.D_FORCE_ACTUAL_RSA);

            File file = new File(decryptedFileDestination+b2bWorkFlowId);
            FileOutputStream in = new FileOutputStream(file);
            in.write(decBlock);
            in.close();
            System.out.println("Descriptografia da chave simetrica executada com sucesso, chave disponivel no diretorio: "
                    +decryptedFileDestination+b2bWorkFlowId);
        }catch(Exception ex){
            ex.printStackTrace();
        }finally{
            api.closeSession();   
        }

    }
}
