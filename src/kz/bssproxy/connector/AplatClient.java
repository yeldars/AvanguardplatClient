/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package kz.bssproxy.connector;

/**
 *
 * @author BSS
 */

import kz.gamma.jce.provider.GammaTechProvider;
import kz.gamma.xmldsig.JCPXMLDSigInit;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;
import javax.xml.transform.OutputKeys;

/**
 * Created by Yeldar Saumbayev
 * Date: 12.08.2014
 * Time: 11:01:48
 */
public class AplatClient {

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception{
        
        //BSSProxyConfig.getInstance("C:\\Projects\\BSSPROXY\\bssproxy.conf");
        
        //Security.addProvider(new GammaTechProvider());
        Security.addProvider(new GammaTechProvider());
        JCPXMLDSigInit.init(); 
          
        String tumarProfile = System.getProperty("tumar.profile", "");
        String tumarSerial = System.getProperty("tumar.serial", "");
        String inputFileName = System.getProperty("input.file", "");
        String outputFileName = System.getProperty("output.file", "");
         
        System.out.println("Tumar Profile "+tumarProfile);
        System.out.println("Tumar Serial "+tumarSerial);
        System.out.println("input.file "+inputFileName);
        System.out.println("output.file "+outputFileName);
        //String body = new Scanner( new File(inputFileName) );
        String body = readFileAsString(inputFileName);

        //String body = "<body id=\"signedContent\"><payments><payment><ct><id>000000302</id><date>2014-08-13T10:57:51.0228</date></ct><service><id>228</id><accountId>777777777</accountId><amount>924.00</amount><commission>50.00</commission><parameters/><subservices><subservice><parameters/></subservice></subservices></service></payment></payments></body>";
        //String signStr = signAplatRequestBody("FSystemMGR","1F4559902460F29AA9C16147539357ED6D5AFF929282AAD2916822F9773E9775",body);
        String signStr = signAplatRequestBody(tumarProfile,tumarSerial,body);
        String str= "<request><header><security>"+signStr+"</security></header>"+body+"</request>";
        System.out.println(str);
        
        PrintWriter out = new PrintWriter(outputFileName);
        out.println(str);
        out.close();

        //tint i = aplatHttpRequest(str,2,"1039","1389","2a27179561");        
        //int i = aplatHttpRequest(str,2,"10296","15866","2a27179561");        
    }
    
private static String readFileAsString(String filePath) throws IOException {
        StringBuffer fileData = new StringBuffer();
        BufferedReader reader = new BufferedReader(
                new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
        }
        reader.close();
        return fileData.toString();
    }


    /**
     *
     * @param profile
     * @param serial    */
    public static String signAplatRequestBody(String profile,String serial,String xmlStr) {
        try {
            // Формируем класс хранилища ключей, будут доступны все профайлы криптопровайдера.
            
            KeyStore store = loadKeyStore(profile, "");
            //Получение списка ключей
            Enumeration en = store.aliases();
            while (en.hasMoreElements()) {
                en.nextElement();                
            }
            // Получение закрытого ключа по серийному номеру сертификата
            PrivateKey prvKey =  (PrivateKey)store.getKey(serial, null);
            if (prvKey != null) {
                //Получение сертификата по серийному номеру 
                Certificate cert = store.getCertificate(serial);
                if (cert != null) {
                    
                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    DocumentBuilder builder = dbf.newDocumentBuilder();
                    InputSource source = null;
                    source = new InputSource(new StringReader( xmlStr ));
                    // Подписываем XML документ
                    
                    String sigDoc = signXML(builder.parse(source), cert, prvKey);
                    //System.out.println(sigDoc);
                    return sigDoc;
                    // Проверяем подпись XML документа
                    //if (!validateXML(sigDoc))
                    //    throw new Exception("Подпись не прошла проверку");
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Создаем экземпляр класса для работы с TumarCSP.
     * Данный метод загружает ключи из выбранного профайла, при этом можно задать пароль на профайл
     *
     * @param profileName
     * @param pass
     * @return
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    private static KeyStore loadKeyStore(String profileName, String pass) throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore store = KeyStore.getInstance("GKS", "GAMMA");
        store.load(new ByteArrayInputStream(profileName.getBytes()), pass.toCharArray());
        
        return store;
    }

    /**
     * Метод формирования подписи xml документа
     *
     * @param doc
     * @param cert
     * @param privKey
     * @return
     * @throws Exception
     */    
  
private static String signXML(Document doc, Certificate cert, PrivateKey privKey)
            throws Exception {
        String signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
        String digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        XMLSignature sig = new XMLSignature(doc,"#signedContent", signMethod);
        
        Transforms transforms = new Transforms(doc);
        transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");        
        sig.addDocument("#signedContent", transforms, digestMethod);
        sig.sign(privKey);
        sig.addKeyInfo((X509Certificate) cert);

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(sig.getElement());
        transformer.transform(source, result);

        String xmlString = result.getWriter().toString();
        return xmlString;

    
    }






}

