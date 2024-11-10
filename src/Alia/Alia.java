package Alia;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class Alia {
    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String rec = "rec@snnu.edu.com";
        String[] messages = new String[]{"111", "12345678", "01234567890123456789", "7777777777", "123", "1123", "123", "123", "123", "123"};
        String[] users = new String[]{"send@snnu.edu.com", "send1@snnu.edu.com", "send2@snnu.edu.com", "send3@snnu.edu.com", "send4@snnu.edu.com", "send5@snnu.edu.com", "send6@snnu.edu.com", "send7@snnu.edu.com", "send8@snnu.edu.com", "send9@snnu.edu.com"};
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Alia/";
        String pairingParametersFileName = dir+"a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            SetKey(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            SetKey(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            signCrypt(pairingParametersFileName, publicParameterFileName, mskFileName,skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println((end - start));
        }
    }



    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String pkFileName,String skFileName, String signCryptFileName, String users, String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        String x1_S =skp.getProperty("x"+users);
        Element xs = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String D1_S =skp.getProperty("D"+users);
        Element DS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(D1_S)).getImmutable();

        String pk_S = pkp.getProperty("pk"+users);
        Element pkS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk_S)).getImmutable();

        String x1_R =skp.getProperty("x"+rec);
        Element xR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_R)).getImmutable();
        String D1_R =skp.getProperty("D"+rec);
        Element DR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(D1_R)).getImmutable();

        String pk_R = pkp.getProperty("pk"+rec);
        Element pkR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk_R)).getImmutable();


        Properties sigC=loadPropFromFile(signCryptFileName);

        String C1 = sigC.getProperty("C"+users);
        Element C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(C1)).getImmutable();

        String U1 = sigC.getProperty("U"+users);
        Element U= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(U1)).getImmutable();

        String S1 = sigC.getProperty("S"+users);
        Element S= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(S1)).getImmutable();

        String h_i1 = sigC.getProperty("h_i"+users);
        Element h_i= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(h_i1)).getImmutable();


        String V1 = sigC.getProperty("V"+users);
        Element V= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(V1)).getImmutable();


        Element K = bp.pairing(U,P.powZn(DR));

        Element F = U.powZn(xR);


        byte[] H_1m = sha1(K.toString()+F.toString());

        Element T = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        byte[] message =new byte[H_1m.length];
        for (int j = 0; j < H_1m.length; j++){
            message[j] = (byte)(H_1m[j] ^ C.toString().charAt(j));
        }
        Element sigma = bp.getZr().newElementFromHash(message,0,message.length);
        byte[] H_is = new byte[message.length];
        for (int i=0;i<message.length;i++){
            H_is = sha1(message[i]+V.toString()+U.toString()+T.toString());
        }

        Element h_1 = bp.getZr().newElementFromHash(H_is,0,H_is.length);

        Element alpha = V.div(sigma);

    }

    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String mskFileName,String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");

        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);


        String x1_S =skp.getProperty("x"+users);
        Element xs = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String D1_S =skp.getProperty("D"+users);
        Element DS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(D1_S)).getImmutable();

        String pk_S = pkp.getProperty("pk"+users);
        Element pkS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk_S)).getImmutable();

        String x1_R =skp.getProperty("x"+rec);
        Element xR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_R)).getImmutable();
        String D1_R =skp.getProperty("D"+rec);
        Element DR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(D1_R)).getImmutable();

        String pk_R = pkp.getProperty("pk"+rec);
        Element pkR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pk_R)).getImmutable();

        Element r = bp.getZr().newRandomElement().getImmutable();

        Element U = P.powZn(r);

        Element F = pkR.powZn(r);

        byte[] H_qm = sha1(rec);

        Element QR = bp.getZr().newElementFromHash(H_qm,0,H_qm.length);


        Element K = bp.pairing(P_pub.powZn(r),P.powZn(QR));


        byte[] H_1m = sha1(K.toString()+F.toString());

        Element T = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);


        Element sigma = bp.getZr().newRandomElement().getImmutable();

        byte[] ci =new byte[H_1m.length];
        for (int j = 0; j < H_1m.length; j++){
            ci[j] = (byte)(H_1m[j] ^ sigma.toString().charAt(j));
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        byte[] H_2m = sha1(sigma.toString());

        Element alpha = bp.getZr().newElementFromHash(H_2m,0,H_2m.length);

        Element m = bp.getZr().newElementFromBytes(messages.getBytes()).getImmutable();

        Element V = m.mul(alpha);
       byte[] H_is = new byte[ci.length];
        for (int i=0;i<ci.length;i++){
             H_is = sha1(ci[i]+V.toString()+U.toString()+T.toString());
        }

        Element h_i = bp.getZr().newElementFromHash(H_is,0,H_is.length);

        Element S = xs.mul(r.add(h_i));


        //首先随机生成随机数。
        Properties sigC=loadPropFromFile(signCryptFileName);

        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toBytes()));
        sigC.setProperty("U"+users, Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("S"+users, Base64.getEncoder().encodeToString(S.toString().getBytes()));
        sigC.setProperty("h_i"+users, Base64.getEncoder().encodeToString(h_i.toString().getBytes()));
        sigC.setProperty("V"+users, Base64.getEncoder().encodeToString(V.toString().getBytes()));
        storePropToFile(sigC,signCryptFileName);
    }

    public static void SetKey(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        Element x = bp.getZr().newRandomElement().getImmutable();

        Element pk = P.powZn(x);

        pkp.setProperty("pk"+user,Base64.getEncoder().encodeToString(pk.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);
    }
    public static void PartialKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");

        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
//
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();


        byte[] BH_1 = sha1(user);
        Element Q=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element D= s.mul(Q);

        //将公钥存储起来。

        skp.setProperty("D"+user,Base64.getEncoder().encodeToString(D.toBytes()));
        storePropToFile(skp,skFileName);

    }

    public static void setup(String pairingParametersFileName, String publicParameterFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置KGC主私钥s

        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicParameterFileName);
    }

}
