package Hui;

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

public class Hui {

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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Hui/";
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
            signCrypt(pairingParametersFileName, publicParameterFileName,skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println((end - start));
        }
    }
    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName,String signCryptFileName, String users,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        Properties SigC = loadPropFromFile(signCryptFileName);
        String xm = skp.getProperty("x" + rec);
        Element xcc = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String ym = skp.getProperty("y" + rec);
        Element ycc = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ym)).getImmutable();


        String Xmi = pkp.getProperty("X"+users);
        Element Xi =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Xmi)).getImmutable();

        String Ymi = pkp.getProperty("Y"+users);
        Element Yi =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ymi)).getImmutable();
        String cm = SigC.getProperty("C"+users);
        Element c =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cm)).getImmutable();

        String Km = SigC.getProperty("K"+users);
        Element K =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km)).getImmutable();

        String Vm = SigC.getProperty("V"+users);
        Element V =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Vm)).getImmutable();

        String Tm = SigC.getProperty("T"+users);
        Element T =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm)).getImmutable();


        byte[] BH_3c = sha1(T.toString()+V.toString());
        Element H_3=bp.getZr().newElementFromHash(BH_3c,0,BH_3c.length).getImmutable();

        byte[] BH_4 = sha1(K.powZn(ycc.add(H_3.mul(xcc))).toString());
        Element H_4i=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();

        byte[] messageByte =new byte[c.toBytes().length];
        for (int j = 0; j < c.toBytes().length; j++){

            messageByte[j] = (byte)( c.toBytes()[j]^ BH_4[j]);
        }
    }

        private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        String rectU = pkp.getProperty("X"+rec);
        String rectY = pkp.getProperty("Y"+rec);
        Element XR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectU)).getImmutable();
        Element YR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();
        String sendU = pkp.getProperty("X"+users);
        String sendY = pkp.getProperty("Y"+users);
        Element XS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendU)).getImmutable();
        Element YS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();
        String sendx = skp.getProperty("x"+users);
        Element xS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendx)).getImmutable();
        String sendd = skp.getProperty("d"+users);
        Element dS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendd)).getImmutable();
        Element k= bp.getZr().newRandomElement().getImmutable();
        Element K = P.powZn(k);

        byte[] BH_1 = sha1(rec+XR.toString()+YR.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
            byte[] messageByte = messages.getBytes();
            byte[] ci = new byte[messageByte.length];
            for (int j = 0; j < messageByte.length; j++){
                ci[j] = (byte)(messageByte[j] ^ BH_1[j]);
            }
            Element c = bp.getZr().newElementFromHash(ci,0,ci.length);


            Element V = (XR.add(YR.add(P_pub.powZn(H_1)))).powZn(k);

            Element T = XS.powZn(H_1.mul(H_1));
            Element q = k.add(H_1.mul(xS.add(H_1.mul(dS))));

            Properties sigC=loadPropFromFile(signCryptFileName);
            sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toBytes()));
            sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
            sigC.setProperty("q"+users, Base64.getEncoder().encodeToString(q.toBytes()));
            sigC.setProperty("V"+users, Base64.getEncoder().encodeToString(V.toBytes()));
            sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toBytes()));
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
