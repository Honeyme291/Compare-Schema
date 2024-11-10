package Zhang;

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

public class Zhang {

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
        try (
                FileInputStream in = new FileInputStream(fileName)){
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Zhang/";
        String pairingParametersFileName = dir+"a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            PartialExtract(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            PartialExtract(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);


            signCrypt(pairingParametersFileName, publicParameterFileName, mskFileName,skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);


            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec);

//            unsignCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, users, signCryptFileName, 2);
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
        String d1_S =skp.getProperty("d"+users);
        Element ds = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(d1_S)).getImmutable();

        String x1_R =skp.getProperty("x"+rec);
        Element xR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_R)).getImmutable();
        String d1_R =skp.getProperty("d"+rec);
        Element dR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(d1_R)).getImmutable();
        String Q_S = pkp.getProperty("Q"+users);
        String T_S = pkp.getProperty("T"+users);

        Element QS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q_S)).getImmutable();
        Element TS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_S)).getImmutable();

        String Q_R = pkp.getProperty("Q"+rec);
        String T_R = pkp.getProperty("T"+rec);

        Element QR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q_R)).getImmutable();
        Element TR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_R)).getImmutable();

        Properties sigC=loadPropFromFile(signCryptFileName);

        String C1 = sigC.getProperty("C"+users);
        Element C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(C1)).getImmutable();

        String U1 = sigC.getProperty("U"+users);
        Element U= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(U1)).getImmutable();

        String r1 = sigC.getProperty("r"+users);
        Element r= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r1)).getImmutable();

        String theta1 = sigC.getProperty("theta"+users);
        Element theta= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(theta1)).getImmutable();


        String I1 = sigC.getProperty("I"+users);
        Element I= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(I1)).getImmutable();

        byte[] H_1 = sha1(rec+ TR.toString()+QR.toString()+P_pub.toString());

        byte[] H_1m = sha1(users+ TS.toString()+QS.toString()+P_pub.toString());

        Element h_1S = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        Element h_1R = bp.getZr().newElementFromHash(H_1,0,H_1.length);

        byte[] option = sha1(rec+U.toString()+U.powZn(h_1R.mul(xR).add(h_1S.mul(dR))).toString());

        byte [] message =new byte[C.toString().length()];


        for (int i=0;i< option.length;i++){
            message[i] = (byte) (C.toString().charAt(i) ^ option[i]);
        }

        Element I2 = P.powZn(theta).sub((QS.powZn(h_1S).add((TS.add(P_pub.powZn(h_1S))).powZn(h_1R))).powZn(r));

        if (I2.isEqual(I)){
            System.out.println("1");
        }

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
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();


        String x1_S =skp.getProperty("x"+users);
        Element xs = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String d1_S =skp.getProperty("d"+users);
        Element ds = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(d1_S)).getImmutable();
        String Q_S = pkp.getProperty("Q"+users);
        String T_S = pkp.getProperty("T"+users);

        Element QS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q_S)).getImmutable();
        Element TS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_S)).getImmutable();

        String Q_R = pkp.getProperty("Q"+rec);
        String T_R = pkp.getProperty("T"+rec);

        Element QR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q_R)).getImmutable();
        Element TR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_R)).getImmutable();

        byte[] H_1m = sha1(users+ TS.toString()+QS.toString()+P_pub.toString());

        Element h_1S = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        Element u = bp.getZr().newRandomElement().getImmutable();

        Element U = (QS.add(TS).add(P_pub.powZn(h_1S))).powZn(u);

        byte[] H_1 = sha1(rec+ TR.toString()+QR.toString()+P_pub.toString());

        Element h_1R = bp.getZr().newElementFromHash(H_1,0,H_1.length);

        byte[] option = sha1(rec+U.toString()+(QR.powZn(h_1R).add((TR.add(P_pub.powZn(h_1R))).powZn(h_1S))).powZn(u.mul(xs.add(ds))).toString());
        //发送方的操作
        byte[] messageByte = messages.getBytes();
        byte[] ci =new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){

            ci[j] = (byte)(messageByte[j] ^ option[j]);
        }

        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);


        Element k = bp.getZr().newRandomElement().getImmutable();

        Element I = P.powZn(k);

        byte[] H_3 = sha1(I.toString()+c.toString());

        Element r = bp.getZr().newElementFromHash(H_3,0,H_3.length);

        Element theta = r.mul(xs.mul(h_1S).add(h_1R.mul(ds))).add(k);




        //首先随机生成随机数。
        Properties sigC=loadPropFromFile(signCryptFileName);

        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toBytes()));
        sigC.setProperty("U"+users, Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("r"+users, Base64.getEncoder().encodeToString(r.toString().getBytes()));
        sigC.setProperty("theta"+users, Base64.getEncoder().encodeToString(theta.toString().getBytes()));
        sigC.setProperty("I"+users, Base64.getEncoder().encodeToString(I.toString().getBytes()));
        storePropToFile(sigC,signCryptFileName);
    }


    public static void PartialExtract(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException{
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

        Element x = bp.getZr().newRandomElement().getImmutable();

        Element Q = P.powZn(x);

        //获取随机数
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));
        pkp.setProperty("Q"+user,Base64.getEncoder().encodeToString(Q.toBytes()));
        storePropToFile(skp,skFileName);
    }

    public static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
//        String Pstr=pubProp.getProperty("P");
//        String BSN_istr=pubProp.getProperty("BSN_"+KGC);
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
//
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();


        Element y = bp.getZr().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(y).getImmutable();
        Element T = P.powZn(alpha).getImmutable();

        byte[] BH_1 = sha1(user+T.toString()+P.toString()+P_pub.toString());
        Element h_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element d = alpha.add(s.mul(h_1));



        //将公钥存储起来。
        pkp.setProperty("T"+user,Base64.getEncoder().encodeToString(T.toBytes()));
        pkp.setProperty("R"+user,Base64.getEncoder().encodeToString(R.toBytes()));
        skp.setProperty("d"+user,Base64.getEncoder().encodeToString(d.toBytes()));
        skp.setProperty("y"+user,Base64.getEncoder().encodeToString(y.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }
    public static void setup(String pairingParametersFileName, String publicParameterFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置KGC主私钥s

        Element x = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(x).getImmutable();

        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));

        storePropToFile(pubProp, publicParameterFileName);
    }


}
