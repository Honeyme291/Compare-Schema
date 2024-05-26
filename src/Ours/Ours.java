package Ours;


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

public class Ours {



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
        String dir = "E:/java program/CLSC-Lxx/database/Ours/";
        String pairingParametersFileName = "E:/java program/CLSC-Lxx/database/Ours/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int j = 0; j < 10; j++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            for (int i = 0; i < users.length; i++) {
                KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            }
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);

            for(int i=0;i<users.length;i++){
                signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            }
            Aggregation(pairingParametersFileName,signCryptFileName,users);

            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users,rec);
            for(int i=0;i<users.length;i++){
                UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,users[i],rec);
            }

//            unsignCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, users, signCryptFileName, 2);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);

        }
    }

    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String skFileName, String signCryptFileName, String users, String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties skp = loadPropFromFile(skFileName);
        Properties SigC = loadPropFromFile(signCryptFileName);
        String xm = skp.getProperty("x"+rec);
        Element x =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String ym = skp.getProperty("y"+rec);
        Element y =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String Km = SigC.getProperty("K"+users);
        Element K = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km)).getImmutable();
        String Tm = SigC.getProperty("T"+users);
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm)).getImmutable();
        String ci = SigC.getProperty("C"+users);
        Element  C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ci)).getImmutable();
        byte [] c= C.toBytes();
        byte [] message = new byte[c.length];
        Element Q = K.powZn(x.add(y)).add(T.powZn(x));
        byte [] H_2 =sha1(users+Q.toString());
//        Element H=bp.getZr().newElementFromHash(H_2,0,H_2.length).getImmutable();
        for (int j = 0; j < c.length; j++){
            message[j] = (byte)(c[j] ^ H_2[j]);
        }
//        System.out.println("解密成功");

    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String signCryptFileName, String[] users,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        //验证操作
        Element[] SX = new Element[users.length];
        Element [] SY = new Element[users.length];
        String [] Xm = new String[users.length];
        String [] Ym = new String[users.length];
        String [] Km = new String[users.length];
        Element [] K  =new Element[users.length];
        String [] Tm = new String[users.length];
        Element [] T = new Element[users.length];
        String [] ci = new String[users.length];
        Element [] c = new Element[users.length];
        byte [][]BH_a = new byte[users.length][];
        Element[] H_a =new Element[users.length];
        Element[] H_b =new Element[users.length];
        Element[] H_c =new Element[users.length];

        for (int i=0;i< users.length;i++){
            Xm[i] = pkp.getProperty("X"+users[i]);
            Ym[i]=pkp.getProperty("Y"+users[i]);
            SX[i] = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Xm[i])).getImmutable();
            SY[i]=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ym[i])).getImmutable();
        }
        String Xi = pkp.getProperty("X"+rec);
        Element RX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Xi)).getImmutable();
        String Yi = pkp.getProperty("X"+rec);
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Yi)).getImmutable();
        byte[] BH_1 = sha1(rec + RX.toString() + RY.toString() + P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        for(int i=0;i< users.length;i++){
            Tm[i] = sigC.getProperty("T"+users[i]);
            Km[i] =sigC.getProperty("K"+users[i]);
            ci[i] = sigC.getProperty("C"+users[i]);
            T[i]=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm[i])).getImmutable();
            K[i]=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km[i])).getImmutable();
            c[i]=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ci[i])).getImmutable();
            BH_a[i] = sha1(users[i]+rec+SX[i].toString()+SY[i].toString()+RX.toString()+RY.toString()+c[i].toString()+K[i].toString()+T[i].toString());
            H_a[i]=bp.getZr().newElementFromHash(BH_a[i],0,BH_a[i].length).getImmutable();
            H_b[i]=bp.getZr().newElementFromHash(BH_a[i],0,BH_a[i].length).getImmutable();
            H_c[i]=bp.getZr().newElementFromHash(BH_a[i],0,BH_a[i].length).getImmutable();
        }

        String signSum = sigC.getProperty("signSum");
        Element Sign =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(signSum)).getImmutable();
        T[0]= T[0].powZn(H_a[0]);
        SX[0]= SX[0].powZn(H_b[0]);
        SY[0] = SY[0].add(P_pub.powZn(H_1)).powZn(H_c[0]);

        T[0]= T[0].powZn(H_a[0]);
        SX[0]= SX[0].powZn(H_b[0]);
        SY[0] = SY[0].add(P_pub.powZn(H_1)).powZn(H_c[0]);
        for(int i=1;i<users.length;i++){
            T[0]=T[0].add(T[i].powZn(H_a[i]));
            SX[0]=SX[0].add(SX[i].powZn(H_b[i]));
            SY[0] = SY[0].add(SY[i].add(P_pub.powZn(H_1)).powZn(H_c[i]));
        }

        Element op = P.powZn(Sign);
        Element sum =T[0].add(SX[0].add(SY[0]));
        if(op.isEqual(sum)){
            System.out.println("验证成功");
        }

    }

    private static void Aggregation(String pairingParametersFileName, String signCryptFileName,String[] users) {

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        String[] sign1 = new String[users.length];
        Element[] sign = new Element[users.length];

        for (int i=0;i<users.length;i++){
            sign1[i]=sigC.getProperty("sign"+users[i]);
            sign[i]= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sign1[i])).getImmutable();
            if (i==0){
                continue;
            }else {
                sign[0]=sign[0].add(sign[i]);
            }
        }

        sigC.setProperty("signSum", Base64.getEncoder().encodeToString(sign[0].toBytes()));
        storePropToFile(sigC,signCryptFileName);
    }




    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送方的操作

        //首先随机生成两个随机数。
        Element k= bp.getZr().newRandomElement().getImmutable();
        Element t= bp.getZr().newRandomElement().getImmutable();
        Element K = P.powZn(k);
        Element T = P.powZn(t);
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        String rectX = pkp.getProperty("X"+rec);
        String rectY =pkp.getProperty("Y"+rec);
        Element RX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();
        String sendX = pkp.getProperty("X"+users);
        String sendY =pkp.getProperty("Y"+users);
        Element SX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendX)).getImmutable();
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();
        String sendx = skp.getProperty("x"+users);
        String sendy =skp.getProperty("y"+users);
        Element Sx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendx)).getImmutable();
        Element Sy = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendy)).getImmutable();


        byte[] BH_1 = sha1(rec+RX.toString()+RY.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        //Xi.add(Ri.add(P_pub.powZn(h1i))).powZn(t);
        Element Q1 = RX.add(RY.add(P_pub.powZn(H_1))).powZn(k);
        Element Q2 = RX.powZn(t);
        Element Q = Q1.add(Q2);
        byte[] messageByte = messages.getBytes();
        byte[] alpha_hash = sha1(rec+Q.toString());
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ alpha_hash[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);
//        //签名
        byte[] BH_a = sha1(users+rec+SX.toString()+SY.toString()+RX.toString()+RY.toString()+c.toString()+K.toString()+T.toString());
        Element H_a=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_b=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_c=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element sign = H_a.mul(t.add(H_b.mul(Sx.add(H_c.mul(Sy)))));
        //将消息保存下来
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toBytes()));
        sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(ci.toString().getBytes()));
        sigC.setProperty("sign"+users, Base64.getEncoder().encodeToString(sign.toBytes()));
        storePropToFile(sigC,signCryptFileName);
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

        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("X"+user,Base64.getEncoder().encodeToString(X.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));

        //KGC生成私钥
        Element u= bp.getZr().newRandomElement().getImmutable();
        Element Y=P.powZn(u).getImmutable();
        byte[] BH_1 = sha1(user+X.toString()+Y.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element y = u.add(H_1.powZn(s)).getImmutable();
        //将公钥对保存下来。
        //生成私钥和公钥对
        //H1不能存储。
        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
        skp.setProperty("y"+user,Base64.getEncoder().encodeToString(y.toBytes()));
//        pkp.setProperty("H1_"+ID_i, H_1.toString());
        storePropToFile(pkp,pkFileName);
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
