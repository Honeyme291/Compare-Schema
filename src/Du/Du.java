package Du;

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

public class Du{



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
        String dir = "E:/java program/CLSC-Lxx/database/Du/";
        String pairingParametersFileName = "E:/java program/CLSC-Lxx/database/Du/a.properties";
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
            //Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users,rec);
            for(int i=0;i<users.length;i++){
                UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,pkFileName,users[i],rec);

            }

//            unsignCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, users, signCryptFileName, 2);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println((end - start)*5);

        }
    }

    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String skFileName, String signCryptFileName, String pkFileName,String users, String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp =loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        Properties SigC = loadPropFromFile(signCryptFileName);
        String xm = skp.getProperty("x"+rec);
        Element xb =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String dB = skp.getProperty("d"+rec);
        Element db =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();


        String  xB= pkp.getProperty("T"+rec);
        String qB=pkp.getProperty("Q"+rec);
        Element XB = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(xB)).getImmutable();
        Element QB=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(qB)).getImmutable();
        String  xA= pkp.getProperty("T"+users);
        String qA=pkp.getProperty("Q"+users);
        Element XA = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(xA)).getImmutable();
        Element QA=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(qA)).getImmutable();

        String Ua = SigC.getProperty("U"+users);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ua)).getImmutable();
        Element Lop = U.powZn(xb.add(db));
        byte [] Km = sha1(rec+U.toString()+Lop.toString());
        Element K = bp.getZr().newElementFromHash(Km,0,Km.length).getImmutable();
        String ci = SigC.getProperty("C"+users);
        Element  C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ci)).getImmutable();
        byte [] c= C.toBytes();
        byte [] message = new byte[c.length];

        for (int j = 0; j < c.length; j++){
            message[j] = (byte)(c[j] ^ Km[j]);
        }

        byte [] H_3i = sha1(K.toString()+rec+XB.toString()+QB.toString());

        Element H_3=bp.getZr().newElementFromHash(H_3i,0,H_3i.length).getImmutable();
        byte [] la = sha1(users+XA.toString()+QA.toString()+U.toString()+H_3.toString()+c.toString());
//        Element La = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(la)).getImmutable();
        Element La=bp.getZr().newElementFromHash(la,0,la.length).getImmutable();
        byte [] za= sha1(users+XA.toString()+QA.toString()+U.toString()+H_3.toString()+c.toString());
//        Element Za = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(za)).getImmutable();
        Element Za=bp.getZr().newElementFromHash(za,0,za.length).getImmutable();
        byte[] ha = sha1(users+XA.toString()+P.toString()+P_pub.toString());
//        Element Ha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ha)).getImmutable();
        Element Ha=bp.getZr().newElementFromHash(ha,0,ha.length).getImmutable();

        Element M1= QA.powZn(La);
        Element M2 = (P_pub.powZn(Ha).add(XA)).powZn(Za);
        Element M = (M2.add(M1)).powZn(H_3);


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
        Element u= bp.getZr().newRandomElement().getImmutable();
       // Element t= bp.getZr().newRandomElement().getImmutable();
//        Element K = P.powZn(u);
       // Element T = P.powZn(t);
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);

        String sendX = pkp.getProperty("Q"+users);
        String sendY =pkp.getProperty("T"+users);
        Element QA = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendX)).getImmutable();
        Element TA = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();

        byte[] BH_A = sha1(users+TA.toString()+P.toString()+P_pub.toString());
        Element H_A=bp.getZr().newElementFromHash(BH_A,0,BH_A.length).getImmutable();

        Element U = QA.add(TA).add(P_pub.powZn(H_A)).powZn(u);




        String rectX = pkp.getProperty("Q"+rec);
        String rectY =pkp.getProperty("T"+rec);
        Element QB = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();
        Element TB = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();
        byte[] BH_B = sha1(rec+TB.toString()+P.toString()+P_pub.toString());
        Element H_B=bp.getZr().newElementFromHash(BH_B,0,BH_B.length).getImmutable();


        String sendx = skp.getProperty("d"+users);
        String sendy =skp.getProperty("x"+users);
        Element da = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendx)).getImmutable();
        Element xa = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendy)).getImmutable();
        Element OP1= QB.add(TB.add(P_pub.powZn(H_B))).powZn(xa.add(da)).powZn(u);
        byte[] BK = sha1(rec+U.toString()+OP1.toString());
        Element K=bp.getZr().newElementFromHash(BK,0,BK.length).getImmutable();
        //
        byte[] BH_3 = sha1(rec+K.toString()+QB.toString()+TB.toString());
        Element H_3=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();
        byte[] messageByte = messages.getBytes();
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ BK[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);
//        //签名
        //  5/12 17点 剩余还没有做。。



        byte [] la = sha1(users+rec+TA.toString()+QA.toString()+U.toString()+H_3.toString()+c.toString());
        byte [] za = sha1(users+TA.toString()+QA.toString()+U.toString()+H_3.toString()+c.toString());
        Element La=bp.getZr().newElementFromHash(la,0,la.length).getImmutable();
        Element Za=bp.getZr().newElementFromHash(za,0,za.length).getImmutable();

        Element sign = u.powZn(xa.add(da)).powZn(La.powZn(xa).add(Za.powZn(da)).invert());


        //将消息保存下来
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("U"+users, Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toString().getBytes()));
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
        Element Q = P.powZn(x).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("Q"+user,Base64.getEncoder().encodeToString(Q.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));

        //KGC生成私钥
        Element a= bp.getZr().newRandomElement().getImmutable();
        Element T=P.powZn(a).getImmutable();
        byte[] BH_1 = sha1(user+T.toString()+P.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element d_ID = a.add(H_1.powZn(s)).getImmutable();
        //将公钥对保存下来。
        //生成私钥和公钥对
        //H1不能存储。
        pkp.setProperty("T"+user,Base64.getEncoder().encodeToString(T.toBytes()));
        skp.setProperty("d"+user,Base64.getEncoder().encodeToString(d_ID.toBytes()));
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


