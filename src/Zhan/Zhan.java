package Zhan;

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

public class Zhan {
    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Zhan/";
        String pairingParametersFileName = dir + "a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";

        for (int j = 0; j < 10; j++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            Partial(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[j], pkFileName, skFileName);
            Partial(pairingParametersFileName, publicParameterFileName, mskFileName, users[j], pkFileName, skFileName);
            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[j], users[j], signCryptFileName,rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,users[j],rec);
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
//  Properties sigC=loadPropFromFile(signCryptFileName);
//        sigC.setProperty("c"+users, Base64.getEncoder().encodeToString(c.toBytes()));
//        sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
//        sigC.setProperty("alpha"+users, Base64.getEncoder().encodeToString(alpha.toBytes()));
//        sigC.setProperty("Belta"+users, Base64.getEncoder().encodeToString(Belta.toBytes()));
//        sigC.setProperty("mathx"+users, Base64.getEncoder().encodeToString(mathx.toBytes()));
//        sigC.setProperty("mathy"+users, Base64.getEncoder().encodeToString(mathy.toBytes()));
//        sigC.setProperty("W"+users, Base64.getEncoder().encodeToString(W.toBytes()));
//        sigC.setProperty("Z"+users, Base64.getEncoder().encodeToString(Z.toBytes()));

        String cm = SigC.getProperty("c"+users);
        Element  C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cm)).getImmutable();

        String Km = SigC.getProperty("K"+users);
        Element  K= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km)).getImmutable();

        String alpham = SigC.getProperty("alpha"+users);
        Element  alpha= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alpham)).getImmutable();

        String Beltam = SigC.getProperty("Belta"+users);
        Element  Belta= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Beltam)).getImmutable();

        String mathxm = SigC.getProperty("mathx"+users);
        Element  mathx= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mathxm)).getImmutable();

        String mathym = SigC.getProperty("mathy"+users);
        Element  mathy= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mathym)).getImmutable();

        String Wm = SigC.getProperty("W"+users);
        Element  W= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Wm)).getImmutable();

        String Zm = SigC.getProperty("Z"+users);
        Element  Z= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Zm)).getImmutable();

        String Tagm = SigC.getProperty("Tag"+users);
        Element  Tag= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tagm)).getImmutable();

        String Skeym = SigC.getProperty("Skey"+users);
        Element  skey= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Skeym)).getImmutable();

        P.powZn(Belta).isEqual(K.powZn(alpha).add(Tag));

        String xm = skp.getProperty("x"+rec);
        Element  x= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();

        String dm = skp.getProperty("d"+rec);
        Element  d= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dm)).getImmutable();

        Element V = K.powZn(x.add(d));
        byte[] BH_1 = sha1(V.toString()+K.toString());
        Element Skey =bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        if(Skey.isEqual(skey)){
            System.out.println("验证成功");
        }

        byte[] ci = new byte[C.toBytes().length];
        byte [] mi = new byte[ci.length];
        for (int j = 0; j <ci.length; j++){
            mi[j] = (byte)(ci[j] ^ BH_1[j]);
        }

    }



    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
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

        //发送方的操作
        byte[] BH_1 = sha1(rec+XR.toString()+YR.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        //首先随机生成两个随机数。
        Element k= bp.getZr().newRandomElement().getImmutable();
        Element K = P.powZn(k);

        Element V = (XR.add(YR.add(P_pub.powZn(H_1)))).powZn(k);


        Element Tag = P.powZn(xS.add(dS));

        byte[] Skey = sha1(V.toString()+K.toString());

        Element Skeyoption =bp.getZr().newElementFromHash(Skey,0,Skey.length).getImmutable();
        byte[] messageByte = messages.getBytes();
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ Skey[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        Element R =bp.getG1().newRandomElement().getImmutable();

        byte[] BH_3 = sha1(users+R.toString()+ XS.toString()+YS.toString()+P_pub.toString()+K.toString()+c.toString());
        Element H_3=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();


        Element alpha = H_3.add(k.mul(xS)).mul(xS.add(dS));

        Element Belta  = alpha.mul(k.mul(xS)).add(xS).add(dS);

        Element mathx = H_3.mul(xS.add(dS).add(xS.mul(dS))).div(k.mul(xS)).add(xS.add(dS));

        Element mathy = H_3.mul(xS.add(dS).add(xS.div(dS))).div(k.mul(xS).mul(dS)).add(xS.add(dS).div(dS));

        Element W = P.powZn(H_3.mul(xS).mul(dS));

        Element Z = P_pub.powZn(H_3.mul(xS).div(dS));


        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("c"+users, Base64.getEncoder().encodeToString(c.toBytes()));
        sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
        sigC.setProperty("alpha"+users, Base64.getEncoder().encodeToString(alpha.toBytes()));
        sigC.setProperty("Belta"+users, Base64.getEncoder().encodeToString(Belta.toBytes()));
        sigC.setProperty("mathx"+users, Base64.getEncoder().encodeToString(mathx.toBytes()));
        sigC.setProperty("mathy"+users, Base64.getEncoder().encodeToString(mathy.toBytes()));
        sigC.setProperty("W"+users, Base64.getEncoder().encodeToString(W.toBytes()));
        sigC.setProperty("Z"+users, Base64.getEncoder().encodeToString(Z.toBytes()));
        sigC.setProperty("Tag"+users, Base64.getEncoder().encodeToString(Tag.toBytes()));
        sigC.setProperty("Skey"+users, Base64.getEncoder().encodeToString(Skeyoption.toBytes()));
        storePropToFile(sigC,signCryptFileName);
    }


    public static void Partial(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");

        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();

        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        String rectX =pkp.getProperty("X"+user);
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();

        //获取随机数
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element Y = P.powZn(y).getImmutable();
        byte[] BH_1 = sha1(user+X.toString()+Y.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element d = y.add(H_1.mul(s)).getImmutable();

        if(P.powZn(d).equals(Y.add(P_pub.powZn(H_1)))){
            System.out.println("注册成功");
        }

        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
        skp.setProperty("d"+user,Base64.getEncoder().encodeToString(d.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);
    }
    public static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");

        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();

        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("X"+user,Base64.getEncoder().encodeToString(X.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));

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
