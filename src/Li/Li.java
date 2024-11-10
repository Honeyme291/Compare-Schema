package Li;

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

public class Li {
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Li/";
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
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[j], pkFileName, skFileName);
            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[j], users[j], signCryptFileName,rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[j],rec);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);
        }

    }


    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName,String signCryptFileName, String users,String rec) throws NoSuchAlgorithmException {
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
        Element xcc =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String ym = skp.getProperty("y"+rec);
        Element ycc =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ym)).getImmutable();

        String Xm = pkp.getProperty("X"+rec);
        Element Xcc =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Xm)).getImmutable();
        String AIDm = pkp.getProperty("AID2"+rec);
        Element AID2cc =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AIDm)).getImmutable();


        String Xmi = pkp.getProperty("X"+users);
        Element Xi =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Xmi)).getImmutable();

        String Ymi = pkp.getProperty("Y"+users);
        Element Yi =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ymi)).getImmutable();

        String AIDmi = pkp.getProperty("AID2"+users);
        Element AID2 =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(AIDmi)).getImmutable();

        String qm = SigC.getProperty("q"+users);
        Element q =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(qm)).getImmutable();

        String cm = SigC.getProperty("C"+users);
        Element c =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cm)).getImmutable();

        String Km = SigC.getProperty("K"+users);
        Element K =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km)).getImmutable();

        String Vm = SigC.getProperty("V"+users);
        Element V =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Vm)).getImmutable();

        String Tm = SigC.getProperty("T"+users);
        Element T =bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm)).getImmutable();

        byte[] BH_3 = sha1(AID2.toString()+Xi.toString());
        Element H_3i=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();

        byte[] BH_3c = sha1(AID2cc.toString()+Xcc.toString());
        Element H_3cc=bp.getZr().newElementFromHash(BH_3c,0,BH_3c.length).getImmutable();

        byte[] BH_5 = sha1(rec+AID2.toString()+K.toString()+c.toString());
        Element H_5i=bp.getZr().newElementFromHash(BH_5,0,BH_5.length).getImmutable();

        //验证操作：
        P.powZn(q).isEqual(K.add(V).add(T));


        byte[] BH_4 = sha1(K.powZn(ycc.add(H_3cc.mul(xcc))).toString());
        Element H_4i=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();

        byte[] messageByte =new byte[c.toBytes().length];
        for (int j = 0; j < c.toBytes().length; j++){

            messageByte[j] = (byte)( c.toBytes()[j]^ BH_4[j]);
        }

        for (int j = 0; j <users.length(); j++){
            messageByte[j] = (byte)( c.toBytes()[j]^ BH_4[j]);
        }

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
        Element K = P.powZn(k);

        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        String rectX = pkp.getProperty("X"+rec);
        String rectY =pkp.getProperty("Y"+rec);
        String AID2m = pkp.getProperty("AID2"+users);
        String snedX = pkp.getProperty("X"+users);
        String snedY = pkp.getProperty("Y"+users);
        String snedx = skp.getProperty("x"+users);
        String snedy = skp.getProperty("y"+users);
        Element Xcc = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();
        Element Ycc = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();
        Element AID2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AID2m)).getImmutable();
        Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(snedX)).getImmutable();
        Element Yi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(snedY)).getImmutable();
        Element yi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(snedy)).getImmutable();
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(snedx)).getImmutable();

        byte[] BH_1i = sha1(AID2+Xi.toString()+P_pub.toString());
        Element H_1i=bp.getZr().newElementFromHash(BH_1i,0,BH_1i.length).getImmutable();

        byte[] BH_1 = sha1(rec+Xcc.toString()+P_pub.toString());
        Element H_1cc=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        byte[] BH_4 = sha1(Ycc.add(P_pub.powZn(H_1cc)).toString());
        Element H_4i=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();

        byte[] messageByte = messages.getBytes();
        byte[] ci =new byte[messageByte.length+users.length()];
        for (int j = 0; j < messageByte.length; j++){

            ci[j] = (byte)(messageByte[j] ^ BH_4[j]);
        }

        for (int j = 0; j <users.length(); j++){

            ci[messageByte.length+j] = (byte)(users.charAt(j) ^ BH_4[j]);
        }

        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        byte[] BH_3 = sha1(AID2.toString()+Xi.toString());
        Element H_3i=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();

        byte[] BH_5 = sha1(rec+AID2.toString()+K.toString()+c.toString());
        Element H_5i=bp.getZr().newElementFromHash(BH_5,0,BH_5.length).getImmutable();

        Element V = Yi.powZn(H_5i).add(P_pub.powZn(H_5i.mul(H_1i)));
        Element T = Xi.powZn(H_5i.mul(H_3i));
        Element q = k.add(H_5i.mul(yi.add(H_3i.mul(xi))));

        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toBytes()));
        sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
        sigC.setProperty("q"+users, Base64.getEncoder().encodeToString(q.toBytes()));
        sigC.setProperty("V"+users, Base64.getEncoder().encodeToString(V.toBytes()));
        sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toBytes()));
        storePropToFile(sigC,signCryptFileName);
    }

    public static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {

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

        Element g= bp.getZr().newRandomElement().getImmutable();
        Element AID1 = P.powZn(g).getImmutable();

        Element x= bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //KGC执行的操作
        byte[] option = sha1(AID1.powZn(s).toString());

        byte[] AID2m = new byte[user.toString().length()];
        byte [] AID2k = new byte[user.toString().length()];

        for (int i=0;i<AID2k.length;i++){
            AID2k[i] = (byte)(AID2m[i] ^ option[i]);
        }
        Element AID2p = bp.getZr().newElementFromHash(AID2k,0,AID2k.length);
        String AID2 = AID2p.toString();
        //将公钥存储起来。
        pkp.setProperty("AID1"+user,Base64.getEncoder().encodeToString(AID1.toBytes()));
        pkp.setProperty("AID2"+user,Base64.getEncoder().encodeToString(AID2.getBytes()));
        pkp.setProperty("X"+user,Base64.getEncoder().encodeToString(X.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));

        Element w= bp.getZr().newRandomElement().getImmutable();
        Element W = P.powZn(w).getImmutable();


        byte[] BH_1 = sha1(AID2+X.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        byte[] BH_2 = sha1(AID2+W.toString()+P_pub.toString());
        Element H_2=bp.getZr().newElementFromHash(BH_2,0,BH_2.length).getImmutable();

        Element d = w.add(s.mul(H_1).add(H_2));


        //KGC生成私钥
      if(P.powZn(d).isEqual(W.add(P_pub.powZn(H_1).add(P.powZn(H_2))))){
          System.out.println("密钥生成成功");
      }

      Element y = d.sub(H_2);
      byte[] BH_3 = sha1(AID2+X.toString());
      Element H_3=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();
      Element Y = W.add(X.powZn(H_3));



      pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
      skp.setProperty("y"+user,Base64.getEncoder().encodeToString(y.toBytes()));
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
