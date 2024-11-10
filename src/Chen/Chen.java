package Chen;

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

public class Chen {
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Chen/";
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


            offlinesignCrypt(pairingParametersFileName, publicParameterFileName, mskFileName,skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            onlinesignCrypt(pairingParametersFileName, publicParameterFileName, mskFileName,skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);


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

        Properties SigC = loadPropFromFile(signCryptFileName);
        String x1_S =skp.getProperty("x1"+users);
        Element x1s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String x2_S =skp.getProperty("x2"+users);
        Element x2s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x2_S)).getImmutable();
        String X1_S = pkp.getProperty("X1"+users);
        String X2_S = pkp.getProperty("X2"+users);
        Element X1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X1_S)).getImmutable();
        Element X2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X2_S)).getImmutable();
        String X1_R = pkp.getProperty("X1"+rec);
        String X2_R = pkp.getProperty("X2"+rec);
        Element X1R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X1_R)).getImmutable();
        Element X2R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X2_R)).getImmutable();

        Properties sigC=loadPropFromFile(signCryptFileName);

        String C1S = sigC.getProperty("C1"+users);
        Element C1= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1S)).getImmutable();

        String D_R = skp.getProperty("D"+rec);
        Element DR= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D_R)).getImmutable();

        String C2S = sigC.getProperty("C2"+users);
        Element C2= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2S)).getImmutable();

        String CS = sigC.getProperty("C"+users);
        Element C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(CS)).getImmutable();


        String C3S = sigC.getProperty("C3"+users);
        Element C3= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(C3S)).getImmutable();


        String ts = sigC.getProperty("t"+users);
        Element t= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ts)).getImmutable();

        String TS = sigC.getProperty("T"+users);
        Element T= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TS)).getImmutable();


        String r2s = sigC.getProperty("r2"+users);
        Element r2= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r2s)).getImmutable();

        String alphaS = sigC.getProperty("alpha"+users);
        Element alpha= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaS)).getImmutable();
        String beltaS = sigC.getProperty("belta"+users);
        Element belta= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(beltaS)).getImmutable();

        String yS = sigC.getProperty("y"+users);
        Element y= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yS)).getImmutable();



        Element W = bp.pairing(C1.powZn(C3).add(C2),DR);

        byte[] k_3 = sha1(X1S.toString()+X2S.toString()+W.toString()+X1R.toString()+X2R.toString()+X1R.powZn(x1s).toString()+X2R.powZn(x1s).toString());
        Element k=bp.getZr().newElementFromHash(k_3,0,k_3.length).getImmutable();


        byte [] message =new byte[C.toString().length()];


        for (int i=0;i< k_3.length;i++){
            message[i] = (byte) (C2.toString().charAt(i) ^ k_3[i]);
        }


    }

    private static void onlinesignCrypt(String pairingParametersFileName, String publicParameterFileName, String mskFileName,String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        String gStr = pubProp.getProperty("g");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element g = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        String x1_S =skp.getProperty("x1"+users);
        Element x1s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String x2_S =skp.getProperty("x2"+users);
        Element x2s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x2_S)).getImmutable();
        String X1_S = pkp.getProperty("X1"+users);
        String X2_S = pkp.getProperty("X2"+users);
        Element X1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X1_S)).getImmutable();
        Element X2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X2_S)).getImmutable();
        String X1_R = pkp.getProperty("X1"+rec);
        String X2_R = pkp.getProperty("X2"+rec);
        Element X1R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X1_R)).getImmutable();
        Element X2R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X2_R)).getImmutable();

        Properties sigC=loadPropFromFile(signCryptFileName);

        String C1S = sigC.getProperty("C1"+users);
        Element C1= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1S)).getImmutable();

        String C2S = sigC.getProperty("C2"+users);
        Element C2= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2S)).getImmutable();

        String TS = sigC.getProperty("T"+users);
        Element T= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TS)).getImmutable();

        String WS = sigC.getProperty("W"+users);
        Element W= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(WS)).getImmutable();
        String r2s = sigC.getProperty("r2"+users);
        Element r2= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r2s)).getImmutable();

        String alphaS = sigC.getProperty("alpha"+users);
        Element alpha= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaS)).getImmutable();
        String beltaS = sigC.getProperty("belta"+users);
        Element belta= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(beltaS)).getImmutable();

        String yS = sigC.getProperty("y"+users);
        Element y= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yS)).getImmutable();

        byte[] BH_1 = sha1(rec+X1R.toString()+X2R.toString());
        Element qR=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element C3 = alpha.mul(qR.sub(belta));

        byte[] BH_3 = sha1(X1S.toString()+X2S.toString()+W.toString()+X1R.toString()+X2R.toString()+X1R.powZn(x1s).toString()+X2R.powZn(x1s).toString());
        Element k=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();


        byte[] h_3 = sha1(messages+r2.toString()+users);

        byte[] messageByte = messages.getBytes();
        byte[] ci =new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){

            ci[j] = (byte)(messageByte[j] ^ h_3[j]);
        }

        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        byte[] h_4 = sha1(C3.toString()+c.toString()+r2.toString()+users+rec+C1.toString()+C2.toString()+X1S.toString()+X2S.toString()+X1R.toString()+X2R.toString());

        Element h=bp.getZr().newElementFromHash(h_4,0,h_4.length).getImmutable();

        Element t = y.mul(x2s.add(h));


        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toBytes()));
        sigC.setProperty("C3"+users, Base64.getEncoder().encodeToString(C3.toBytes()));
        sigC.setProperty("t"+users, Base64.getEncoder().encodeToString(t.toBytes()));

        storePropToFile(sigC,signCryptFileName);

    }
        private static void offlinesignCrypt(String pairingParametersFileName, String publicParameterFileName, String mskFileName,String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        String gStr = pubProp.getProperty("g");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element g = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();


        String x1_S =skp.getProperty("x1"+users);
        Element x1s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x1_S)).getImmutable();
        String X1_S = pkp.getProperty("X1"+users);
        String X2_S = pkp.getProperty("X2"+users);
        String D_S = skp.getProperty("D"+users);
        Element X1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X1_S)).getImmutable();
        Element X2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(X2_S)).getImmutable();
        Element DS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D_S)).getImmutable();
        //发送方的操作


        //首先随机生成随机数。

        Element r1 = bp.getZr().newRandomElement().getImmutable();
        Element r2 = bp.getZr().newRandomElement().getImmutable();
        Element belta = bp.getZr().newRandomElement().getImmutable();
        Element y = bp.getZr().newRandomElement().getImmutable();


        byte[] H_1m = sha1(r2.toString()+users+X1S.toString()+X2S.toString());

        Element alpha = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        Element W = g.powZn(r1);

        Element C1 = P.powZn(r1.add(alpha.invert()));

        Element C2 = P.powZn(r1.mul(belta.add(s)));

        Element T = DS.powZn(x1s.mul(y.invert()));

        Properties sigC=loadPropFromFile(signCryptFileName);

        sigC.setProperty("C1"+users, Base64.getEncoder().encodeToString(C1.toBytes()));
        sigC.setProperty("C2"+users, Base64.getEncoder().encodeToString(C2.toBytes()));
        sigC.setProperty("alpha"+users, Base64.getEncoder().encodeToString(alpha.toString().getBytes()));
        sigC.setProperty("belta"+users, Base64.getEncoder().encodeToString(belta.toString().getBytes()));
        sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toString().getBytes()));
        sigC.setProperty("y"+users,Base64.getEncoder().encodeToString(y.toString().getBytes()));
        sigC.setProperty("r2"+users,Base64.getEncoder().encodeToString(r2.toString().getBytes()));
        sigC.setProperty("W"+users, Base64.getEncoder().encodeToString(W.toBytes()));

        sigC.setProperty("r2"+users, Base64.getEncoder().encodeToString(r2.toBytes()));
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


        String rectX2 =pkp.getProperty("X2"+user);
        Element X2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX2)).getImmutable();

        byte[] BH_1 = sha1(user+X2.toString());
        Element q=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element D = P.powZn(q.add(s).invert());
        //获取随机数
        skp.setProperty("D"+user,Base64.getEncoder().encodeToString(D.toBytes()));
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

        Element x1 = bp.getZr().newRandomElement().getImmutable();
        Element x2 = bp.getZr().newRandomElement().getImmutable();
        Element X1 = P.powZn(x1).getImmutable();
        Element X2 = P.powZn(x2).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("X1"+user,Base64.getEncoder().encodeToString(X1.toBytes()));
        pkp.setProperty("X2"+user,Base64.getEncoder().encodeToString(X2.toBytes()));
        skp.setProperty("x1"+user,Base64.getEncoder().encodeToString(x1.toBytes()));
        skp.setProperty("x2"+user,Base64.getEncoder().encodeToString(x2.toBytes()));
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
        Element g= bp.pairing(P,P);
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        storePropToFile(pubProp, publicParameterFileName);
    }
}
