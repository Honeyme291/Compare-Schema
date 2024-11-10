package Yu;

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

public class Yu {
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Yu/";
        String pairingParametersFileName = "E:/java program/CLSC-Lxx/Compare-Schema/database/Yu/a.properties";
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
            for (int i=0;i< users.length;i++){
                KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            }
            for (int i = 0; i < users.length; i++) {
                Extract(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            }
            Extract(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);

            for(int i=0;i<users.length;i++){
                signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            }
            for(int i=0;i<users.length;i++) {
                Aggregation(pairingParametersFileName, signCryptFileName, users);
            }
            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users,rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users,rec);;

//            unsignCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, users, signCryptFileName, 2);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println((end - start));

        }
    }

    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName,String signCryptFileName, String[] users,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp =loadPropFromFile(skFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        //验证操作
        Element[] M = new Element[users.length];
        Element [] F = new Element[users.length];
        Element [] U = new Element[users.length];
        Element [] Y = new Element[users.length];
        String [] Ym = new String[users.length];
        String [] Um  =new String[users.length];
        String [] Mm = new String[users.length];
        String [] Fm = new String[users.length];
        Element [] H_2 = new Element[users.length];
        Element [] H_1 = new Element[users.length];
        byte[][] H_2m =new byte[users.length][];
        byte[][] H_1m =new byte[users.length][];
        String[]  ci = new String[users.length];




        String Sign = sigC.getProperty("signSum");
        Element u= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Sign));
        String rects = skp.getProperty("s"+rec);
        String rectw =skp.getProperty("w"+rec);
        Element sr=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rects));
        Element sw =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rectw));
        Element[] V = new Element[users.length];
        for (int i=0;i< users.length;i++){
            Fm[i] =sigC.getProperty("F"+users[i]);
            F[i] = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Fm[i])).getImmutable();
            V[i]=  F[i].powZn(sr.add(sw));
        }

        byte[][] h_3 = new byte[users.length][];

        for (int i=0;i< users.length;i++){
            h_3[i]=sha1(V.toString()+F[i].toString());
        }

        for(int i=0;i< users.length;i++){
            ci[i] =sigC.getProperty("C"+users[i]);
        }
        byte[] [] m =new byte[users.length][ci[0].length()];

        for(int i=0;i< users.length;i++){
            for (int j=0;j< ci.length;j++){
                m[i][j] = (byte) (ci[i].charAt(j) ^ h_3[i][j]);
            }
        }
        for(int i=0;i<users.length;i++){
            M[i]=bp.getZr().newElementFromBytes(m[i],m[i].length);
        }
    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName,String signCryptFileName, String[] users,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp =loadPropFromFile(skFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        //验证操作
        Element[] M = new Element[users.length];
        Element [] F = new Element[users.length];
        Element [] U = new Element[users.length];
        Element [] Y = new Element[users.length];
        String [] Ym = new String[users.length];
        String [] Um  =new String[users.length];
        String [] Mm = new String[users.length];
        String [] Fm = new String[users.length];
        Element [] H_2 = new Element[users.length];
        Element [] H_1 = new Element[users.length];
        byte[][] H_2m =new byte[users.length][];
        byte[][] H_1m =new byte[users.length][];
        String[]  ci = new String[users.length];




        String Sign = sigC.getProperty("signSum");
        Element u= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Sign));
        String rects = skp.getProperty("s"+rec);
        String rectw =skp.getProperty("w"+rec);
        Element sr=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rects));
        Element sw =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rectw));
        Element[] V = new Element[users.length];
        for (int i=0;i< users.length;i++){
          Fm[i] =sigC.getProperty("F"+users[i]);
          F[i] = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Fm[i])).getImmutable();
          V[i]=  F[i].powZn(sr.add(sw));
      }





        byte[][] h_3 = new byte[users.length][];

       for (int i=0;i< users.length;i++){
           h_3[i]=sha1(V.toString()+F[i].toString());
       }

        for(int i=0;i< users.length;i++){
            ci[i] =sigC.getProperty("C"+users[i]);
        }
        byte[] [] m =new byte[users.length][ci[0].length()];

        for(int i=0;i< users.length;i++){
            for (int j=0;j< ci.length;j++){
                m[i][j] = (byte) (ci[i].charAt(j) ^ h_3[i][j]);
            }
        }
        for(int i=0;i<users.length;i++){
            M[i]=bp.getZr().newElementFromBytes(m[i],m[i].length);
        }
        for (int i=0;i<users.length;i++){
             Ym[i]=pkp.getProperty("Y"+users[i]);
             Y[i]=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ym[i])).getImmutable();

        }

        for (int i=0;i< users.length;i++){
             H_1m[i] = sha1(rec+Y.toString());
             H_1[i]=bp.getZr().newElementFromHash(H_1m[i], 0,H_1m[i].length).getImmutable();

        }

        for (int i=0;i<users.length;i++){
            Um[i]=pkp.getProperty("U"+users[i]);
            U[i]=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Um[i])).getImmutable();

        }

        for (int i=0;i<users.length;i++){
            H_2m[i] = sha1(M[i].toString()+F[i].toString());
            H_2[i]= bp.getZr().newElementFromHash(H_2m[i],0,H_2m[i].length).getImmutable();
        }

        Element option0 = H_2[0];
        for(int i=1;i< users.length;i++){
            option0.powZn(H_2[i]);
        }

        Element option1=U[0];
        for (int i=1;i< users.length;i++){
            option1.add(U[i]);
        }

        Element option3 = P_pub.powZn(H_1[0]);

        for (int i=1;i< users.length;i++){
            option3.add(P_pub.powZn(H_1[i]));
        }

        Element option4 =Y[0];

        for (int i=1;i< users.length;i++){
            option4.add(Y[i]);
        }
        Element option = option1.add(option3).add(option4);
        option = option.powZn(option0);

        if(P.powZn(u).equals(option)){
            System.out.println("验证成功");
        }

    }

    private static void Aggregation(String pairingParametersFileName, String signCryptFileName,String[] users) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        String[] sign1 = new String[users.length];
        Element[] sign = new Element[users.length];
        for (int i=0;i<users.length;i++){
            sign1[i]=sigC.getProperty("u"+users[i]);
        }
        for(int i=0;i<users.length;i++){
            sign[i]= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sign1[i])).getImmutable();
        }
        for (int i=1;i<users.length;i++){
            sign[0]=sign[0].add(sign[i]);
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
        Element f= bp.getZr().newRandomElement().getImmutable();
        Element F = P.powZn(f);

        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);
        String rectU = pkp.getProperty("U"+rec);
        String rectY =pkp.getProperty("Y"+rec);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectU)).getImmutable();
        Element Y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();

//        String sendX = pkp.getProperty("X"+users);
//        String sendY =pkp.getProperty("Y"+users);
//        Element SX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendX)).getImmutable();
//        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();

        byte[] BH_1 = sha1(rec+Y.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element V = (U.add(P_pub.powZn(H_1).add(Y))).powZn(f);

        byte [] h_3 = sha1(V.toString()+F.toString());


        byte[] messageByte = messages.getBytes();
        byte[] ci =new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){

            ci[j] = (byte)(messageByte[j] ^ h_3[j]);
        }

        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);


        String sendw = skp.getProperty("w"+users);
        String sends =skp.getProperty("s"+users);
        Element w = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendw)).getImmutable();
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sends)).getImmutable();

        byte [] mu1 =sha1(messages+F.toString());

        Element mu =bp.getZr().newElementFromHash(mu1,0,mu1.length);

        Element u = mu.powZn(w.add(s)).add(f);

        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("F"+users, Base64.getEncoder().encodeToString(F.toBytes()));
        sigC.setProperty("u"+users, Base64.getEncoder().encodeToString(u.toBytes()));
        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(c.toString().getBytes()));
        storePropToFile(sigC,signCryptFileName);
    }


    public static void Extract(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException{
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
        String s_istr=mskPro.getProperty("x");
        Element x=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        String rectY =pkp.getProperty("Y"+user);
        Element Y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();

        //获取随机数
        Element v = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(v).getImmutable();
        byte[] BH_1 = sha1(user+Y.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element s = v.add(H_1.powZn(x)).getImmutable();

        Element R =P.powZn(s).add(Y.powZn(v));
        pkp.setProperty("R"+user,Base64.getEncoder().encodeToString(R.toBytes()));
        pkp.setProperty("U"+user,Base64.getEncoder().encodeToString(U.toBytes()));
        skp.setProperty("s"+user,Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(pkp,pkFileName);
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

        Element w = bp.getZr().newRandomElement().getImmutable();
        Element Y = P.powZn(w).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
        skp.setProperty("w"+user,Base64.getEncoder().encodeToString(w.toBytes()));

        //KGC生成私钥
//        Element u= bp.getZr().newRandomElement().getImmutable();
//        Element Y=P.powZn(u).getImmutable();
//
//
//
//        //将公钥对保存下来。
//        //生成私钥和公钥对
//        //H1不能存储。
//        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
//        skp.setProperty("y"+user,Base64.getEncoder().encodeToString(y.toBytes()));
////        pkp.setProperty("H1_"+ID_i, H_1.toString());
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }

    public static void setup(String pairingParametersFileName, String publicParameterFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置KGC主私钥s

        Element x = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));
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
