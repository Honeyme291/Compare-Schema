package Mohammed;

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

public class Mohammed{
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
        String dir = "E:/java program/CLSC-Lxx/Compare-Schema/database/Mohammed/";
        String pairingParametersFileName = "E:/java program/CLSC-Lxx/Compare-Schema/database/Mohammed/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int j = 0; j < 10; j++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            for (int i = 0; i < users.length; i++) {
                PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            }
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            for (int i = 0; i < users.length; i++) {
                KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            }
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);

            for(int i=0;i< users.length;i++){
                signCrypt1(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            }
            for(int i=0;i< users.length;i++){
                signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            }
            for(int i=0;i<users.length;i++){
                UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,users[i],rec);
            }
            for (int i=0;i< users.length;i++){
                Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users[i],rec,messages[i]);
            }


//            unsignCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, users, signCryptFileName, 2);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println((end - start));

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

        String xm = skp.getProperty("sk"+users);
        Element sk =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String C1m = SigC.getProperty("C1"+users);
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1m)).getImmutable();
        String C2m = SigC.getProperty("C2"+users);
        Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2m)).getImmutable();
        String C3m = SigC.getProperty("C3"+users);
        Element C3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C3m)).getImmutable();
        String C4m = SigC.getProperty("C4"+users);
        Element C4 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C4m)).getImmutable();

        Element C0p = bp.pairing(P.powZn(sk),C1);

        byte [] H_2 =sha1(C0p.toString());

        byte [] message =new byte[C2.toString().length()];

        for (int i=0;i< C2.toString().length();i++){
            message[i] = (byte) (C2.toString().charAt(i) ^ H_2[i]);
        }


    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String signCryptFileName, String users,String rec,String messages) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        //验证操作
        String C4m = sigC.getProperty("C4"+users);
        Element C4 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C4m)).getImmutable();
        String C1m = sigC.getProperty("C1"+users);
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1m)).getImmutable();
        String Tm = sigC.getProperty("T"+users);
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm)).getImmutable();

        String C2m = sigC.getProperty("C2"+users);
        Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2m)).getImmutable();
        String C3m = sigC.getProperty("C3"+users);
        Element C3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C3m)).getImmutable();


        Element option = bp.pairing(C1,T);

        byte [] C5m = sha1(option.toString());

        byte [] mess = new byte[C4m.length()];

        for (int i=0;i<C4m.length();i++){
            mess[i] = (byte)( C2m.charAt(i)^C5m[i] );
        }

        for (int i=0;i<C4m.length();i++){
            mess[i] = (byte)( C1m.charAt(i)^C5m[i] );
        }
        for (int i=0;i<C4m.length();i++){
            mess[i] = (byte)( C4m.charAt(i)^C5m[i] );
        }
        if (mess.equals(messages)){
            System.out.println("验证成功");
        }


    }

    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String pkm =pkp.getProperty("pk"+users);
        Element pk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkm)).getImmutable();
        String Qm =pkp.getProperty("Q"+users);
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Qm)).getImmutable();

        String skm = skp.getProperty("sk"+users);

        Element sk = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(skm)).getImmutable();
        //发送方的操作

        //首先随机生成随机数。
        Properties sigC=loadPropFromFile(signCryptFileName);
        String r1m = sigC.getProperty("r1"+users);
        Element r1 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r1m)).getImmutable();
        String r2m=sigC.getProperty("r2"+users);
        Element r2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r2m)).getImmutable();
        String r3m=sigC.getProperty("r3"+users);
        Element r3 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r3m)).getImmutable();
        String H_2=sigC.getProperty("H_2"+users);

        Element H_2m = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(H_2)).getImmutable();





        //计算参数

        Element C0 = bp.pairing(pk,P.powZn(Q.powZn(r1)));
        Element C1= P.powZn(r1);
        String C2m = new String();
        C2m = H_2m.toString();

        Element C2 = bp.getZr().newElementFromBytes(C2m.getBytes(),C2m.length());

        byte[] H_1m = sha1(messages+r2.toString());
        byte [] H_3m = sha1(C1.toString());

        Element H_1 = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        Element H_3 = bp.getZr().newElementFromHash(H_3m,0,H_3m.length);

        Element C3 = r1.powZn(H_1).add(sk.powZn(H_3));

        byte[] H_mum = sha1(C0.powZn(r3).toString());

        Element H_mu = bp.getZr().newElementFromHash(H_mum,0,H_mum.length);

        byte [] op  =new byte[messages.length()];

        for (int i=0;i<messages.length();i++){
            op[i] = (byte) (messages.charAt(i)^H_mum[i]);
        }

        Element C4 = bp.getZr().newElementFromBytes(op,op.length).getImmutable();
        Element T = r3.powZn(sk);


        sigC.setProperty("C1"+users, Base64.getEncoder().encodeToString(C1.toBytes()));
        sigC.setProperty("C2"+users, Base64.getEncoder().encodeToString(C2.toBytes()));
        sigC.setProperty("C3"+users, Base64.getEncoder().encodeToString(C3.toString().getBytes()));
        sigC.setProperty("C4"+users, Base64.getEncoder().encodeToString(C4.toString().getBytes()));
        sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toString().getBytes()));

        storePropToFile(sigC,signCryptFileName);
    }

    private static void signCrypt1(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String pkm =pkp.getProperty("pk"+users);
        Element pk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkm)).getImmutable();
        String Qm =pkp.getProperty("Q"+users);
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Qm)).getImmutable();

        String skm = skp.getProperty("sk"+users);

        Element sk = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(skm)).getImmutable();

        Element r1= bp.getZr().newRandomElement().getImmutable();
        Element r2= bp.getZr().newRandomElement().getImmutable();
        Element r3= bp.getZr().newRandomElement().getImmutable();

        Element C0 = bp.pairing(pk,P.powZn(Q.powZn(r1)));

        Element C1= P.powZn(r1);
        byte [] r1m = r1.toBytes();

        byte [] H_2m = sha1(C0.toString());
        for(int i=0;i< H_2m.length;i++) {
            H_2m[i] = (byte) (H_2m[i] ^ r1m[i]);
        }
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("r1"+users, Base64.getEncoder().encodeToString(r1.toBytes()));
        sigC.setProperty("r2"+users, Base64.getEncoder().encodeToString(r2.toBytes()));
        sigC.setProperty("r3"+users, Base64.getEncoder().encodeToString(r3.toBytes()));
        sigC.setProperty("H_2"+users, Base64.getEncoder().encodeToString(H_2m));

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
        Element a = bp.getZr().newRandomElement().getImmutable();
        String Qm=pkp.getProperty("Q"+user);
        Element Q=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Qm)).getImmutable();

        Element pk = P_pub.powZn(a);
        Element sk = a.powZn(s.powZn(Q));

        pkp.setProperty("pk"+user, Base64.getEncoder().encodeToString(pk.toBytes()));

        skp.setProperty("sk"+user,Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }

    public static void PartialKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
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

        byte [] H_1m = sha1(user);

        Element Q = bp.getZr().newElementFromHash(H_1m,0,H_1m.length);

        Element ppk = Q.powZn(s);

        //将公钥存储起来。
        pkp.setProperty("Q"+user,Base64.getEncoder().encodeToString(Q.toBytes()));
        pkp.setProperty("ppk"+user,Base64.getEncoder().encodeToString(ppk.toBytes()));
        //KGC生成私钥

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

