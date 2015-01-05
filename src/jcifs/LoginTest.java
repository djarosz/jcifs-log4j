package jcifs;

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Date;

import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;

public class LoginTest {
	/*    public static void main(String argv[]) throws UnknownHostException, SmbException {
			UniAddress dc = UniAddress.getByName("spawalnia");
			NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("devel;javart4:aqq");
			SmbSession.logon(dc, auth); 
			
			System.out.print("ping");
			NtlmPasswordAuthentication auth2 = new NtlmPasswordAuthentication("devel;pprzybysz:aqq");
			SmbSession.logon(dc, auth2); 
			System.out.print("pong");

			NtlmPasswordAuthentication auth3 = new NtlmPasswordAuthentication("devel;javart2:aqq");
			SmbSession.logon(dc, auth3);
			System.out.print("ping");
	    }*/

	static int failures = 0;
	static int success = 0;
	static String host = "spawalnia";

	public static void main(String[] args) throws Exception {
		if (args.length > 0)
			host = args[0];
		Config.setProperty("session.transport.log.level", "3");
		Config.setProperty("jcifs.smb.client.soTimeout", "100000");
		Config.setProperty("jcifs.smb.client.responseTimeout", "10000");

		System.out.println(Config.getProperty("jcifs.smb.client.soTimeout"));
		LoginTest ntlmAuth = new LoginTest();
		if (args.length > 1)
			ntlmAuth.test2(Integer.parseInt(args[1]));
		else
			ntlmAuth.test2(20000);
	}
	
	public void test1() throws Exception {
		new Monitor().start();

		for (int i = 0; i < 150; i++) {
			//new T("devel", "javart4", "aqq").start();
			new T("polkomtel", "pawel.przybysz", "haselko33##").start();
			//new T("devel", "javart2", "aqq").start();
		}
	}	
	
	public void test2(int repeatCount) throws Exception {
		UniAddress dc = UniAddress.getByName(host, true);
		//long startTime = System.nanoTime();
		for (int i = 0; i < repeatCount; i++) {
			//tryLogin(dc, "spawalnia", "javart4", "aqq");
			tryLogin(dc, "polkomtel", "pawel.przybysz", "haselko33##");
			//tryLogin(dc, "polkomtel", "javart4", "aqq");
			//tryLogin(dc, "spawalnia", "javart4", "zle haslo");
		}
		//System.out.println("Logins per second: " + (repeatCount / ((System.nanoTime() - startTime) / 1000000000.0)));
	}
	
	public byte[] tryLogin(UniAddress dc, String domain, String login, String password) {
		Type1Message m1 = null;
		Type2Message m2 = null;
		Type3Message m3 = null;
		byte[] challenge = null;
		try {
			m1 = new Type1Message(0xb203, domain, domain);
			//System.out.println("Type 1 message: " + m1.toString());

			challenge = SmbSession.getChallenge(dc);
			m2 = new Type2Message(m1, challenge, null);
			//System.out.println("Type 2 message: " + m2.toString());

			m3 = new Type3Message(m2, password, domain, login, domain);
			//System.out.println("Type 3 message: " + m3.toString());

			NtlmPasswordAuthentication npa = new NtlmPasswordAuthentication(m3.getDomain(), m3.getUser(), m2.getChallenge(), m3.getLMResponse(), m3
					.getNTResponse());
			SmbSession.logon(dc, npa);					
	
		} catch (Exception e) {
			System.out.println("Type 1 message: " + m1.toString());
			System.out.println("Type 2 message: " + m2.toString());
			System.out.println("Type 3 message: " + m3.toString());
			System.out.println((++failures) + " / " + e + " / " + Thread.currentThread().getName());
			e.printStackTrace();
		}	
		return challenge;
	}

	class T extends Thread {

		private final String domain;
		private final String user;
		private final String password;
		public static final int cycleTime = 25;
		public static final int cycleRandomTime = 1;
		public UniAddress dc;
		private byte[] chalange;
		

		public T(String domain, String user, String password) throws UnknownHostException {			
			super();
			this.domain = domain;
			this.user = user;
			this.password = password;
			dc = UniAddress.getByName(host, true);
		}
		
		public void run() {

			while (true) {
				try {
					byte[] newChalange = tryLogin(dc, domain, user, password);
					if (chalange == null)
						chalange = newChalange;
					if (!Arrays.equals(chalange, newChalange)) {
						System.out.println("" + new Date() + " hurahi!!!");
						chalange = newChalange;
					}
					success++;
					//Thread.sleep(cycleTime + new Random().nextInt(cycleRandomTime));
				} catch (Exception e) {
					System.out.println((++failures) + " / " + e + " / " + Thread.currentThread().getName());
					e.printStackTrace();
				}
			}
		}
	}

	class Monitor extends Thread {

		public void run() {
			while (true) {
				try {
					Thread.sleep(5000);
					System.err.println("Success: " + success + ", failures: " + failures);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

	}
    
}
