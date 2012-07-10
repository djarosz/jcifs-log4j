package jcifs.smb;

import java.io.InputStream;
import java.io.IOException;

import org.apache.log4j.Logger;

public class TestLocking implements Runnable {

	private static final Logger LOGGER = Logger.getLogger(TestLocking.class);

	int numThreads = 1;
	int numIter = 1;
	long delay = 100;
	String url = null;
	int numComplete = 0;
	long ltime = 0L;

	public void run()
	{
		try {
			SmbFile f = new SmbFile(url);
			SmbFile d = new SmbFile(f.getParent());
			byte[] buf = new byte[1024];

			for (int ii = 0; ii < numIter; ii++) {

				synchronized (this) {
					ltime = System.currentTimeMillis();
					wait();
				}

				try {
					double r = Math.random();
					if (r < 0.333) {
						f.exists();
						//                      LOGGER.debug('e');
					} else if (r < 0.667) {
						d.listFiles();
						//                      LOGGER.debug('l');
					} else if (r < 1.0) {
						InputStream in = f.getInputStream();
						while (in.read(buf) > 0) {
							//                          LOGGER.debug('r');
						}
						in.close();
					}
				} catch (IOException ioe) {
					LOGGER.error("", ioe);
					//ioe.printStackTrace(System.err);
				}

			}
		} catch (Exception e) {
			LOGGER.error("", e);
		} finally {
			numComplete++;
		}
	}

	public static void main(String[] args) throws Exception
	{
		if (args.length < 1) {
			LOGGER.error("usage: TestLocking [-t <numThreads>] [-i <numIter>] [-d <delay>] url");
			System.exit(1);
		}

		TestLocking t = new TestLocking();
		t.ltime = System.currentTimeMillis();

		for (int ai = 0; ai < args.length; ai++) {
			if (args[ai].equals("-t")) {
				ai++;
				t.numThreads = Integer.parseInt(args[ai]);
			} else if (args[ai].equals("-i")) {
				ai++;
				t.numIter = Integer.parseInt(args[ai]);
			} else if (args[ai].equals("-d")) {
				ai++;
				t.delay = Long.parseLong(args[ai]);
			} else {
				t.url = args[ai];
			}
		}

		Thread[] threads = new Thread[t.numThreads];
		int ti;

		for (ti = 0; ti < t.numThreads; ti++) {
			threads[ti] = new Thread(t);
			LOGGER.info(threads[ti].getName());
			threads[ti].start();
		}

		while (t.numComplete < t.numThreads) {
			long delay;

			do {
				delay = 2L;

				synchronized (t) {
					long expire = t.ltime + t.delay;
					long ctime = System.currentTimeMillis();

					if (expire > ctime)
						delay = expire - ctime;
				}

				if (delay > 2)
					LOGGER.debug("delay=" + delay);
				Thread.sleep(delay);
			} while (delay > 2);

			synchronized (t) {
				t.notifyAll();
			}
			//LOGGER.debug("numComplete=" + t.numComplete + ",numThreads=" + t.numThreads);
		}

		for (ti = 0; ti < t.numThreads; ti++) {
			threads[ti].join();
			LOGGER.info(threads[ti].getName());
		}

	}
}
