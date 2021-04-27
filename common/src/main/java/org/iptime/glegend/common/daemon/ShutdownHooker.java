package org.iptime.glegend.common.daemon;

import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.utils.Util;

@Log4j2
public class ShutdownHooker {
    DaemonG process = null;
    long max_waiting_time = 0L;

    public ShutdownHooker(DaemonG proc, int max_waiting_seconds) {
        this.process = proc;
        this.max_waiting_time = (long) (max_waiting_seconds * 1000);
        if (this.max_waiting_time < 0L) {
            this.max_waiting_time = 10000L;
        }
    }

    public void run() {
        try {
            log.debug("{} running", getClass().getSimpleName());

            long e = System.currentTimeMillis();
            this.process.nextStop();

            while (this.process != null && this.process.isFinish()==false) {
                Util.sleep(1000);
                if (System.currentTimeMillis() - e > this.max_waiting_time) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
