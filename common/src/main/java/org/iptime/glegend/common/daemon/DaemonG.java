package org.iptime.glegend.common.daemon;

import lombok.extern.log4j.Log4j2;

@Log4j2
public class DaemonG implements Runnable {

    DaemonG parents = null;

    String name = "";

    public String getName() {
        return ("".equals(name) ? Thread.currentThread().getName() : name);
    }

    public void setName(String name) {
        this.name = name;
    }

    public enum Status {
        INIT("초기화함수 수행 대기상태"),
        EXECUTE("실행함수 수행 대기상태"),
        SLEEP("대기함수 수행 대기상태"),
        FAIL("실패처리함수 수행 대기상태"),
        STOP("종료처리함수 수행 대기상태"),
        FINISH("종료상태");

        final private String desc;
        private Status(String desc) { this.desc=desc; }
        public String getDesc() { return desc; }
        public String getName() { return name(); }
    }

    private Status status = Status.SLEEP;
    public Status getStatus() {
        return this.status;
    }

    public void nextInit() { this.status = Status.INIT; }
    public void nextExecute() { this.status = Status.EXECUTE; }
    public void nextFail() { this.status = Status.FAIL; }
    public void nextSleep() { this.status = Status.SLEEP; }
    public void nextStop() { this.status = Status.STOP; }

    public boolean isFinish() { return ( this.status == Status.FINISH ); }
    public boolean isStop() { return ( this.status == Status.STOP ); }
    public boolean isFail() { return ( this.status == Status.FAIL ); }

    private long lastCheckTime = System.currentTimeMillis();
    public long getLastCheckTime() {
        return this.lastCheckTime;
    }

    ////////////////////////////////////////////////////

    public DaemonG(DaemonG parents) {
        this.parents = parents;
        setName(getClass().getSimpleName());
    }

    public DaemonG() {
    }

    public void run() {
        while(status != Status.FINISH)
        {
            try {
                if (parents != null && parents.getStatus() == Status.STOP )
                    status = Status.STOP;
            } catch (Exception e) {
                log.warn("parents lookup fail. e={}", e.getMessage(), e);
            }

            switch( status ) {
                case INIT:
                    init();
                    break;
                case EXECUTE:
                    execute();
                    break;
                case FAIL:
                    fail();
                    break;
                case STOP:
                    stop();
                    status = Status.FINISH;
                    break;
                case SLEEP:
                    sleep();
                    break;
                default:
                    log.warn("{} invalid status={}",  getName(), status);
            }

            lastCheckTime = System.currentTimeMillis();
        }
    }

    public void init() {}

    public void execute() {}

    public void fail() {}

    public void sleep() {
        try {
            Thread.sleep(1000);
        } catch (Exception e) {
        }
    }

    public void stop() {}
}
