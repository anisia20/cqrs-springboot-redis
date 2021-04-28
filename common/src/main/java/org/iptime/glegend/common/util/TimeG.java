package org.iptime.glegend.common.util;

import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.utils.Util;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

@Log4j2
public class TimeG {
    public static final int ONE_DAY_MILLIS = 86400000;
    public static final int ONE_HOUR_MILLIS = 3600000;
    public static final int ONE_MINUTE_MILLIS = 60000;
    public static final int ONE_SECOND_MILLIS = 1000;
    public static final int ONE_DAY_SECONDS = 86400;
    public static final int ONE_HOUR_SECONDS = 3600;
    public static final int ONE_MINUTE_SECONDS = 60;

    Date mDate = new Date();
    SimpleDateFormat mSimpleDateFormat = null;

    public TimeG() {
        mSimpleDateFormat = new SimpleDateFormat( "yyyyMMddHHmmss" );
    }

    public TimeG( String pattern ) {
        mSimpleDateFormat = new SimpleDateFormat( pattern );
    }

    public TimeG(String pattern, Locale locale) {
        this.mSimpleDateFormat = new SimpleDateFormat(pattern, locale);
    }

    public long toMillis(String date)
    {
        try {
            return this.mSimpleDateFormat.parse(date).getTime();
        } catch (Exception e) {
            return 0L;
        }
    }

    public static long toMillis(String str_date, String fmt) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(fmt);
            return sdf.parse(str_date).getTime();
        } catch (Exception var3) {
            return toMillis14("19700101090000");
        }
    }

    public static long toMillis(String str_date, String fmt, Locale currentLocale) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(fmt, currentLocale);
            return sdf.parse(str_date).getTime();
        } catch (Exception var4) {
            return toMillis14("19700101090000");
        }
    }

    public static long toMillis14(String str) {
        if (str == null) {
            return -3L;
        } else if (str.length() != 14) {
            return -2L;
        } else {
            Calendar cal = Calendar.getInstance();

            try {
                int year = Integer.parseInt(str.substring(0, 4));
                int mon = Integer.parseInt(str.substring(4, 6));
                int day = Integer.parseInt(str.substring(6, 8));
                int hour = Integer.parseInt(str.substring(8, 10));
                int min = Integer.parseInt(str.substring(10, 12));
                int second = Integer.parseInt(str.substring(12));
                cal.set(year, mon - 1, day, hour, min, second);
                return cal.getTimeInMillis();
            } catch (Exception var9) {
                Util.llog("[ERROR] toMillis14 " + var9.getMessage());
                return toMillis14("19700101090000");
            }
        }
    }

    public String toFormat() {
        return toFormat(System.currentTimeMillis());
    }

    public String toFormat( String pattern ) {
        return toFormat( pattern, System.currentTimeMillis() );
    }

    public String toFormat( String pattern, long timemillis ) {
        try {
            SimpleDateFormat simpleDateFormat= new SimpleDateFormat( pattern );
            this.mDate.setTime(timemillis);
            return simpleDateFormat.format(this.mDate);
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public String toFormat(long timemillis) {
        try {
            this.mDate.setTime(timemillis);
            return this.mSimpleDateFormat.format(this.mDate);
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public String addDate(String date, int type, int addCnt)
    {
        try {
            Calendar cal = Calendar.getInstance();
            cal.setTime( this.mSimpleDateFormat.parse(date) );
            cal.add( type, addCnt);
            return this.mSimpleDateFormat.format(cal.getTime());
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public String addDate(String pattern, String date, int type, int addCnt)
    {
        try {
            SimpleDateFormat simpleDateFormat= new SimpleDateFormat( pattern );
            Calendar cal = Calendar.getInstance();
            cal.setTime( simpleDateFormat.parse(date) );
            cal.add( type, addCnt);
            return simpleDateFormat.format(cal.getTime());
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public long diffDayOfDate(String begin, String end)
    {
        try {
            Date beginDate = this.mSimpleDateFormat.parse(begin);
            Date endDate = this.mSimpleDateFormat.parse(end);

            long diff = endDate.getTime() - beginDate.getTime();
            long diffDays = diff / ONE_DAY_MILLIS;

            return diffDays;
        } catch(Exception e) {
            return -1;
        }
    }

    public int diffYearOfDate(String begin, String end)
    {
        int month = diffMonthOfDate(begin, end);
        return (int) Math.ceil(month/12);
    }

    public int diffMonthOfDate(String begin, String end)
    {
        int strtYear = Integer.parseInt(begin.substring(0,4));
        int strtMonth = Integer.parseInt(begin.substring(4,6));

        int endYear = Integer.parseInt(end.substring(0,4));
        int endMonth = Integer.parseInt(end.substring(4,6));

        return (endYear - strtYear)* 12 + (endMonth - strtMonth);
    }

    public long addSeconds(long given_time, int seconds) {
        try {
            Calendar day = Calendar.getInstance();

            day.setTimeInMillis(given_time);

            day.add(13, seconds);

            return day.getTimeInMillis();
        } catch (Exception e) {
        }
        return toMillis("19700101090000");
    }

    public int getWeekDay(String ymd)
    {
        try {
            SimpleDateFormat simpleDateFormat= new SimpleDateFormat( "yyyyMMdd" );
            Date date = simpleDateFormat.parse(ymd);

            Calendar day = Calendar.getInstance();
            day.setTime(date);

            return day.get(Calendar.DAY_OF_WEEK);
        } catch(Exception e) {
            return -1;
        }
    }

    public static String toFormat14(long ll) {
        return ll == 0L ? "19700101090000" : toFormat(ll, "yyyyMMddHHmmss");
    }

    public static String toFormat14() {
        return toFormat(System.currentTimeMillis(), "yyyyMMddHHmmss");
    }

    public static String toFormat(long timemillis, String fmt) {
        try {
            SimpleDateFormat m_df = new SimpleDateFormat(fmt);
            Date m_date = new Date();
            m_date.setTime(timemillis);
            return m_df.format(m_date);
        } catch (Exception var5) {
            return "19700101090000";
        }
    }

    public static String toFormat(long timemillis, String fmt, Locale currentLocale) {
        try {
            SimpleDateFormat m_df = new SimpleDateFormat(fmt, currentLocale);
            Date m_date = new Date();
            m_date.setTime(timemillis);
            return m_df.format(m_date);
        } catch (Exception var6) {
            return "19700101090000";
        }
    }

    public static void main(String args[]) {
        // addDate(String pattern, String date, int type, int addCnt)
        String result = new TimeG().addDate("yyyyMM", "201801", Calendar.MONTH, -2);
        System.out.println(result);

    }
}
