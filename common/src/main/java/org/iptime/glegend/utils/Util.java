package org.iptime.glegend.utils;

import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.common.code.ResultCode;
import org.iptime.glegend.common.model.Result;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.ObjectUtils;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.ValidatorFactory;
import javax.validation.Validator;
import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryUsage;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

@Log4j2
@Configuration
public class Util {

    // String, Array, Collection, Map
    public static boolean isNullOrEmpty(Object obj) {
        return ObjectUtils.isEmpty(obj);
    }
    static Validator validator;

    public static String nullConv( String s ) {
        if( s == null ) {
            return "";
        }else {
            return s.trim();
        }
    }

    public static void sleep( int milliSec ) {
        try {
            Thread.sleep(milliSec);
        } catch (InterruptedException e) {}
    }

    public static String nullConv( String s, String defaultStr ) {
        if( s == null ) {
            return defaultStr;
        }else {
            return s.trim();
        }
    }

    public static String msg(String fmt, Object ... args)
    {
        StringBuffer sb = new StringBuffer();
        String logx = (String)fmt;
        int length = logx.length();
        int pos = 0;
        int from_pos = 0;
        int arg_idx = 0;
        do
        {
            pos = logx.indexOf("{}", from_pos);
            if(pos < 0)
            {
                sb.append(logx.substring(from_pos, length));
                break;
            }
            sb.append(logx.substring(from_pos, pos));
            if(args == null)
            {
                sb.append("null");
                sb.append(logx.substring(pos + 2));
                break;
            }
            if(arg_idx >= args.length)
            {
                sb.append(logx.substring(pos));
                break;
            }
            sb.append(args[arg_idx++]);
            from_pos = pos + 2;
        } while(true);

        return sb.toString();
    }

    public static String getErrMsg( StackTraceElement e, String msg, Throwable cause, boolean isSimple ) {
        String result = "";

        if (isSimple==false) {
            String clazz = e.getClassName().substring( e.getClassName().lastIndexOf(".") + 1 );
            result = "[" + clazz + ":" + e.getMethodName() + "(" + e.getLineNumber() + ")] ";
            result += "err=[" + msg + "] cause=[" + cause +"]";
        } else {
            result += msg;
        }

        return result;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static void getHeapSize() {
        long mb = 1024L*1024L;
        MemoryUsage mf = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        log.info("------------ memory status ------------");
        log.info("HeapMemory : \t (u/c/m) "+mf.getUsed()/mb+"MB / "+mf.getCommitted()/mb+"MB / "+mf.getMax()/mb+"MB");

        mf = ManagementFactory.getMemoryMXBean().getNonHeapMemoryUsage();
        log.info("NonHeapMemory : \t (u/c/m) "+mf.getUsed()/mb+"MB / "+mf.getCommitted()/mb+"MB / "+mf.getMax()/mb+"MB");

        log.info("Detail Heap Memory : young gen(eden+survivor), old gen(tenured gen), perm gen");
        for (MemoryPoolMXBean mx : ManagementFactory.getMemoryPoolMXBeans()) {
            mf = mx.getUsage();
            log.info(String.format("\t%-20s \t (u/c/m) %15s",mx.getName(), mf.getUsed()/mb+"MB / "+mf.getCommitted()/mb+"MB / "+mf.getMax()/mb+"MB"));
        }
        log.info("-----------------------------------------------");
    }

    public static String getHeapSize2() {
        StringBuffer sb = new StringBuffer();
        long mb = 1024L*1024L;
        MemoryUsage mf = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        sb.append("HeapMemory : "+mf.getUsed()/mb+"MB / "+mf.getMax()/mb+"MB");

        mf = ManagementFactory.getMemoryMXBean().getNonHeapMemoryUsage();
        sb.append(" / NonHeapMemory : "+mf.getUsed()/mb+"MB / "+mf.getMax()/mb+"MB / ");

        for (MemoryPoolMXBean mx : ManagementFactory.getMemoryPoolMXBeans()) {
            mf = mx.getUsage();
            sb.append(String.format(" %s : %s",mx.getName(), mf.getUsed()/mb+"MB / "+mf.getMax()/mb+"MB"));
        }
        return sb.toString();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static String getLocInfo( Exception e ) {
        return getLocInfo( null, e );
    }

    public static String getLocInfo( Exception e, boolean isSimple ) {
        if (e.getCause() == null)
            return getLocInfo( null, e, isSimple );
        else
            return getLocInfo( null, e.getCause(), isSimple );
    }

    public static String getLocInfo( Throwable e, boolean isSimple ) {
        return getLocInfo( null, e, isSimple );
    }

    public static String getLocInfo( Object obj, Exception e ) {
        if (e.getCause() == null)
            return getLocInfo( obj, e, true );
        else
            return getLocInfo( obj, e.getCause(), false );
    }

    public static String getLocInfo( Object obj, Throwable ex, boolean isSimple )
    {
        if (obj == null)
            return getErrMsg( ex.getStackTrace()[0], ex.getMessage(), ex, isSimple );

        for (int i = 0; i < ex.getStackTrace().length; i++)
        {
            StackTraceElement e = ex.getStackTrace()[i];
            if ( e.getClassName().equals( obj.getClass().getName() ) )
                return getErrMsg( e, ex.getMessage(), ex, isSimple );
        }

        return getErrMsg( ex.getStackTrace()[0], ex.getMessage(), ex, isSimple );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static String getCauseInfo( Exception e ) {
        return getCauseInfo( e, false );
    }

    public static String getCauseInfo( Exception ex, boolean isSimple )
    {
        Throwable e1 = ex.getCause();
        if (e1 == null) return "";

        return getErrMsg( e1.getStackTrace()[0], e1.getMessage(), e1.getCause(), isSimple );
    }

    public static String getCauseInfo( Throwable e1, boolean isSimple )
    {
        if (e1 == null) return "";

        return getErrMsg( e1.getStackTrace()[0], e1.getMessage(), e1.getCause(), isSimple );
    }

    /** Get the current line number.
     * @return int - Current line number.
     */
    public static int getLineNumber() {
        return getLineNumber(0);
    }

    /** Get the line number for called prev. source
     * @return int - Current line number.
     */
    public static int getLineNumber(int prev) {
        return Thread.currentThread().getStackTrace()[2+prev].getLineNumber();
    }

    public static String getSrcLoc(int prev) {
        StackTraceElement el = Thread.currentThread().getStackTrace()[2+prev];
        return el.getFileName()+":"+el.getLineNumber();
    }

    public static String getSrcLoc2(int prev) {
        StackTraceElement el = Thread.currentThread().getStackTrace()[2+prev];
        String[] clazz = el.getClassName().split("\\.");
        return clazz[clazz.length-1]+":"+el.getMethodName()+"("+el.getLineNumber()+")";
    }

    public static String toString( Object obj )
    {
        StringBuffer sb = new StringBuffer();

        Field[] fields = obj.getClass().getDeclaredFields(); //Get all fields incl. private ones
        for (Field field : fields){
            try {
                field.setAccessible(true);
                String key=field.getName();
                String value;

                try{
                    value = (String) field.get(obj);
                } catch (ClassCastException e){
                    value="";
                }

                sb.append("{").append(key).append(": ").append(value).append("}");
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
            } catch (SecurityException e) {
                e.printStackTrace();
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////

    static SimpleDateFormat mSimpleDateFormat = null;

    public static String toFormat() {
        return toFormat(System.currentTimeMillis());
    }

    public static String toFormat(long timemillis) {
        try {
            if (mSimpleDateFormat == null) mSimpleDateFormat = new SimpleDateFormat( "yyyyMMddHHmmss" );
            return  mSimpleDateFormat.format( new Date( timemillis ) );
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public static String toFormat(String pattern, long timemillis) {
        try {
            // if (mSimpleDateFormat == null)
            mSimpleDateFormat = new SimpleDateFormat( pattern );
            return  mSimpleDateFormat.format( new Date( timemillis ) );
        } catch (Exception e) {
            return "19700101090000";
        }
    }

    public static String toFormat(String pattern) {
        return toFormat(pattern, System.currentTimeMillis());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void unixCmd(String[] command) throws IOException
    {
        Runtime runtime=Runtime.getRuntime();

        runtime.exec(command);
        runtime.gc();
    }

    ///////////////////////////////////////////

    private static final Comparator<File> lastModified = new Comparator<File>() {
        public int compare(File o1, File o2) {
            return o1.lastModified() == o2.lastModified() ? 0 : (o1.lastModified() < o2.lastModified() ? 1 : -1 ) ;
        }
    };

    public static File[] sortFiles( File[] obj, int sortType )
    {
        File[] files = obj.clone();

        if (sortType == 1)
        {
            Arrays.sort( files, lastModified );
        }
        else if (sortType == 2) {
            Arrays.sort( files );
        }
        else if (sortType == 3) {
            List unsortedList = Arrays.asList( files );
            Collections.sort( unsortedList, Collections.reverseOrder() );
            files = (File[]) unsortedList.toArray();
        }

        return files;
    }

    public static Long getBigDecimal( Object obj ) {
        if (obj instanceof BigDecimal) {
            return Long.valueOf( ((BigDecimal) obj).longValue() );
        } else if (obj instanceof Long) {
            return (Long) obj;
        } else {
            return Long.valueOf( (String) obj );
        }
    }

    public static String[] explode(String str, String sep) {
        ArrayList arrlist = new ArrayList();
        String[] res = null;

        if ((str == null) || (sep == null)) {
            res = new String[0];
            return res;
        }

        if (str.length() == 0) {
            res = new String[0];
            return res;
        }

        int find_pos = 0;
        int start_pos = 0;
        int len_sep = sep.length();
        while (true) {
            find_pos = str.indexOf(sep, start_pos);
            if (find_pos < 0) {
                arrlist.add(str.substring(start_pos));
                break;
            }

            if (start_pos == find_pos)
                arrlist.add("");
            else
                arrlist.add(str.substring(start_pos, find_pos));

            start_pos = find_pos + len_sep;
        }

        res = new String[arrlist.size()];

        for (int i = 0; i < arrlist.size(); ++i) {
            res[i] = ((String) arrlist.get(i));
        }
        return res;
    }

    public static <TYPE> void llog(TYPE str) {
        SimpleDateFormat df = new SimpleDateFormat("[HH:mm:ss:SSS]");

        StackTraceElement[] ste = new Exception().getStackTrace();

        System.out.println(df.format(new Date()) + ste[1].getClassName() + "::"
                + ste[1].getMethodName() + "(" + ste[1].getLineNumber() + ")>>"
                + str);
    }

    public static void llog(String format, Object... args) {
        SimpleDateFormat df = new SimpleDateFormat("[HH:mm:ss:SSS]");

        StackTraceElement[] ste = new Exception().getStackTrace();

        String str = merge(format, args);
        System.out.println(df.format(new Date()) + ste[1].getClassName() + "::"
                + ste[1].getMethodName() + "(" + ste[1].getLineNumber() + ")>>"
                + str);
    }

    public static String merge(String fmt, Object... args){
        StringBuilder sb = new StringBuilder("["+getSrcLoc(2)+"] "+fmt.toString().replaceAll("\\{\\}", "%s"));

        if(isSimpleFormat(sb))
            return mergeFast(sb, args);
        else
            return mergeSlow(sb, args);
    }

    static boolean isSimpleFormat(StringBuilder fmt){
        int len = fmt.length();
        boolean result = true;
        try {
            for(int i = 0 ; i < len ; i++){
                char c = fmt.charAt(i);
                if(c=='%'&&fmt.charAt(i+1)!='s')
                    result = false;
            }
        } catch (Exception e) {
            result = false;
        }
        return result;
    }

    static String mergeSlow(StringBuilder fmt, Object ... args){
        return String.format(fmt.toString(), args);
    }

    static String mergeFast(StringBuilder fmt, Object ... args){
        StringBuilder sb = new StringBuilder();
        if(args==null){
            return sb.append(fmt).toString();
        }

        int length = fmt.length();

        String v;
        int pos = 0;
        int from_pos = 0;
        int arg_idx = 0;

        while(true){
            pos = fmt.indexOf("%s", from_pos);
            if(pos<0){
                sb.append(fmt.substring(from_pos, length));
                break;
            }

            if(arg_idx<args.length){
                if(args[arg_idx]!=null)
                    v = args[arg_idx].toString();
                else
                    v = "null";
            }
            else{
                sb.append(fmt.substring(from_pos, length));
                break;
            }

            arg_idx++;

            sb.append(fmt.substring(from_pos,pos));

            sb.append(v);
            from_pos = pos + 2;
        }

        return sb.toString();
    }

    public static String getLineSeparator() {
        return "\n";
    }

    public static String getMethodName(Object obj) {
        if (obj == null) {
            return "[ERROR]Util.getMethodName:>>null";
        } else {
            try {
                Exception e = new Exception();
                StackTraceElement element = e.getStackTrace()[1];
                return obj.getClass().getName() + "::" + element.getMethodName() + "(L:" + element.getLineNumber()
                        + ")";
            } catch (Exception arg2) {
                return "[ERROR]Util.getMethodName:>>" + obj.toString();
            }
        }
    }

    public static void llog(String string) {
        System.out.println(string);
    }

    // YYYYMM
    // month= 0 : this month
    // month=-1 : one month ago
    public static String getYm(int month){
        String   ym       = "";
        Calendar objCal   = Calendar.getInstance();
        objCal.add(Calendar.MONTH, month);
        String   strYear  = null;
        int      nMonth;

        String   strMonth = null;

        strYear           = ""+objCal.get(Calendar.YEAR);
        nMonth            = objCal.get(Calendar.MONTH)+1;
        strMonth          = nMonth>9?""+nMonth:"0"+nMonth;
        ym                = strYear + strMonth;
        return ym;
    }

    // YYYYMMDD
    // date= 0 : today
    // date=-1 : yesterday
    public static String getYmd(int date){
        String   ymd      = "";
        Calendar objCal   = Calendar.getInstance();
        objCal.add(Calendar.DATE, date);

        String   strYear  = null;
        int      nMonth;
        int      nDate;

        String   strMonth = null;
        String   strDate  = null;

        strYear           = ""+objCal.get(Calendar.YEAR);
        nMonth            = objCal.get(Calendar.MONTH)+1;
        strMonth          = nMonth>9?""+nMonth:"0"+nMonth;
        nDate             = objCal.get(Calendar.DATE);
        strDate           = nDate>9?""+nDate:"0"+nDate;

        ymd                = strYear + strMonth + strDate;
        return ymd;
    }

    public static int atoi(Object o) {
        try {
            return atoi(o.toString());
        } catch (Exception var2) {
            return -9999999;
        }
    }

    public static int atoi(String str) {
        try {
            return str.length() == 0 ? 0 : Integer.parseInt(str);
        } catch (Exception var2) {
            return -9999999;
        }
    }

    public static long atol(String str) {
        try {
            return str.length() == 0 ? 0L : Long.parseLong(str);
        } catch (Exception var2) {
            return -9999999L;
        }
    }

    public static double atod(String str) {
        try {
            return str.length() == 0 ? 0.0D : Double.parseDouble(str);
        } catch (Exception var2) {
            return -9999999.0D;
        }
    }

    public static float atof(String str) {
        try {
            return str.length() == 0 ? 0.0F : Float.parseFloat(str);
        } catch (Exception var2) {
            return -9999999.0F;
        }
    }

    public static String getRemoteIpAddr(ServerHttpRequest request) {

        String ip = "";
        if (isNullOrEmpty(request.getRemoteAddress()) == false) {
            ip = request.getRemoteAddress().getAddress().getHostAddress();
        }

        List<String> xForwardedValues = request.getHeaders().get("X-Forwarded-For");
        if (isNullOrEmpty(xForwardedValues)) {
            return ip;
        }

        if (xForwardedValues.size() > 1) {
            log.warn("Multiple X-Forwarded-For headers found, discarding all");
            return ip;
        }

        ip = xForwardedValues.get(0);
        return ip;
    }

    public static boolean isValidIPAddr( String ip, String[] pattern )
    {
        boolean isIpOk = false;
        for (int i=0; i < pattern.length; i++) {
            String p = pattern[i].trim().replaceAll("\\.", "\\\\.").replaceAll("\\*", ".*");
            if ("".equals(p)) continue;
            if ( ip.matches( p ) == true ) { isIpOk = true; break; }
        }

        return isIpOk;
    }

    @Bean
    public static void getValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    public static boolean isValid(Object source, Result result) {
        Set<ConstraintViolation<Object>> violations = validator.validate(source);
        for (ConstraintViolation<Object> violation : violations) {
            result.setResultFail(ResultCode.getResultCd(ResultCode.Prefix.PREFIX_R.key+violation.getMessage()));
            return false;
        }
        return true;
    }

    public static boolean isValidChar(String regexp, String col) {
        try {
            if (isNullOrEmpty(col)) return false;
            return (Pattern.compile(regexp).matcher(col).find());

        } catch (Exception e) {
            log.error(e.getMessage());
            return false;
        }
    }


    public static boolean isValidByteSize(int maxSize, String col) {
        try {
            if (isNullOrEmpty(col)) return false;
            return (col.getBytes().length <= maxSize);

        } catch (Exception e) {
            log.error(e.getMessage());
            return false;
        }
    }

    public static boolean isValidExt( String ext, String[] pattern )
    {
        boolean isOk = false;
        for (int i=0; i < pattern.length; i++) {
            String p = pattern[i].trim().replaceAll("\\*", ".*");
            if ("".equals(p)) continue;
            if ( ext.matches( p ) == true ) { isOk = true; break; }
        }

        return isOk;
    }

    public static void main(String[] args) {
        System.out.println("aa" + Util.toFormat("yyyyMM"));

        System.out.println("bb" + Util.toFormat("HHmm"));

    }
}
