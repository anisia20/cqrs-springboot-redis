package org.iptime.glegend.common.util;

import org.iptime.glegend.utils.Util;

import java.text.DecimalFormat;
import java.util.Random;

public class UuidMaker {
    public static final String TT_CAB = "1";
    public static final String TT_IMG = "2";
    TimeG time14 = new TimeG("yyyyMMddHHmmss");
    DecimalFormat df2 = new DecimalFormat("00");
    DecimalFormat df3 = new DecimalFormat("000");
    DecimalFormat df4 = new DecimalFormat("0000");
    DecimalFormat df5 = new DecimalFormat("00000");
    DecimalFormat df9 = new DecimalFormat("000000000");
    private static final char[] CA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
    String mRSIDX = "";
    Random rand = new Random(System.currentTimeMillis());
    int[] pos = new int[3];

    public UuidMaker(int rs_num) {
        for (int i = 0; i < CA.length; ++i) {
            if (CA[i] == 'A') {
                this.pos[0] = i;
            }

            if (CA[i] == '0') {
                this.pos[1] = i;
            }

            if (CA[i] == 'a') {
                this.pos[2] = i;
            }
        }

        this.mRSIDX = this.df2.format((long) rs_num);
    }

    public synchronized String nextKey(String template_type) {
        String stime = this.time14.toFormat();
        return this.encode(this.df5.format((long) this.rand.nextInt(100000)) + stime + this.mRSIDX
                + this.df3.format((long) this.rand.nextInt(1000)) + template_type);
    }

    String encode(String str) {
        if (str.length() % 5 != 0) {
            return "INVALID_FORMAT";
        } else {
            int n = str.length();
            String r_str = "";

            for (int i = 0; i * 5 < n; ++i) {
                r_str = r_str + this.encode(Util.atoi(str.substring(i * 5, i * 5 + 5)));
            }

            return r_str;
        }
    }

    String encode(long num) {
        return this.encode((int) num);
    }

    String encode(int num) {
        String str = "";
        if (num > (int) Math.pow((double) CA.length, 3.0D)) {
            return "EXCEED_NUM";
        } else {
            for (int i = 2; i >= 0; --i) {
                int x = (int) Math.pow((double) CA.length, (double) i);
                if (num < x) {
                    str = str + CA[0];
                } else {
                    int dn = num / x;
                    str = str + CA[dn];
                    num -= x * dn;
                }
            }

            return str;
        }
    }

    public String getDate(String key) {
        if (key == null) {
            return null;
        } else {
            String decode_str = this.decode(key);
            return decode_str.length() != 25 ? null : decode_str.substring(5, 19);
        }
    }

    public String getFolderIdx(String key) {
        if (key == null) {
            return null;
        } else {
            String decode_str = this.decode(key);
            return decode_str.length() != 25 ? null : decode_str.substring(21, 24);
        }
    }

    public String getTemplateType(String key) {
        if (key == null) {
            return null;
        } else {
            String decode_str = this.decode(key);
            return decode_str.length() != 25 ? null : decode_str.substring(24, 25);
        }
    }

    public int getRSNum(String key) {
        if (key == null) {
            return -1;
        } else {
            String decode_str = this.decode(key);
            return decode_str.length() != 25 ? -1 : Util.atoi(decode_str.substring(19, 21));
        }
    }

    String decode(String key) {
        if (key.length() % 3 != 0) {
            return "INVALID_KEY";
        } else {
            String r_str = "";

            for (int i = 0; i < key.length() / 3; ++i) {
                int n1 = this.searchIdx(key.charAt(i * 3));
                int n2 = this.searchIdx(key.charAt(i * 3 + 1));
                int n3 = this.searchIdx(key.charAt(i * 3 + 2));
                if (n1 < 0 || n2 < 0 || n3 < 0) {
                    return "INVALID_KEY_TYPE";
                }

                int num = (int) ((double) n1 * Math.pow((double) CA.length, 2.0D)
                        + (double) n2 * Math.pow((double) CA.length, 1.0D)
                        + (double) n3 * Math.pow((double) CA.length, 0.0D));
                r_str = r_str + this.df5.format((long) num);
            }

            return r_str;
        }
    }

    int searchIdx(char c) {
        if (c >= 'A' && c <= 'Z') {
            return this.pos[0] + (c - 65);
        } else if (c >= '0' && c <= '9') {
            return this.pos[1] + (c - 48);
        } else {
            return c >= 'a' && c <= 'z' ? this.pos[2] + (c - 97) : -1;
        }
    }

}
