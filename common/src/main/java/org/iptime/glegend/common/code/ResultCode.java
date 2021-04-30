package org.iptime.glegend.common.code;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.util.HashMap;

@Getter
@AllArgsConstructor
@ToString
public enum ResultCode {

    /**
     * 코드 설명
     *         내부코드   코드타입               내부코드 설명                                                         클라이언트 코드 설명
     * R_000("000", "ETC",		"기타에러", 									"기타에러"),
     */


    /**
     * 00X 성공
     */
    R_000("000", "COMMON",	"성공", 										"성공"),


    /**
     * 내부 GW 실패코드
     * ------------------- 클라이언트 연동 (메시지 처리, 이미지 등록 등) ------------------
     * 100 ~ 199 클라이언트 에러
     */
    // ------- A2P 메시지 발송(RS) -------
    R_100("100", "AUTH",		"인증에러", 									"인증에러"),
    R_290("290", "ETC",		"기타에러", 									"기타에러"),


    /**
     * ------------------- 기타 오류코드  ------------------
     * 9xxx 결과코드 사용
     */
    R_ETC("999", "ETC", 		"기타", 										"기타오류"),
    R_RETRY("988", "ETC", 		"이통사 에러(재처리필요)", 						"이통사 에러(재처리필요)"),
    ;

    public String r;
    public String tp;
    public String rd;
    public String cd;

    public static HashMap<String, ResultCode> getresultCode() {
        HashMap<String, ResultCode> codeMap = new HashMap<>();
        for (ResultCode c : values()) {
            codeMap.put(c.r, c);
        }
        return codeMap;
    }

    public static ResultCode getResultCd(String result) {
        return getResultCd(result, ResultCode.R_ETC);
    }

    public static ResultCode getResultCd(String result, ResultCode rcsresultCd) {
        ResultCode resultCd = null;
        try {
            resultCd = ResultCode.valueOf(result);
        } catch (Exception e) {
            resultCd = (rcsresultCd == null) ? ResultCode.R_ETC : rcsresultCd;
        }
        return resultCd;
    }

    @Getter
    @AllArgsConstructor
    @ToString
    public enum Prefix {
        PREFIX_R("R_"),
        ;
        public String key;
    }
}
