package org.iptime.glegend.common.model;

import org.iptime.glegend.common.code.ResultCode;

import java.util.HashMap;

public class Result extends HashMap<String, Object> {

    private static final long serialVersionUID = 1456046014038813591L;

    public Result() {}

    public Result(ResultCode resultCode) {
        setResultData(resultCode);
    }

    public Result(ResultCode resultCode, Object data) {
        setResultData(resultCode, data);
    }

    public void setSuccess() {
        setResultData(ResultCode.R_000);
    }

    public void setSuccess(Object data) {
        setResultData(ResultCode.R_000, data);
    }

    public void setResultFail() {
        setResultData(ResultCode.R_ETC.r, ResultCode.R_ETC.rd);
    }

    public void setResultFail(ResultCode resultCode) {
        setResultData(resultCode.r, resultCode.rd);
    }

    public void setResultFail(ResultCode resultCode, Object data) {
        setResultData(resultCode.r, resultCode.rd, data);
    }

    public void setResultFail(String result, String resultDesc) {
        setResultData(result, resultDesc);
    }

    public void setResultFail(String result, String resultDesc, Object data) {
        setResultData(result, resultDesc, data);
    }

    public void setResultData(ResultCode resultCode) {
        setResultData(resultCode.r, resultCode.rd);
    }

    public void setResultData(ResultCode resultCode, Object data) {
        setResultData(resultCode.r, resultCode.rd, data);
    }

    public void setResultData(String result, String resultDesc) {
        put("r", result);
        put("rd", resultDesc);
    }

    public void setResultData(String result, String resultDesc, Object data) {
        put("r", result);
        put("rd", resultDesc);
        put("data", data);
    }

    public void setData(Object data) {
        put("data", data);;
    }

    public Object getData() {
        return get("data");
    }

    public String getResult() {
        return (String) get("r");
    }

    public String getResultDescription() {
        return (String) get("rd");
    }
}
