package cn.net.insurance.core.common.utils;


import cn.net.insurance.core.base.model.RespResult;
import cn.net.insurance.core.base.utils.JacksonUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;


@Slf4j
public class LogWrite extends Thread {
    private RespResult result;
    private long start;
    private long end;
    private String url;
    private String ip;
    private Map<String,String> paramMap;
    private String userId;

    public LogWrite(String url, String ip, Map<String,String> paramMap, RespResult result, long start, long end, String userId) {
        this.result = result;
        this.start = start;
        this.end = end;
        this.url = url;
        this.ip = ip;
        this.paramMap = paramMap;
        this.userId = userId;
    }

    @SneakyThrows
    @Override
    public void run() {
        log.info("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",result.getStatus(), result.getErrorCode(), result.getErrorMsg(), userId, start, end, end - start, url, ip, JacksonUtils.toJson(paramMap));
    }

}
