package cn.net.insurance.core.base.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RespResult<T> implements Serializable {
    private final static int SUCESS_STATUS = 1;
    private final static int FAIL_STATUS = -1;
    private int status;
    private String errorCode;
    private String errorMsg;
    private T data;

    public static <T> RespResult<T> success() {
        return success(null);
    }

    public static <T> RespResult<T> success(T data) {
        return RespResult.<T>builder().status(SUCESS_STATUS).errorCode(ExtraCodeEnum.NORMAL.code).errorMsg(ExtraCodeEnum.NORMAL.msg).data(data).build();
    }

    public static RespResult fail(String code, String msg) {
        return RespResult.builder().status(FAIL_STATUS).errorCode(code).errorMsg(msg).build();
    }

    public static RespResult fail(ExtraCodeEnum extraCode) {
        return fail(extraCode.code,extraCode.msg);
    }

    public static <T> RespResult<T> fail(ExtraCodeEnum extraCode, T data){
        return RespResult.<T>builder().status(FAIL_STATUS).errorCode(extraCode.code).errorMsg(extraCode.msg).data(data).build();
    }

    public boolean result() {
        return status == SUCESS_STATUS;
    }
}
