package cn.net.insurance.core.base.model;

import lombok.Getter;


@Getter
public class GwInsuranceException extends RuntimeException {

    private String code;
    private String message;

    public GwInsuranceException(ExtraCodeEnum resultEnum) {
        super(resultEnum.getMsg());
        this.code = resultEnum.getCode();
        this.message = resultEnum.getMsg();
    }

    public GwInsuranceException(String code, String message) {
        super(message);
        this.code = code;
        this.message = message;
    }
}