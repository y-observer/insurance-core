package cn.net.insurance.core.common.model;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * @author panxf
 * @Description 响应给前端H5时因Long类型的雪花ID数值过大，在前端丢失精度，
 *              后端将响应体中的Long统一转换成了String，故这里页码改成了int 避开转换成String
 * @createTime 2021年12月4日 20:39
 */
@Data
public class BasePageResp<T> implements Serializable {

    /**
     * 当前页
     */
    private int current;

    /**
     * 每页的数量
     */
    private int size;

    /**
     * 总页数
     */
    private int pages;

    /**
     * 总记录数
     */
    private int total;

    /**
     * 结果集
     */
    private List<T> records;

}
