package com.study.hello.springcloud.security.service;

import com.study.hello.springcloud.security.dto.AaaDto;

public abstract class AbstractAaaService<T extends AaaDto> implements AaaService {
    @Override
    public String sayHello(AaaDto dto) {
        if (dto.getClass().equals(getGenericTypeClass())) {
            return sayHello01((T) dto);
        }
        return null;
    }

    // 获取泛型类型的Class对象
    protected abstract Class<T> getGenericTypeClass();

    public abstract String sayHello01(T dto);
}
