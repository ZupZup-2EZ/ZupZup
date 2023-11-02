package com.twoez.zupzup.global.support;


import java.util.List;
import java.util.function.Function;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

public class PageCollectors {
    public static <O, T> Page<T> convertContent(
            Page<O> page, Pageable pageable, Function<O, T> mapper) {
        List<T> list = page.getContent().stream().map(mapper).toList();
        return PageableExecutionUtils.getPage(list, pageable, list::size);
    }
}
