package com.onetwo.mailboxcommonconfig.common.utils;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.dsl.DateTimePath;
import com.querydsl.core.types.dsl.NumberPath;
import com.querydsl.core.types.dsl.StringPath;

import java.time.Instant;

public class QueryDslUtil {

    public static void ifConditionExistAddEqualPredicate(Long condition, NumberPath<Long> path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.eq(condition));
    }

    public static void ifConditionExistAddEqualPredicate(Integer condition, NumberPath<Integer> path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.eq(condition));
    }

    public static void ifConditionExistAddEqualPredicate(String condition, StringPath path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.eq(condition));
    }

    public static void ifConditionExistAddLikePredicate(String condition, StringPath path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.contains(condition));
    }

    public static void ifConditionExistAddGoePredicate(Instant condition, DateTimePath<Instant> path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.goe(condition));
    }

    public static void ifConditionExistAddLoePredicate(Instant condition, DateTimePath<Instant> path, BooleanBuilder booleanBuilder) {
        if (isNotNull(condition)) booleanBuilder.and(path.loe(condition));
    }

    private static boolean isNotNull(Object object) {
        return object != null;
    }
}
