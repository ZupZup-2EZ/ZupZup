package com.twoez.zupzup.plogging.repository.redis;


import com.twoez.zupzup.plogging.domain.Plogger;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PloggingRedisRepository extends CrudRepository<Plogger, String> {}
