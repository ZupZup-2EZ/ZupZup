package com.twoez.zupzup.plogginglog.repository;


import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PloggingLogRepository extends JpaRepository<PloggingLog, Long> {}
