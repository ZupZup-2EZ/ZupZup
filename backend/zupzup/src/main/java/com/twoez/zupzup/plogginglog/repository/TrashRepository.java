package com.twoez.zupzup.plogginglog.repository;


import com.twoez.zupzup.plogginglog.domain.Trash;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrashRepository extends JpaRepository<Trash, Long> {
    Optional<Trash> findByPloggingLogId(Long ploggingLogId);
}
