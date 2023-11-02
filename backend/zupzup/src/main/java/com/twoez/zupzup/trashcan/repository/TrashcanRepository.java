package com.twoez.zupzup.trashcan.repository;


import com.twoez.zupzup.trashcan.domain.Trashcan;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrashcanRepository extends JpaRepository<Trashcan, Long> {}
