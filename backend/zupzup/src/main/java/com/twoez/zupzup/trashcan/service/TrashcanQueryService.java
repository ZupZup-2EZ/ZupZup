package com.twoez.zupzup.trashcan.service;


import com.twoez.zupzup.trashcan.domain.Trashcan;
import com.twoez.zupzup.trashcan.repository.TrashcanQueryRepository;
import java.math.BigDecimal;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class TrashcanQueryService {

    private final TrashcanQueryRepository trashcanQueryRepository;

    public List<Trashcan> findByLocation(BigDecimal latitude, BigDecimal longitude) {
        return trashcanQueryRepository.findByLocation(latitude, longitude);
    }
}
