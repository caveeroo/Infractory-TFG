package com.tfg.infractory.domain.repository;

import java.util.Set;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.domain.model.Domain;
import com.tfg.infractory.domain.model.Provider;

@Repository
public interface DomainRepository extends JpaRepository<Domain, Long> {
    Optional<Domain> findDomainByDomain(String domain);

    List<Domain> findDomainsByProvider(Provider provider);

    List<Domain> findAllByDomainIn(Set<String> domains);
}
