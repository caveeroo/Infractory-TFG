package com.tfg.infractory.domain.repository;

import java.util.Set;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Repository
public interface NebulaRepository extends JpaRepository<Nebula, Long> {
    List<Nebula> findByLighthouseTrue();

    List<Nebula> findByLighthouseFalse();

    @Query("SELECT n FROM Nebula n LEFT JOIN FETCH n.lighthouseIps LEFT JOIN FETCH n.allowedCIDRs LEFT JOIN FETCH n.allowedRoles WHERE n.id = :id")
    Optional<Nebula> findByIdWithAllCollections(@Param("id") Long id);

    @Query("SELECT n FROM Nebula n LEFT JOIN FETCH n.lighthouseIps LEFT JOIN FETCH n.allowedCIDRs LEFT JOIN FETCH n.allowedRoles")
    List<Nebula> findAllWithCollections();

    @Query("SELECT n FROM Nebula n LEFT JOIN FETCH n.lighthouseIps WHERE n.id = :id")
    Optional<Nebula> findByIdWithLighthouseIps(Long id);

    @Query("SELECT n FROM Nebula n WHERE n.id = :id")
    Optional<Nebula> findByIdBasic(Long id);

    @Query("SELECT n.lighthouseIps FROM Nebula n WHERE n.id = :id")
    Set<String> findLighthouseIpsById(Long id);

    @Query("SELECT n.roles FROM Nebula n WHERE n.id = :id")
    Set<String> findRolesById(Long id);

    @Query("SELECT n.allowedCIDRs FROM Nebula n WHERE n.id = :id")
    Set<String> findAllowedCIDRsById(Long id);

    @Query("SELECT n.allowedRoles FROM Nebula n WHERE n.id = :id")
    Set<String> findAllowedRolesById(Long id);

    // Correct the query method to use the correct attribute
    @Query("SELECT n.ip FROM Nebula n WHERE n.ip = :ip")
    List<String> findByIp(@Param("ip") String ip);

    @Query("SELECT COUNT(n) FROM Nebula n WHERE n.lighthouse = :lighthouse")
    long countByLighthouse(@Param("lighthouse") Nebula lighthouse);

    @Query("SELECT n FROM Nebula n WHERE n.lighthouse = true")
    List<Nebula> findAllLighthouses();

    // @Query("SELECT n.ip FROM Nebula n WHERE n.ip LIKE CONCAT(:baseIp, '%')")
    // List<String> findIpsInSubnet(@Param("baseIp") String baseIp);

    @Query("SELECT n.ip FROM Nebula n WHERE SUBSTRING(n.ip, 1, LOCATE('.', n.ip, LOCATE('.', n.ip, LOCATE('.', n.ip) + 1) + 1) - 1) = :subnetPrefix")
    List<String> findIpsInSubnet(@Param("subnetPrefix") String subnetPrefix);
}