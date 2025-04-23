package com.tfg.infractory.infrastructure.cloud.client;

import java.util.Map;
import java.util.List;
import org.slf4j.Logger;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Comparator;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import java.util.stream.Collectors;
import jakarta.annotation.PostConstruct;
import java.lang.reflect.ParameterizedType;
import java.util.concurrent.ConcurrentHashMap;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.springframework.web.util.UriComponentsBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Value;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.core.ParameterizedTypeReference;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.springframework.web.client.HttpClientErrorException;

import com.tfg.infractory.infrastructure.cloud.model.Image;
import com.tfg.infractory.infrastructure.cloud.model.digitalocean.DORegion;
import com.tfg.infractory.infrastructure.cloud.model.digitalocean.DOSize;
import com.tfg.infractory.infrastructure.cloud.model.digitalocean.Droplet;
import com.tfg.infractory.infrastructure.cloud.model.digitalocean.DOSSHKey;

@Component
public class DigitalOceanClient {
    private static final Logger logger = LoggerFactory.getLogger(DigitalOceanClient.class);
    private static final String API_BASE_URL = "https://api.digitalocean.com/v2";

    @Value("${digitalocean.api.token}")
    private String apiToken;

    private final RestTemplate restTemplate;
    private final ConcurrentHashMap<String, DORegion> regions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DOSize> sizes = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    public DigitalOceanClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.registerModule(new Jdk8Module());
        this.objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @PostConstruct
    public void init() {
        if (isConfigured()) {
            try {
                fetchAndStoreRegions();
                fetchAndStoreSizes();
                logger.info("Regions fetched: {}", regions.size());
                logger.info("Sizes fetched: {}", sizes.size());
            } catch (Exception e) {
                logger.error("Error initializing DigitalOceanClient", e);
            }
        } else {
            logger.warn("DigitalOcean API token not configured. Skipping initialization.");
        }
    }

    public boolean isConfigured() {
        return apiToken != null && !apiToken.isEmpty() && !apiToken.equals("dummy-token");
    }

    private void fetchAndStoreRegions() {
        List<DORegion> fetchedRegions = getRegions();
        logger.info("Fetched regions: {}", fetchedRegions);
        if (fetchedRegions == null || fetchedRegions.isEmpty()) {
            logger.warn("No regions fetched from the API");
            return;
        }
        for (DORegion region : fetchedRegions) {
            regions.put(region.getSlug(), region);
        }
    }

    private void fetchAndStoreSizes() {
        List<DOSize> fetchedSizes = getSizes();
        logger.info("Fetched sizes: {}", fetchedSizes);
        if (fetchedSizes == null || fetchedSizes.isEmpty()) {
            logger.warn("No sizes fetched from the API");
            return;
        }
        for (DOSize size : fetchedSizes) {
            sizes.put(size.getSlug(), size);
        }
    }

    public DORegion getRegion(String slug) {
        return regions.get(slug);
    }

    public DOSize getSize(String slug) {
        return sizes.get(slug);
    }

    public List<DORegion> getAllRegions() {
        return List.copyOf(regions.values()).stream()
                .sorted((r1, r2) -> Boolean.compare(r2.isAvailable(), r1.isAvailable()))
                .collect(Collectors.toList());
    }

    public List<DOSize> getAllSizes() {
        return List.copyOf(sizes.values()).stream()
                .sorted(Comparator.comparing(DOSize::getPriceHourly))
                .collect(Collectors.toList());
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        if (isConfigured()) {
            headers.setBearerAuth(apiToken);
        }
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    public Droplet createDroplet(Droplet droplet) {
        if (!isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Cannot create droplet.");
            return null;
        }
        logger.info("Creating droplet with configuration: {}", droplet);

        // Create a map for the request body
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("name", droplet.getName());
        requestBody.put("region", droplet.getRegion());
        requestBody.put("size", droplet.getSize());
        requestBody.put("image", droplet.getImage());
        requestBody.put("ssh_keys", droplet.getSshKeys());

        try {
            String requestJson = objectMapper.writeValueAsString(requestBody);
            logger.info("Sending request to DigitalOcean API: {}", requestJson);
        } catch (JsonProcessingException e) {
            logger.error("Error serializing request body", e);
        }

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, createHeaders());
        ResponseEntity<DropletResponse> response = restTemplate.exchange(
                API_BASE_URL + "/droplets",
                HttpMethod.POST,
                request,
                DropletResponse.class);
        logger.info("Droplet creation response received: {}", response.getBody());
        return response.getBody().getDroplet();
    }

    public void deleteDroplet(Long dropletId) {
        HttpEntity<?> request = new HttpEntity<>(createHeaders());
        restTemplate.exchange(
                API_BASE_URL + "/droplets/" + dropletId,
                HttpMethod.DELETE,
                request,
                Void.class);
    }

    public Droplet getDroplet(Long dropletId) {
        HttpEntity<?> request = new HttpEntity<>(createHeaders());
        ResponseEntity<String> response = restTemplate.exchange(
                API_BASE_URL + "/droplets/" + dropletId,
                HttpMethod.GET,
                request,
                String.class);
        try {
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            JsonNode dropletNode = rootNode.path("droplet");
            return objectMapper.treeToValue(dropletNode, Droplet.class);
        } catch (Exception e) {
            logger.error("Error parsing Droplet JSON", e);
            return null;
        }
    }

    private List<DORegion> getRegions() {
        String url = UriComponentsBuilder.fromHttpUrl(API_BASE_URL)
                .path("/regions")
                .toUriString();
        logger.info("Fetching regions from URL: {}", url);
        return getList(url, new ParameterizedTypeReference<List<DORegion>>() {
        });
    }

    private List<DOSize> getSizes() {
        String url = UriComponentsBuilder.fromHttpUrl(API_BASE_URL)
                .path("/sizes")
                .toUriString();
        logger.info("Fetching sizes from URL: {}", url);
        return getList(url, new ParameterizedTypeReference<List<DOSize>>() {
        });
    }

    private <T> List<T> getList(String url, ParameterizedTypeReference<List<T>> responseType) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(apiToken);
            HttpEntity<?> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() != HttpStatus.OK) {
                logger.error("Error response from DigitalOcean API: {}", response.getBody());
                return new ArrayList<>();
            }

            JsonNode rootNode = objectMapper.readTree(response.getBody());
            logger.debug("Parsed JSON: {}", rootNode);

            JsonNode itemsNode = rootNode.path("images");
            if (itemsNode.isMissingNode()) {
                itemsNode = rootNode.path("sizes");
            }
            if (itemsNode.isMissingNode()) {
                itemsNode = rootNode.path("regions");
            }
            if (itemsNode.isMissingNode()) {
                logger.warn("Neither 'images', 'sizes' nor 'regions' field found in response");
                return new ArrayList<>();
            }

            @SuppressWarnings("unchecked")
            CollectionType type = objectMapper.getTypeFactory().constructCollectionType(
                    List.class,
                    (Class<T>) ((ParameterizedType) responseType.getType()).getActualTypeArguments()[0]);
            return objectMapper.convertValue(itemsNode, type);

        } catch (Exception e) {
            logger.error("Unexpected exception while processing response from DigitalOcean API: {}", url, e);
            return new ArrayList<>();
        }
    }

    public List<Droplet> getAllDroplets() {
        JsonNode response = makeRequest("/droplets", HttpMethod.GET, null);
        List<Droplet> droplets = new ArrayList<>();
        if (response.has("droplets") && response.get("droplets").isArray()) {
            for (JsonNode dropletNode : response.get("droplets")) {
                droplets.add(objectMapper.convertValue(dropletNode, Droplet.class));
            }
        }
        return droplets;
    }

    private JsonNode makeRequest(String endpoint, HttpMethod method, Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(apiToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<?> entity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.exchange(
                API_BASE_URL + endpoint,
                method,
                entity,
                String.class);

        try {
            return objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JSON response", e);
        }
    }

    public List<Image> getAllImages() {
        String url = UriComponentsBuilder.fromHttpUrl(API_BASE_URL)
                .path("/images")
                .queryParam("type", "distribution")
                .toUriString();
        logger.info("Fetching images from URL: {}", url);
        List<Image> images = getList(url, new ParameterizedTypeReference<List<Image>>() {
        });
        logger.info("Fetched {} images from DigitalOcean", images.size());
        return images;
    }

    public List<DOSSHKey> getAllSshKeys() {
        String url = API_BASE_URL + "/account/keys";
        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(createHeaders()),
                String.class);

        try {
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            JsonNode sshKeysNode = rootNode.path("ssh_keys");
            if (sshKeysNode.isMissingNode() || !sshKeysNode.isArray()) {
                logger.warn("No 'ssh_keys' array found in the response");
                return new ArrayList<>();
            }

            List<DOSSHKey> sshKeys = new ArrayList<>();
            for (JsonNode keyNode : sshKeysNode) {
                DOSSHKey sshKey = objectMapper.treeToValue(keyNode, DOSSHKey.class);
                sshKeys.add(sshKey);
            }

            return sshKeys;
        } catch (Exception e) {
            logger.error("Error parsing SSH keys response", e);
            return new ArrayList<>();
        }
    }

    public DOSSHKey getSshKeyByFingerprint(String fingerprint) {
        String url = API_BASE_URL + "/account/keys/" + fingerprint;
        try {
            ResponseEntity<DOSSHKeyResponse> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(createHeaders()),
                    DOSSHKeyResponse.class);
            return response.getBody().getSshKey();
        } catch (HttpClientErrorException.NotFound e) {
            logger.info("SSH key with fingerprint {} not found", fingerprint);
            return null;
        } catch (Exception e) {
            logger.error("Error retrieving SSH key with fingerprint {}", fingerprint, e);
            return null;
        }
    }

    public DOSSHKey createSshKey(String name, String publicKey) {
        String url = API_BASE_URL + "/account/keys";
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("name", name);
        requestBody.put("public_key", publicKey);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, createHeaders());
        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                String.class);

        try {
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            JsonNode sshKeyNode = rootNode.path("ssh_key");
            if (sshKeyNode.isMissingNode()) {
                logger.error("SSH key node not found in response");
                return null;
            }
            return objectMapper.treeToValue(sshKeyNode, DOSSHKey.class);
        } catch (Exception e) {
            logger.error("Error parsing SSH key creation response", e);
            return null;
        }
    }

    public void deleteSshKey(String keyIdOrFingerprint) {
        String url = API_BASE_URL + "/account/keys/" + keyIdOrFingerprint;
        restTemplate.exchange(
                url,
                HttpMethod.DELETE,
                new HttpEntity<>(createHeaders()),
                Void.class);
    }

    public boolean sshKeyExists(String fingerprint) {
        String url = API_BASE_URL + "/account/keys";
        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(createHeaders()),
                String.class);

        try {
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            JsonNode sshKeysNode = rootNode.path("ssh_keys");
            if (sshKeysNode.isArray()) {
                for (JsonNode keyNode : sshKeysNode) {
                    if (fingerprint.equals(keyNode.path("fingerprint").asText())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error checking SSH key existence", e);
        }
        return false;
    }
}

class DOSSHKeyResponse {
    private DOSSHKey ssh_key;

    public DOSSHKey getSshKey() {
        return ssh_key;
    }

    public void setSshKey(DOSSHKey ssh_key) {
        this.ssh_key = ssh_key;
    }
}

class DOSSHKeyListResponse {
    private List<DOSSHKey> ssh_keys;

    public List<DOSSHKey> getSshKeys() {
        return ssh_keys;
    }

    public void setSshKeys(List<DOSSHKey> ssh_keys) {
        this.ssh_keys = ssh_keys;
    }
}

class DropletResponse {
    private Droplet droplet;

    public Droplet getDroplet() {
        return droplet;
    }

    public void setDroplet(Droplet droplet) {
        this.droplet = droplet;
    }
}