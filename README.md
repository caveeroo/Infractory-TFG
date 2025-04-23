<div align="center">
  <h1>Infractory</h1>
  <p><strong>Your Central Command for Multi-Cloud Red Team Infrastructure</strong></p>
  <p><i>Seamlessly manage, replicate, and secure your hybrid Red Team environments across AWS, DigitalOcean, and more!</i></p>
</div>

Infractory is a powerful **Java-based web application** designed to streamline the management of complex, multi-cloud, and hybrid Red Team infrastructure. It provides a unified interface to control resources, replicate environments, and securely handle sensitive data across diverse cloud providers.

## ✨ Features

Infractory comes packed with features to supercharge your Red Team operations:

* **Unified Multi-Cloud Management**: Control infrastructure across AWS, DigitalOcean, Azure (and more!) from a single, intuitive dashboard.
* **Environment Replication**: Spin up standardized Red Team environments quickly and consistently across different cloud platforms.
* **Secure E2E Comms with Nebula**: Utilizes Nebula's decentralized VPN mesh network for secure, flexible, and resilient connectivity between all your components.
* **Effortless Container Orchestration**: Manage and scale your containerized tools and services efficiently using Docker Swarm.
* **Robust Secrets Management**: Securely store, organize, and access operational secrets, credentials, and loot with built-in encryption.
* **Intuitive Web Interface**: A user-friendly dashboard makes managing and monitoring your infrastructure straightforward.

## 🚀 Getting Started

Get Infractory up and running in a few steps:

### Prerequisites

*(Ensure you have Java JDK and Gradle installed on your system)*

### Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/caveeroo/Infractory-TFG.git](https://github.com/caveeroo/Infractory-TFG.git)
    cd Infractory
    ```

2.  **Build the Project:**
    ```bash
    ./gradlew build installDist
    ```

### Configuration

3.  **Configure Services:**
    * Set up your **Nebula VPN** network. *(Refer to Nebula documentation and `src/main/resources/nebula/config.yml`)*
    * Initialize **Docker Swarm**. *(Refer to Docker documentation and `compose.yaml`)*
    * Add your **Cloud Provider Credentials** securely (e.g., via environment variables or a secrets manager - see `src/main/resources/application-dev.properties` for local dev setup examples).
    * Configure the **Database** (PostgreSQL) connection (see `compose.yaml` and `src/main/resources/application.properties`).

4.  **Run the Application:**
    ```bash
    ./gradlew bootRun
    ```

5.  **Access the Web Interface:**
    * Open your browser and navigate to `http://localhost:8080` (or the configured port).

*(For more detailed guides and references, check out the [HELP.md](HELP.md) file)*

## 🛠️ Usage

Once installed, access the Infractory web interface to:

1.  **Deploy Instances**: Create new servers on your chosen cloud providers.
2.  **Configure Nebula**: Set up your secure network overlay.
3.  **Manage Docker Swarm**: Deploy and manage containerized services.
4.  **Store Secrets**: Add and manage sensitive credentials and operational data.
5.  **Monitor Infrastructure**: Keep an eye on your deployed resources via the dashboard.

## 🆘 Support

Need help or have questions? Feel free to open an issue on the GitHub repository.

---

<div align="center">
  Made with ❤️  by @caveeroo
</div>
