document.addEventListener('DOMContentLoaded', function () {
    // Keep track of current service ID for restart functionality
    let currentServiceId = null;

    // Initialize refresh logs functionality
    initializeLogsRefresh();

    // Initialize service inspection
    initializeServiceInspection();

    // Initialize quick actions
    initializeQuickActions();
});

function initializeLogsRefresh() {
    const refreshLogsBtn = document.getElementById('refreshLogsBtn');
    const nodeLogsContainer = document.getElementById('nodeLogs');

    if (refreshLogsBtn && nodeLogsContainer) {
        const nodeId = window.location.pathname.split('/').pop();

        // Initial logs load
        refreshNodeLogs(nodeId, nodeLogsContainer);

        // Setup refresh button
        refreshLogsBtn.addEventListener('click', () => {
            refreshNodeLogs(nodeId, nodeLogsContainer);
        });

        // Auto-refresh every 30 seconds
        setInterval(() => {
            refreshNodeLogs(nodeId, nodeLogsContainer);
        }, 30000);
    }
}

function refreshNodeLogs(nodeId, container) {
    fetch(`/swarm/node/${nodeId}/logs`)
        .then(response => response.text())
        .then(logs => {
            container.textContent = logs;
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
            container.textContent = 'Error loading logs. Please try again.';
        });
}

function initializeServiceInspection() {
    // Setup service inspection modal
    const modal = document.getElementById('serviceInspectModal');
    const restartBtn = document.getElementById('modalRestartService');

    // Handle inspect button clicks
    document.addEventListener('click', (e) => {
        const inspectBtn = e.target.closest('[data-action="inspect"]');
        if (inspectBtn) {
            const serviceCard = inspectBtn.closest('[data-service-id]');
            if (serviceCard) {
                const serviceId = serviceCard.dataset.serviceId;
                inspectService(serviceId);
            }
        }
    });

    // Handle restart button clicks
    document.addEventListener('click', (e) => {
        const restartBtn = e.target.closest('[data-action="restart"]');
        if (restartBtn) {
            const serviceCard = restartBtn.closest('[data-service-id]');
            if (serviceCard) {
                const serviceId = serviceCard.dataset.serviceId;
                restartService(serviceId);
            }
        }
    });

    // Handle restart button in modal
    if (restartBtn) {
        restartBtn.addEventListener('click', () => {
            if (currentServiceId) {
                restartService(currentServiceId);
            }
        });
    }
}

function inspectService(serviceId) {
    currentServiceId = serviceId;

    // Show loading state in modal
    updateServiceModal({
        serviceName: 'Loading...',
        serviceId: 'Loading...',
        status: 'loading',
        dockerImage: 'Loading...',
        replicas: 'Loading...'
    }, 'Loading service details...');

    $('#serviceInspectModal').modal('show');

    fetch(`/swarm/service/${serviceId}/inspect`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                updateServiceModal(data.service, data.inspectOutput);
            } else {
                throw new Error(data.message || 'Failed to inspect service');
            }
        })
        .catch(error => {
            console.error('Error inspecting service:', error);
            // Update modal with error state
            updateServiceModal({
                serviceName: 'Error',
                serviceId: serviceId,
                status: 'error',
                dockerImage: 'N/A',
                replicas: 'N/A'
            }, `Error inspecting service: ${error.message}`);
        });
}

function updateServiceModal(service, inspectOutput) {
    // Update basic information
    document.getElementById('modalServiceName').textContent = service.serviceName;
    document.getElementById('modalServiceId').textContent = service.serviceId;

    // Update status with appropriate styling
    const statusElement = document.getElementById('modalServiceStatus');
    statusElement.textContent = service.status;
    statusElement.className = ''; // Clear existing classes
    statusElement.classList.add(service.status.toLowerCase());

    document.getElementById('modalServiceImage').textContent = service.dockerImage;
    document.getElementById('modalServiceReplicas').textContent = service.replicas;

    // Update environment variables
    const envVarsContainer = document.getElementById('modalServiceEnvVars');
    if (service.environmentVariables && Object.keys(service.environmentVariables).length > 0) {
        const envVarsList = Object.entries(service.environmentVariables)
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        envVarsContainer.innerHTML = `<pre>${envVarsList}</pre>`;
    } else {
        envVarsContainer.innerHTML = '<p>No environment variables set</p>';
    }

    // Update ports
    const portsContainer = document.getElementById('modalServicePorts');
    if (service.publishedPorts) {
        portsContainer.innerHTML = `<pre>${service.publishedPorts}</pre>`;
    } else {
        portsContainer.innerHTML = '<p>No ports published</p>';
    }

    // Update tags
    const tagsContainer = document.getElementById('modalServiceTags');
    if (service.tags && service.tags.length > 0) {
        tagsContainer.innerHTML = service.tags
            .map(tag => `<span class="badge badge-info mr-1">${tag}</span>`)
            .join('');
    } else {
        tagsContainer.innerHTML = '<p>No tags assigned</p>';
    }

    // Update inspect output
    const inspectContainer = document.getElementById('modalServiceInspect');
    if (typeof inspectOutput === 'string') {
        inspectContainer.textContent = inspectOutput;
    } else if (inspectOutput === null || inspectOutput === undefined) {
        inspectContainer.textContent = 'No inspection data available';
    } else {
        try {
            inspectContainer.textContent = JSON.stringify(inspectOutput, null, 2);
        } catch (error) {
            console.error('Error stringifying inspect output:', error);
            inspectContainer.textContent = 'Error formatting inspection data';
        }
    }
}

function restartService(serviceId) {
    if (!confirm('Are you sure you want to restart this service?')) {
        return;
    }

    fetch(`/swarm/service/${serviceId}/restart`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Service restarted successfully');
                location.reload(); // Refresh the page to show updated status
            } else {
                alert('Error restarting service: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error restarting service. Please try again.');
        });
}

function initializeQuickActions() {
    // Drain Node action
    const drainNodeBtn = document.getElementById('drainNodeBtn');
    if (drainNodeBtn) {
        drainNodeBtn.addEventListener('click', () => {
            const nodeId = window.location.pathname.split('/').pop();
            drainNode(nodeId);
        });
    }

    // Remove from Swarm action
    const removeNodeBtn = document.getElementById('removeNodeBtn');
    if (removeNodeBtn) {
        removeNodeBtn.addEventListener('click', () => {
            const nodeId = window.location.pathname.split('/').pop();
            removeFromSwarm(nodeId);
        });
    }
}

function drainNode(nodeId) {
    if (!confirm('Are you sure you want to drain this node? No new tasks will be scheduled on it.')) {
        return;
    }

    fetch(`/swarm/node/${nodeId}/drain`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
                location.reload();
            } else {
                alert('Error draining node: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error draining node. Please try again.');
        });
}

function removeFromSwarm(nodeId) {
    if (!confirm('Are you sure you want to remove this node from the swarm? This action cannot be undone.')) {
        return;
    }

    fetch(`/swarm/node/${nodeId}/remove`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
                window.location.href = '/swarm'; // Redirect to swarm dashboard
            } else {
                alert('Error removing node: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error removing node. Please try again.');
        });
}

// Add event listeners when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function () {
    // Refresh Node Inspection Details Button & Initial Load
    const refreshDetailsBtn = document.getElementById('refreshLogsBtn');
    if (refreshDetailsBtn) {
        refreshDetailsBtn.addEventListener('click', fetchNodeInspectionDetails);
        fetchNodeInspectionDetails(); // Initial details fetch
    }

    // Add listeners for Service Card actions
    const serviceCards = document.querySelectorAll('.service-card');
    serviceCards.forEach(card => {
        const serviceId = card.getAttribute('data-service-id');
        if (!serviceId) return;

        const inspectButton = card.querySelector('button[data-action="inspect"]');
        if (inspectButton) {
            inspectButton.addEventListener('click', () => openServiceInspectModal(serviceId));
        }

        const restartButton = card.querySelector('button[data-action="restart"]');
        if (restartButton) {
            // Use handleRestartService defined below
            restartButton.addEventListener('click', () => handleRestartService(serviceId, 'card'));
        }
    });
});

// Function to fetch and display node inspection details
function fetchNodeInspectionDetails() {
    const detailsContainer = document.getElementById('nodeLogs');
    if (!detailsContainer) return;

    const nodeId = getNodeIdFromPath(); // Helper function to get node ID from URL
    if (!nodeId) {
        detailsContainer.textContent = 'Could not determine Node ID.';
        return;
    }

    detailsContainer.textContent = 'Loading details...';
    // Use the same endpoint as before, as it now returns inspect details
    fetch(`/swarm/node/${nodeId}/logs`)
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.text();
        })
        .then(data => {
            detailsContainer.textContent = data || 'No details available.';
        })
        .catch(error => {
            console.error('Error fetching node details:', error);
            detailsContainer.textContent = 'Error fetching details: ' + error.message;
        });
}

// Function to handle restarting a service (from card or modal)
function handleRestartService(serviceId, context = 'card') {
    const confirmationMessage = 'Are you sure you want to restart this service?';
    if (confirm(confirmationMessage)) {
        fetch(`/swarm/service/${serviceId}/restart`, { method: 'POST' })
            .then(response => response.json()) // Expecting JSON response {success: boolean, message: string}
            .then(data => {
                alert(data.message);
                if (data.success) {
                    window.location.reload(); // Reload to see updated status
                }
            })
            .catch(error => {
                console.error(`Error restarting service (from ${context}):`, error);
                alert('Error restarting service: ' + error.message);
            });
    }
}

// --- Service Inspection Modal Functionality ---

async function openServiceInspectModal(serviceId) {
    console.log(`Opening inspect modal for service ID: ${serviceId}`);
    const modal = $('#serviceInspectModal'); // Using jQuery selector as Bootstrap JS likely uses it
    if (!modal.length) return; // Check if modal exists

    // Reset modal content to loading state
    resetModalContent();
    modal.find('.modal-title').text('Loading Service Details...');

    // Use Bootstrap's event system to populate AFTER the modal is shown
    // Detach previous handler first to avoid multiple triggers
    modal.off('shown.bs.modal').on('shown.bs.modal', async () => {
        console.log('Modal shown event triggered for service ID:', serviceId);
        try {
            // Fetch data in parallel
            const [detailsRes, inspectRes, logsRes] = await Promise.all([
                fetch(`/swarm/service/${serviceId}/details`),
                fetch(`/swarm/service/${serviceId}/inspect`),
                fetch(`/swarm/service/${serviceId}/logs`)
            ]);

            // --- Response Handling --- 
            let details = null;
            let inspectData = null;
            let logs = 'Error loading logs.';

            if (detailsRes.ok) {
                details = await detailsRes.json();
            } else {
                throw new Error(`Failed to fetch service details: ${detailsRes.statusText} (${detailsRes.status})`);
            }

            if (inspectRes.ok) {
                try {
                    const inspectJsonString = await inspectRes.text();
                    inspectData = JSON.parse(inspectJsonString);
                } catch (parseError) {
                    console.error('Error parsing inspect JSON:', parseError);
                    inspectData = { error: "Failed to parse inspect data." };
                }
            } else {
                const errorText = await inspectRes.text();
                inspectData = { error: `Inspect fetch failed: ${inspectRes.statusText} (${inspectRes.status}) - ${errorText}` };
            }

            if (logsRes.ok) {
                logs = await logsRes.text();
                if (!logs || logs.trim() === '') {
                    logs = 'No logs available for this service.';
                }
            } else {
                logs = `Error loading logs: ${logsRes.statusText} (${logsRes.status})`;
                try {
                    const errorBody = await logsRes.text();
                    if (errorBody) logs += ` - ${errorBody}`;
                } catch (e) { }
            }
            // --- End Response Handling ---

            // Populate modal with fetched data
            console.log("Details received:", details);
            console.log("Inspect data received:", inspectData);
            console.log("Logs received:", logs);
            populateModalContent(details, inspectData, logs);

            // Attach restart handler to modal button
            const modalRestartBtn = document.getElementById('modalRestartService');
            if (modalRestartBtn) {
                // Ensure listener is attached only once after modal is fully shown and populated
                const newRestartBtn = modalRestartBtn.cloneNode(true);
                modalRestartBtn.parentNode.replaceChild(newRestartBtn, modalRestartBtn);
                newRestartBtn.addEventListener('click', () => handleRestartService(serviceId, 'modal'));
            }

        } catch (error) {
            console.error('Error fetching service details inside shown.bs.modal:', error);
            modal.find('.modal-title').text('Error Loading Details');
            document.getElementById('modalServiceInspect').textContent = 'Failed to load service details: \n' + error.message;
            document.getElementById('modalServiceLogs').textContent = 'Error loading data.';
            const modalRestartBtn = document.getElementById('modalRestartService');
            if (modalRestartBtn) modalRestartBtn.style.display = 'none';
        }
    });

    modal.modal('show'); // Show modal (population happens on 'shown.bs.modal' event)

    // The old try/catch block that fetched data immediately is removed.
}

function resetModalContent() {
    document.getElementById('modalServiceName').textContent = 'Loading...';
    document.getElementById('modalServiceId').textContent = 'Loading...';
    document.getElementById('modalServiceStatus').textContent = 'Loading...';
    document.getElementById('modalServiceImage').textContent = 'Loading...';
    document.getElementById('modalServiceReplicas').textContent = 'Loading...';
    document.getElementById('modalServiceEnvVars').textContent = 'Loading...';
    document.getElementById('modalServicePorts').textContent = 'Loading...';
    document.getElementById('modalServiceTags').innerHTML = 'Loading...';
    document.getElementById('modalServiceLogs').textContent = 'Loading...'; // Reset logs area
    document.getElementById('modalServiceInspect').textContent = 'Loading...';
    // Make restart button visible initially and enabled
    const modalRestartBtn = document.getElementById('modalRestartService');
    if (modalRestartBtn) {
        modalRestartBtn.style.display = 'inline-block';
        modalRestartBtn.disabled = false;
    }
}

function populateModalContent(details, inspectData, logs) {
    // Populate using the 'details' map
    document.getElementById('modalServiceName').textContent = details.serviceName || 'N/A';
    document.getElementById('modalServiceId').textContent = details.serviceId || 'N/A';
    document.getElementById('modalServiceStatus').textContent = details.status || 'N/A';
    document.getElementById('modalServiceImage').textContent = (details.imageName && details.imageTag && details.imageName !== 'N/A') ? `${details.imageName}:${details.imageTag}` : 'N/A';
    document.getElementById('modalServiceReplicas').textContent = details.replicas !== undefined ? details.replicas : 'N/A';

    // Format Environment Variables
    const envVarsContainer = document.getElementById('modalServiceEnvVars');
    if (details.environmentVariables && Object.keys(details.environmentVariables).length > 0) {
        // Display as key=value pairs, one per line, in a <pre> tag for formatting
        const envString = Object.entries(details.environmentVariables)
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        envVarsContainer.innerHTML = `<pre>${envString}</pre>`;
    } else {
        envVarsContainer.innerHTML = 'No environment variables defined.'; // Use innerHTML here too for consistency
    }

    // Format Published Ports
    const portsContainer = document.getElementById('modalServicePorts');
    if (details.publishedPorts && details.publishedPorts.trim() !== '') {
        portsContainer.innerHTML = `<pre>${details.publishedPorts.replace(/,/g, '\n')}</pre>`; // Display one port mapping per line
    } else {
        portsContainer.innerHTML = 'No ports published.';
    }

    // Format Tags
    const tagsContainer = document.getElementById('modalServiceTags');
    tagsContainer.innerHTML = ''; // Clear previous tags
    if (details.tags && details.tags.length > 0) {
        details.tags.forEach(tag => {
            const span = document.createElement('span');
            span.className = 'tag badge badge-info mr-1'; // Use Bootstrap badge for styling
            span.textContent = tag;
            tagsContainer.appendChild(span);
        });
    } else {
        tagsContainer.innerHTML = 'No tags associated.'; // Use innerHTML
    }

    // Display logs
    console.log(`Setting logs content for #modalServiceLogs with:`, logs);
    try {
        const logElement = document.getElementById('modalServiceLogs');
        // Escape HTML entities in the logs first, then replace newlines with <br>
        const formattedLogs = escapeHtml(logs).replace(/\r\n|\r|\n/g, '<br>');
        logElement.innerHTML = formattedLogs; // Use innerHTML with <br>
    } catch (e) {
        console.error("Error setting logs text content:", e);
        // Use textContent for plain error message as fallback
        document.getElementById('modalServiceLogs').textContent = 'Error displaying logs.';
    }

    // Format and display inspect output
    let inspectOutputText = 'Failed to load or parse inspect data.'; // Default error message
    if (inspectData && typeof inspectData === 'object') {
        if (inspectData.error) {
            inspectOutputText = `Error inspecting service: ${inspectData.error}`;
        } else {
            // Pretty print the parsed JSON object
            inspectOutputText = JSON.stringify(inspectData, null, 2);
        }
    } else if (typeof inspectData === 'string') {
        // This case might happen if JSON parsing failed but we got a string response
        inspectOutputText = inspectData;
    }
    document.getElementById('modalServiceInspect').textContent = inspectOutputText;

    // Update modal title
    $('#serviceInspectModal .modal-title').text(`Details for: ${details.serviceName || 'Service'}`); // Use jQuery to set title
}

// Helper function to get Node ID from the current URL path
function getNodeIdFromPath() {
    const pathParts = window.location.pathname.split('/');
    // Example path: /swarm/node/123
    if (pathParts.length >= 4 && pathParts[1] === 'swarm' && pathParts[2] === 'node') {
        return pathParts[3];
    }
    console.warn('Could not extract Node ID from URL path:', window.location.pathname);
    return null;
}

// Add helper function to escape HTML characters for safe insertion
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
} 