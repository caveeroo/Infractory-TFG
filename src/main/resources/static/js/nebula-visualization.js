document.addEventListener('DOMContentLoaded', function () {
    initializeNetworkVisualization();
});

function initializeNetworkVisualization() {
    const container = document.querySelector('.visualization-container');
    if (!container) return;

    // Get all nodes
    const lighthouseNodes = container.querySelectorAll('.lighthouse');
    const regularNodes = container.querySelectorAll('.node.regular');

    // Create network lines
    createNetworkLines(container, lighthouseNodes, regularNodes);

    // Add hover effects
    addNodeHoverEffects(lighthouseNodes, regularNodes);
}

function createNetworkLines(container, lighthouseNodes, regularNodes) {
    // Remove existing lines
    container.querySelectorAll('.network-line').forEach(line => line.remove());

    // Create lines from lighthouse nodes to regular nodes
    lighthouseNodes.forEach(lighthouse => {
        regularNodes.forEach(node => {
            createLine(container, lighthouse, node);
        });
    });
}

function createLine(container, from, to) {
    const line = document.createElement('div');
    line.className = 'network-line';

    // Get positions
    const fromRect = from.getBoundingClientRect();
    const toRect = to.getBoundingClientRect();
    const containerRect = container.getBoundingClientRect();

    // Calculate relative positions
    const fromX = fromRect.left + fromRect.width / 2 - containerRect.left;
    const fromY = fromRect.top + fromRect.height / 2 - containerRect.top;
    const toX = toRect.left + toRect.width / 2 - containerRect.left;
    const toY = toRect.top + toRect.height / 2 - containerRect.top;

    // Calculate line properties
    const length = Math.sqrt(Math.pow(toX - fromX, 2) + Math.pow(toY - fromY, 2));
    const angle = Math.atan2(toY - fromY, toX - fromX) * 180 / Math.PI;

    // Position and rotate line
    line.style.width = `${length}px`;
    line.style.left = `${fromX}px`;
    line.style.top = `${fromY}px`;
    line.style.transform = `rotate(${angle}deg)`;
    line.style.transformOrigin = '0 0';

    // Add data attributes for hover effects
    line.dataset.from = from.dataset.ip;
    line.dataset.to = to.dataset.ip;

    container.appendChild(line);
}

function addNodeHoverEffects(lighthouseNodes, regularNodes) {
    const allNodes = [...lighthouseNodes, ...regularNodes];

    allNodes.forEach(node => {
        node.addEventListener('mouseenter', () => highlightConnections(node));
        node.addEventListener('mouseleave', () => resetConnections());
    });
}

function highlightConnections(node) {
    const lines = document.querySelectorAll('.network-line');
    const nodeIp = node.dataset.ip;

    lines.forEach(line => {
        if (line.dataset.from === nodeIp || line.dataset.to === nodeIp) {
            line.style.opacity = '1';
            line.style.backgroundColor = 'var(--c2)';
            line.style.height = '3px';
        } else {
            line.style.opacity = '0.1';
        }
    });

    // Highlight connected nodes
    const nodes = document.querySelectorAll('.node');
    nodes.forEach(n => {
        if (n === node) return;
        if (isConnected(n.dataset.ip, nodeIp)) {
            n.style.transform = 'translateY(-5px)';
            n.style.boxShadow = '0 4px 12px rgba(255, 255, 255, 0.2)';
        } else {
            n.style.opacity = '0.5';
        }
    });
}

function resetConnections() {
    const lines = document.querySelectorAll('.network-line');
    lines.forEach(line => {
        line.style.opacity = '';
        line.style.backgroundColor = '';
        line.style.height = '';
    });

    const nodes = document.querySelectorAll('.node');
    nodes.forEach(node => {
        node.style.transform = '';
        node.style.boxShadow = '';
        node.style.opacity = '';
    });
}

function isConnected(ip1, ip2) {
    const lines = document.querySelectorAll('.network-line');
    return Array.from(lines).some(line =>
        (line.dataset.from === ip1 && line.dataset.to === ip2) ||
        (line.dataset.from === ip2 && line.dataset.to === ip1)
    );
}

// Update visualization on window resize
let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        const container = document.querySelector('.visualization-container');
        const lighthouseNodes = container.querySelectorAll('.lighthouse');
        const regularNodes = container.querySelectorAll('.node.regular');
        createNetworkLines(container, lighthouseNodes, regularNodes);
    }, 250);
}); 