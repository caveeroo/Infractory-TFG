document.addEventListener('DOMContentLoaded', function () {
    const dateRangePicker = $('#dateRangePicker');
    const applyFilterButton = $('#applyFilter');

    // Set the default date range from today to one week ago
    const startDate = moment().subtract(7, 'days');
    const endDate = moment();

    // Initialize the date range picker
    dateRangePicker.daterangepicker({
        opens: 'left',
        startDate: startDate,
        endDate: endDate,
        autoUpdateInput: true
    }, function (start, end, label) {
        dateRangePicker.val(start.format('MM/DD/YYYY') + ' - ' + end.format('MM/DD/YYYY'));
    });

    // Set the default value in the input
    dateRangePicker.val(startDate.format('MM/DD/YYYY') + ' - ' + endDate.format('MM/DD/YYYY'));

    // Handle the filter button click
    applyFilterButton.on('click', function () {
        const dateRange = dateRangePicker.val();
        const [startDate, endDate] = dateRange.split(' - ');

        $.ajax({
            url: '/filterData',
            method: 'GET',
            data: {
                startDate: startDate,
                endDate: endDate
            },
            success: function (response) {
                console.log('Received data:', response);
                updateStatistics(response);
                updateCharts(response);
            },
            error: function (xhr, status, error) {
                console.error('Error filtering data:', error);
            }
        });
    });

    // Initialize the charts
    const ctxHits = document.getElementById('hitsChart').getContext('2d');
    const ctxLoot = document.getElementById('lootChart').getContext('2d');

    window.hitsChart = new Chart(ctxHits, {
        type: 'bar',
        data: {
            labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
            datasets: [{
                label: 'Hits',
                data: [65, 59, 80, 81, 56, 55, 40],
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                barPercentage: 0.5, // Adjusted bar width
                categoryPercentage: 0.5 // Adjusted bar width
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        color: '#ccc' // Grid color
                    }
                },
                x: {
                    grid: {
                        display: false // Remove vertical grid lines
                    }
                }
            }
        }
    });

    window.lootChart = new Chart(ctxLoot, {
        type: 'line',
        data: {
            labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
            datasets: [{
                label: 'Loot',
                data: [28, 48, 40, 19, 86, 27, 90],
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        color: '#ccc' // Grid color
                    }
                },
                x: {
                    grid: {
                        display: false // Remove vertical grid lines
                    }
                }
            }
        }
    });
});

function updateStatistics(data) {
    $('#phishingServersValue').text(data.phishingServers);
    $('#increasePhishingValue').text(data.increasePhishing > 0 ? `↑ ${data.increasePhishing}` : (data.increasePhishing < 0 ? `↓ ${data.increasePhishing}` : '-'));
    $('#redirectorsValue').text(data.redirectors);
    $('#increaseRedirectorsValue').text(data.increaseRedirectors > 0 ? `↑ ${data.increaseRedirectors}` : (data.increaseRedirectors < 0 ? `↓ ${data.increaseRedirectors}` : '-'));
    $('#generalServersValue').text(data.generalServers);
    $('#increaseGeneralValue').text(data.increaseGeneral > 0 ? `↑ ${data.increaseGeneral}` : (data.increaseGeneral < 0 ? `↓ ${data.increaseGeneral}` : '-'));
}

function updateCharts(data) {
    // Destroy existing charts before creating new ones
    if (window.hitsChart) {
        window.hitsChart.destroy();
    }
    if (window.lootChart) {
        window.lootChart.destroy();
    }

    const ctxHits = document.getElementById('hitsChart').getContext('2d');
    const ctxLoot = document.getElementById('lootChart').getContext('2d');

    // Create new chart instances
    window.hitsChart = new Chart(ctxHits, {
        type: 'bar',
        data: {
            labels: ['Phishing Servers', 'Redirectors', 'General Servers'], // Update labels
            datasets: [{
                label: 'Hits',
                data: [data.phishingServers, data.redirectors, data.generalServers], // Update data
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                barPercentage: 0.5, // Adjusted bar width
                categoryPercentage: 0.5 // Adjusted bar width
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        color: '#ccc' // Grid color
                    }
                },
                x: {
                    grid: {
                        display: false // Remove vertical grid lines
                    }
                }
            }
        }
    });

    window.lootChart = new Chart(ctxLoot, {
        type: 'line',
        data: {
            labels: ['Phishing Servers', 'Redirectors', 'General Servers'], // Update labels
            datasets: [{
                label: 'Loot',
                data: [data.increasePhishing, data.increaseRedirectors, data.increaseGeneral], // Update data
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        color: '#ccc' // Grid color
                    }
                },
                x: {
                    grid: {
                        display: false // Remove vertical grid lines
                    }
                }
            }
        }
    });
}