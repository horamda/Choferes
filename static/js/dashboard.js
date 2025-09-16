/**
 * Dashboard Management Module
 * Handles dashboard data fetching, rendering, and user interactions
 */

class DashboardManager {
    constructor() {
        this.charts = [];
        this.isLoading = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadInitialData();
    }

    bindEvents() {
        // Form filters
        document.getElementById('sector_id')?.addEventListener('change', () => this.updateDashboard());
        document.getElementById('fecha_inicio')?.addEventListener('change', () => this.updateDashboard());
        document.getElementById('fecha_fin')?.addEventListener('change', () => this.updateDashboard());
        document.getElementById('btn-actualizar')?.addEventListener('click', () => this.updateDashboard());
        document.getElementById('btn-reset')?.addEventListener('click', () => this.resetFilters());

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target.closest('.dashboard-filter')) {
                this.updateDashboard();
            }
        });
    }

    loadInitialData() {
        document.addEventListener('DOMContentLoaded', () => {
            this.updateDashboard();
        });
    }

    async updateDashboard() {
        if (this.isLoading) return;

        const filters = this.getFilters();
        if (!this.validateFilters(filters)) return;

        this.setLoadingState(true);
        this.clearContent();

        try {
            const data = await this.fetchDashboardData(filters);
            this.renderDashboard(data);
        } catch (error) {
            this.showError('Error al cargar el dashboard: ' + error.message);
        } finally {
            this.setLoadingState(false);
        }
    }

    getFilters() {
        return {
            sector_id: document.getElementById('sector_id')?.value,
            fecha_inicio: document.getElementById('fecha_inicio')?.value,
            fecha_fin: document.getElementById('fecha_fin')?.value
        };
    }

    validateFilters(filters) {
        const { fecha_inicio, fecha_fin } = filters;

        if (fecha_inicio && fecha_fin && new Date(fecha_inicio) > new Date(fecha_fin)) {
            this.showError('La fecha de inicio no puede ser posterior a la fecha fin');
            return false;
        }

        return true;
    }

    async fetchDashboardData(filters) {
        const { sector_id, fecha_inicio, fecha_fin } = filters;
        const params = new URLSearchParams({
            sector_id: sector_id || '',
            from: fecha_inicio || '',
            to: fecha_fin || ''
        });

        // Fetch summary and series data in parallel
        const [summaryResponse, seriesPromises] = await Promise.all([
            fetch(`/api/resumen_dashboard?${params}`),
            this.fetchSeriesData(filters)
        ]);

        if (!summaryResponse.ok) {
            throw new Error(`HTTP ${summaryResponse.status}: ${summaryResponse.statusText}`);
        }

        const summaryData = await summaryResponse.json();

        if (!summaryData.tarjetas || summaryData.tarjetas.length === 0) {
            throw new Error('No hay datos disponibles para los filtros seleccionados');
        }

        return {
            tarjetas: summaryData.tarjetas,
            series: await Promise.all(seriesPromises)
        };
    }

    async fetchSeriesData(filters) {
        const { sector_id, fecha_inicio, fecha_fin } = filters;

        // This would need to be adjusted based on how the series API works
        // For now, returning empty array - will be populated when rendering
        return [];
    }

    async fetchIndicatorSeries(sector_id, indicador_id, fecha_inicio, fecha_fin) {
        const params = new URLSearchParams({
            sector_id: sector_id || '',
            indicador_id,
            from: fecha_inicio || '',
            to: fecha_fin || ''
        });

        const response = await fetch(`/api/serie_indicador?${params}`);
        if (!response.ok) {
            throw new Error(`Error al cargar serie: ${response.statusText}`);
        }

        return await response.json();
    }

    renderDashboard(data) {
        const { tarjetas } = data;
        const cardsContainer = document.getElementById('contenedorTarjetas');
        const chartsContainer = document.getElementById('contenedorGraficos');

        // Render cards
        tarjetas.forEach(tarjeta => {
            this.renderCard(cardsContainer, tarjeta);
            this.renderChart(chartsContainer, tarjeta);
        });
    }

    renderCard(container, tarjeta) {
        const cardHtml = `
            <div class="col-6 col-sm-4 col-md-3 col-xl-2">
                <div class="kpi-card card h-100"
                     style="background: linear-gradient(135deg, ${tarjeta.color || '#667eea'} 0%, ${this.adjustColor(tarjeta.color || '#667eea', -20)} 100%)"
                     role="region"
                     aria-label="Indicador ${tarjeta.indicador}: ${tarjeta.valor}">
                    <div class="card-body text-center d-flex flex-column justify-content-center position-relative">
                        <div class="kpi-label mb-2">${tarjeta.indicador}</div>
                        <div class="kpi-value">${this.formatNumber(tarjeta.valor)}</div>
                    </div>
                </div>
            </div>`;

        container.insertAdjacentHTML('beforeend', cardHtml);
    }

    async renderChart(container, tarjeta) {
        const filters = this.getFilters();
        const chartId = 'g_' + this.sanitizeId(tarjeta.indicador);

        const chartHtml = `
            <div class="col-12 col-md-6">
                <div class="chart-card card h-100">
                    <div class="card-body">
                        <h5 class="card-title fw-bold text-dark mb-4">${tarjeta.indicador}</h5>
                        <div class="chart-container">
                            <canvas id="${chartId}" aria-label="Gráfico de ${tarjeta.indicador}" role="img"></canvas>
                        </div>
                    </div>
                </div>
            </div>`;

        container.insertAdjacentHTML('beforeend', chartHtml);

        try {
            const seriesData = await this.fetchIndicatorSeries(
                filters.sector_id,
                tarjeta.indicador_id,
                filters.fecha_inicio,
                filters.fecha_fin
            );

            this.createChart(chartId, tarjeta, seriesData);
        } catch (error) {
            console.error(`Error loading chart for ${tarjeta.indicador}:`, error);
            const canvas = document.getElementById(chartId);
            if (canvas) {
                canvas.parentElement.innerHTML = `
                    <div class="alert alert-modern alert-warning d-flex align-items-center">
                        <i class="bi bi-exclamation-triangle-fill me-3 fs-4"></i>
                        <div>
                            <strong>Error al cargar el gráfico</strong><br>
                            <small>No se pudieron obtener los datos para ${tarjeta.indicador}</small>
                        </div>
                    </div>`;
            }
        }
    }

    createChart(canvasId, tarjeta, seriesData) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        const chart = new Chart(ctx, {
            type: seriesData.tipo || 'bar',
            data: {
                labels: seriesData.labels || [],
                datasets: [{
                    label: tarjeta.indicador,
                    data: seriesData.data || [],
                    borderColor: seriesData.color || tarjeta.color || '#0d6efd',
                    backgroundColor: seriesData.color || tarjeta.color || '#0d6efd',
                    fill: seriesData.fill || false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });

        this.charts.push(chart);
    }

    setLoadingState(loading) {
        this.isLoading = loading;
        const btn = document.getElementById('btn-actualizar');
        const resetBtn = document.getElementById('btn-reset');

        if (btn) {
            btn.disabled = loading;
            btn.innerHTML = loading ?
                '<span class="spinner-border spinner-border-sm me-2"></span>Cargando...' :
                'Actualizar';
        }

        if (resetBtn) {
            resetBtn.disabled = loading;
        }

        // Show/hide loading overlay
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.style.display = loading ? 'flex' : 'none';
        }
    }

    clearContent() {
        const cardsContainer = document.getElementById('contenedorTarjetas');
        const chartsContainer = document.getElementById('contenedorGraficos');

        if (cardsContainer) cardsContainer.innerHTML = '';
        if (chartsContainer) chartsContainer.innerHTML = '';

        // Destroy existing charts
        this.charts.forEach(chart => chart.destroy());
        this.charts = [];
    }

    showError(message) {
        const alertHtml = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>`;

        const container = document.querySelector('.dashboard-container') ||
                         document.querySelector('main') ||
                         document.body;

        container.insertAdjacentHTML('afterbegin', alertHtml);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const alert = container.querySelector('.alert');
            if (alert) alert.remove();
        }, 5000);
    }

    resetFilters() {
        // Reset to default values (could be enhanced to store original values)
        const today = new Date();
        const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());

        document.getElementById('fecha_inicio').value = lastMonth.toISOString().split('T')[0];
        document.getElementById('fecha_fin').value = today.toISOString().split('T')[0];
        document.getElementById('sector_id').selectedIndex = 0;

        this.updateDashboard();
    }

    sanitizeId(str) {
        return str.replace(/[^a-zA-Z0-9]/g, '_');
    }

    adjustColor(color, amount) {
        // Simple color adjustment for gradient
        const usePound = color[0] === '#';
        const col = usePound ? color.slice(1) : color;

        const num = parseInt(col, 16);
        let r = (num >> 16) + amount;
        let g = (num >> 8 & 0x00FF) + amount;
        let b = (num & 0x0000FF) + amount;

        r = r > 255 ? 255 : r < 0 ? 0 : r;
        g = g > 255 ? 255 : g < 0 ? 0 : g;
        b = b > 255 ? 255 : b < 0 ? 0 : b;

        return (usePound ? '#' : '') + (r << 16 | g << 8 | b).toString(16);
    }

    formatNumber(num) {
        // Format large numbers with K, M suffixes
        if (typeof num !== 'number') return num;

        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new DashboardManager();
});