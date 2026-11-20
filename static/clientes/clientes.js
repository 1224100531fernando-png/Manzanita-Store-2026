
(() => {
    'use strict';

    const $ = id => document.getElementById(id);

    function filtrarClientes() {
        const busqueda = $('buscarCliente').value
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .toLowerCase()
            .trim();

        const estado = $('filtroEstado').value;
        const filas = [...$('tablaClientes').querySelectorAll('tr')];

        let visibles = 0;

        filas.forEach(fila => {
            const texto = fila.textContent
                .normalize('NFD')
                .replace(/[\u0300-\u036f]/g, '')
                .toLowerCase();

            const coincideTexto = texto.includes(busqueda);
            const coincideEstado =
                estado === 'todos' || fila.dataset.estado === estado;

            const mostrar = coincideTexto && coincideEstado;

            fila.hidden = !mostrar;

            if (mostrar) visibles++;
        });

        $('resultadosBusqueda').textContent = visibles;
        $('sinResultados').hidden = visibles !== 0;

        if (filas.length === 0) {
            $('tituloVacio').textContent =
                'Aún no hay clientes registrados';

            $('mensajeVacio').textContent =
                'Los clientes aparecerán aquí cuando creen una cuenta en la tienda.';
        } else {
            $('tituloVacio').textContent =
                'No se encontraron clientes';

            $('mensajeVacio').textContent =
                'Prueba otra búsqueda o cambia el filtro.';
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        $('buscarCliente').addEventListener('input', filtrarClientes);
        $('filtroEstado').addEventListener('change', filtrarClientes);

        $('btnLimpiar').addEventListener('click', () => {
            $('buscarCliente').value = '';
            $('filtroEstado').value = 'todos';
            filtrarClientes();
        });

        filtrarClientes();
    });
})();
