(function() {
    const dropdown = document.getElementById('dropdown-{{ config.name }}');
    if (!dropdown) return;
    
    // Dados dos produtos/itens vindos do backend
    let itemsData = [];
    try {
        itemsData = JSON.parse('{{ products | tojson | safe }}');
        // Garante que seja um array
        if (!Array.isArray(itemsData)) {
            itemsData = [];
        }
    } catch (e) {
        console.error('Erro ao carregar dados do dropdown:', e);
        itemsData = [];
    }
    
    // Elementos do DOM
    const hiddenInput = dropdown.querySelector('input[type="hidden"]');
    const toggleButton = dropdown.querySelector('.dropdown-toggle');
    const dropdownMenu = dropdown.querySelector('.dropdown-menu');
    const itemsContainer = dropdown.querySelector('.dropdown-items');
    const searchInput = dropdown.querySelector('.dropdown-search-input');
    
    // NOVO: Valores de pré-seleção
    const selectedValue = '{{ selectedValue if selectedValue else "" }}';
    const isAccount = {{ 'true' if account else 'false' }};
    
    // NOVO: Função para encontrar item pré-selecionado
    function findPreselectedItem() {
        if (!selectedValue || !isAccount) return null;
        
        return itemsData.find(item => {
            // Tenta diferentes campos de ID dependendo do tipo
            const itemId = item.itemId || item.productId || item.storeId || item.rpiId || item.integrationId || item.id;
            return itemId && itemId.toString() === selectedValue.toString();
        });
    }
    
    // NOVO: Função para configurar item pré-selecionado
    function setupPreselectedItem() {
        const preselectedItem = findPreselectedItem();
        
        if (preselectedItem) {
            // Atualiza o valor do hidden input
            hiddenInput.value = preselectedItem.itemId || preselectedItem.productId || preselectedItem.storeId || preselectedItem.rpiId || preselectedItem.integrationId || preselectedItem.id || '';
            
            // Atualiza o botão do dropdown
            updateToggleButton(preselectedItem);
            
            // Marca o item como selecionado no HTML
            setTimeout(() => {
                const wrappers = dropdown.querySelectorAll('.dropdown-item-wrapper');
                wrappers.forEach(wrapper => {
                    if (wrapper.getAttribute('data-selected') === 'true') {
                        wrapper.classList.add('selected');
                    }
                });
            }, 100);
        }
    }
    
    // NOVO: Função para atualizar o botão do dropdown
    function updateToggleButton(item) {
        if (!item) {
            toggleButton.innerHTML = '<span class="placeholder-text">Selecione {{ config.label.lower() }}</span>';
            return;
        }
        
        // HTML da imagem (para produtos)
        const imageHtml = item.imageUrl ? 
            `<img src="${item.imageUrl}" alt="${item.name || ''}" class="item-image" onerror="this.src='/static/images/productPlaceholder.jpeg'">` : '';
        
        // HTML do valor (para produtos)
        const valueHtml = item.value ? 
            `<span class="item-value">R$ ${parseFloat(item.value).toFixed(2)}</span>` : '';
        
        // HTML do status (para RPIs e integrações)
        let statusHtml = '';
        if (item.hasOwnProperty('online')) {
            const statusClass = item.online ? 'status-online' : 'status-offline';
            const statusText = item.online ? 'Online' : 'Offline';
            statusHtml = `<span class="item-status ${statusClass}">${statusText}</span>`;
        } else if (item.hasOwnProperty('active')) {
            const statusClass = item.active ? 'status-active' : 'status-inactive';
            const statusText = item.active ? 'Ativa' : 'Inativa';
            statusHtml = `<span class="item-status ${statusClass}">${statusText}</span>`;
        }
        
        toggleButton.innerHTML = `
            <div class="selected-item">
                ${imageHtml}
                <div class="item-details">
                    <span class="item-name">${item.name ?? ''}</span>
                    ${valueHtml}
                    ${statusHtml}
                </div>
            </div>
        `;
    }
    
    // Função para renderizar itens
    function renderItems(items) {
        if (!itemsContainer) return;
        
        itemsContainer.innerHTML = '';
        
        if (!items || items.length === 0) {
            itemsContainer.innerHTML = '<div class="dropdown-item-empty">Nenhum {{ config.label.lower() }} encontrado</div>';
            return;
        }
        
        items.forEach(item => {
            const wrapper = document.createElement('div');
            wrapper.className = 'dropdown-item-wrapper';
            
            const itemId = item.itemId || item.productId || item.storeId || item.rpiId || item.integrationId || item.id || '';
            wrapper.setAttribute('data-id', item.id || '');
            wrapper.setAttribute('data-name', item.name || '');
            wrapper.setAttribute('data-item-id', itemId);
            
            // NOVO: Marca como selecionado se for o item pré-selecionado
            if (selectedValue && itemId.toString() === selectedValue.toString()) {
                wrapper.classList.add('selected');
                wrapper.setAttribute('data-selected', 'true');
            }
            
            // HTML da imagem (para produtos)
            const imageHtml = item.imageUrl ? 
                `<img src="${item.imageUrl}" alt="${item.name || ''}" class="item-image" onerror="this.src='/static/images/productPlaceholder.jpeg'">` : '';
            
            // HTML do valor (para produtos)
            const valueHtml = item.value ? 
                `<span class="item-value">R$ ${parseFloat(item.value).toFixed(2)}</span>` : '';
            
            // HTML do ID
            const idHtml = item.id ? 
                `<span class="item-id">ID: ${item.id}</span>` : '';
            
            // HTML do status (para RPIs e integrações)
            let statusHtml = '';
            if (item.hasOwnProperty('online')) {
                const statusClass = item.online ? 'status-online' : 'status-offline';
                const statusText = item.online ? 'Online' : 'Offline';
                statusHtml = `<span class="item-status ${statusClass}">${statusText}</span>`;
            } else if (item.hasOwnProperty('active')) {
                const statusClass = item.active ? 'status-active' : 'status-inactive';
                const statusText = item.active ? 'Ativa' : 'Inativa';
                statusHtml = `<span class="item-status ${statusClass}">${statusText}</span>`;
            }
            
            // HTML do tipo (para integrações)
            const typeHtml = item.type ? 
                `<span class="item-type">${item.type}</span>` : '';
            
            // HTML da descrição (para lojas)
            const descriptionHtml = item.description ? 
                `<span class="item-description">${item.description}</span>` : '';
            
            // NOVO: Indicador de selecionado
            const selectedIndicator = wrapper.classList.contains('selected') ? 
                `<span class="selected-indicator">✓ Selecionado</span>` : '';
            
            wrapper.innerHTML = `
                <div class="dropdown-item">
                    ${imageHtml}
                    <div class="item-details">
                        <span class="item-name">${item.name ?? ''}</span>
                        ${valueHtml}
                        ${statusHtml}
                        ${typeHtml}
                        ${descriptionHtml}
                        ${idHtml}
                        ${selectedIndicator}
                    </div>
                </div>
            `;
            
            // Event listener para seleção
            wrapper.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                // Remove seleção anterior
                dropdown.querySelectorAll('.dropdown-item-wrapper').forEach(el => {
                    el.classList.remove('selected');
                    // Remove indicador de selecionado
                    const indicator = el.querySelector('.selected-indicator');
                    if (indicator) indicator.remove();
                });
                
                // Adiciona seleção atual
                wrapper.classList.add('selected');
                
                // Adiciona indicador de selecionado
                const itemDetails = wrapper.querySelector('.item-details');
                if (itemDetails && !itemDetails.querySelector('.selected-indicator')) {
                    itemDetails.insertAdjacentHTML('beforeend', '<span class="selected-indicator">✓ Selecionado</span>');
                }
                
                hiddenInput.value = itemId;
                
                // Atualiza o botão com o item selecionado
                updateToggleButton(item);
                
                closeDropdown();
            });
            
            itemsContainer.appendChild(wrapper);
        });
    }
    
    // Função para abrir dropdown
    function openDropdown() {
        if (!dropdownMenu) return;
        
        // Fecha outros dropdowns
        document.querySelectorAll('.dropdown-menu').forEach(menu => {
            if (menu !== dropdownMenu) {
                menu.style.display = 'none';
                menu.classList.remove('show');
            }
        });
        
        dropdownMenu.classList.remove('hide');
        dropdownMenu.classList.add('show');
        dropdownMenu.style.display = 'block';
        toggleButton.setAttribute('aria-expanded', 'true');
        
        // Foca no campo de busca se existir
        if (searchInput) {
            setTimeout(() => searchInput.focus(), 100);
        }
    }
    
    // Função para fechar dropdown
    function closeDropdown() {
        if (!dropdownMenu) return;
        
        dropdownMenu.classList.remove('show');
        dropdownMenu.classList.add('hide');
        toggleButton.setAttribute('aria-expanded', 'false');
        
        setTimeout(() => {
            if (dropdownMenu.classList.contains('hide')) {
                dropdownMenu.style.display = 'none';
                dropdownMenu.classList.remove('hide');
            }
        }, 300);
    }
    
    // Event listener para busca
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            const filteredItems = itemsData.filter(item => 
                (item.name && item.name.toLowerCase().includes(query)) ||
                (item.id && item.id.toString().toLowerCase().includes(query)) ||
                (item.type && item.type.toLowerCase().includes(query))
            );
            renderItems(filteredItems);
        });
        
        // Impede que o dropdown feche ao clicar no input de busca
        searchInput.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
    
    // Event listener para o botão toggle
    if (toggleButton) {
        toggleButton.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const isOpen = dropdownMenu.style.display === 'block';
            if (isOpen) {
                closeDropdown();
            } else {
                openDropdown();
            }
        });
    }
    
    // Fecha dropdown ao clicar fora
    document.addEventListener('click', function(e) {
        if (dropdown && !dropdown.contains(e.target)) {
            closeDropdown();
        }
    });
    
    // Fecha dropdown ao pressionar ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeDropdown();
        }
    });
    
    // Inicialização
    renderItems(itemsData);
    
    // NOVO: Configura item pré-selecionado após renderizar
    setTimeout(() => {
        setupPreselectedItem();
    }, 100);
})();