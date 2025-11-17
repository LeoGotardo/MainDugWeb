// ... (Todo o script JS do <head> para gerenciar temas e cores permanece O MESMO) ...
(function() {
    const root = document.documentElement;
    const THEME_KEY = 'theme';
    const COLOR_KEY = 'primaryColor';

    // 1. Definir Tema (Claro/Escuro)
    let preferredTheme = localStorage.getItem(THEME_KEY);
    if (!preferredTheme) {
        const osPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        preferredTheme = osPrefersDark ? 'dark' : 'light';
    }
    root.setAttribute('data-bs-theme', preferredTheme);
    
    // 2. Funções Helper de Cor
    function hexToRgb(hex) {
        let r = 0, g = 0, b = 0;
        if (hex.length == 4) { // #f03
            r = parseInt(hex[1] + hex[1], 16);
            g = parseInt(hex[2] + hex[2], 16);
            b = parseInt(hex[3] + hex[3], 16);
        } else if (hex.length == 7) { // #ff0033
            r = parseInt(hex.substring(1, 3), 16);
            g = parseInt(hex.substring(3, 5), 16);
            b = parseInt(hex.substring(5, 7), 16);
        }
        return `${r}, ${g}, ${b}`;
    }

    function hexToHsl(hex) {
        let r = 0, g = 0, b = 0;
        if (hex.length == 4) {
            r = parseInt(hex[1] + hex[1], 16);
            g = parseInt(hex[2] + hex[2], 16);
            b = parseInt(hex[3] + hex[3], 16);
        } else if (hex.length == 7) {
            r = parseInt(hex.substring(1, 3), 16);
            g = parseInt(hex.substring(3, 5), 16);
            b = parseInt(hex.substring(5, 7), 16);
        }
        r /= 255; g /= 255; b /= 255;
        let max = Math.max(r, g, b), min = Math.min(r, g, b);
        let h, s, l = (max + min) / 2;
        if (max == min) {
            h = s = 0; // grayscale
        } else {
            let d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            switch (max) {
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;
                case g: h = (b - r) / d + 2; break;
                case b: h = (r - g) / d + 4; break;
            }
            h /= 6;
        }
        // Retorna H (0-360), S (0-100), L (0-100)
        return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
    }

    // 3. Função Principal de Aplicação de Cores
    function applyAppTheme(hexColor, theme) {
        const [h, s, l] = hexToHsl(hexColor);
        const rgb = hexToRgb(hexColor);

        // Define as propriedades da COR DE DESTAQUE
        root.style.setProperty('--primary-color', hexColor);
        root.style.setProperty('--primary-color-rgb', rgb);
        root.style.setProperty('--primary-hue', h); // Salva para o CSS usar
        root.style.setProperty('--primary-sat', s + '%'); // Salva para o CSS usar

        // Define as propriedades da PALETA DE FUNDO/TEXTO
        const bgSat = s * 0.15; // Saturação baixa para fundos/textos
        const borderSat = s * 0.2; // Saturação um pouco maior para bordas

        if (theme === 'dark') {
            root.style.setProperty('--page-bg', `hsl(${h}, ${bgSat}%, 10%)`);
            root.style.setProperty('--card-bg', `hsl(${h}, ${bgSat}%, 15%)`);
            root.style.setProperty('--input-bg', `hsl(${h}, ${bgSat}%, 12%)`);
            root.style.setProperty('--custom-border-color', `hsl(${h}, ${borderSat}%, 25%)`);
            root.style.setProperty('--text-primary', `hsl(${h}, ${bgSat}%, 95%)`);
            root.style.setProperty('--text-secondary', `hsl(${h}, ${bgSat}%, 65%)`);
            root.style.setProperty('--table-striped-bg', `hsl(${h}, ${bgSat}%, 12%)`);
            root.style.setProperty('--table-hover-bg', `hsl(${h}, ${bgSat}%, 20%)`);
        } else { // light
            root.style.setProperty('--page-bg', `hsl(${h}, ${bgSat}%, 98%)`);
            root.style.setProperty('--card-bg', `hsl(${h}, ${bgSat}%, 100%)`);
            root.style.setProperty('--input-bg', `hsl(${h}, ${bgSat}%, 100%)`);
            root.style.setProperty('--custom-border-color', `hsl(${h}, ${borderSat}%, 90%)`);
            root.style.setProperty('--text-primary', `hsl(${h}, ${bgSat}%, 10%)`);
            root.style.setProperty('--text-secondary', `hsl(${h}, ${bgSat}%, 40%)`);
            root.style.setProperty('--table-striped-bg', `hsl(${h}, ${bgSat}%, 95%)`);
            root.style.setProperty('--table-hover-bg', `hsl(${h}, ${bgSat}%, 92%)`);
        }
    }
    
    // 4. Aplicar na Carga
    const savedColor = localStorage.getItem(COLOR_KEY) || '#0d6efd';
    applyAppTheme(savedColor, preferredTheme);
})();