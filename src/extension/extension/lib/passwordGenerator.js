// Gerador local de senhas (CSPRNG). Funciona sem login e sem servidor.

const UPPERCASE = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijkmnpqrstuvwxyz';
const NUMBERS = '23456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

function randomIndex(max) {
    // Rejeição para evitar viés do módulo.
    const limit = Math.floor(0x100000000 / max) * max;
    const buffer = new Uint32Array(1);
    do {
        crypto.getRandomValues(buffer);
    } while (buffer[0] >= limit);
    return buffer[0] % max;
}

export function generatePassword(length = 16) {
    const groups = [UPPERCASE, LOWERCASE, NUMBERS, SYMBOLS];
    const all = groups.join('');
    const chars = groups.map((group) => group[randomIndex(group.length)]);
    while (chars.length < length) chars.push(all[randomIndex(all.length)]);

    for (let i = chars.length - 1; i > 0; i--) {
        const j = randomIndex(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}
