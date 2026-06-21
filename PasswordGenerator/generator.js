// PasswordGenerator/generator.js
// Generador de contraseñas en cliente, conforme a NIST SP 800-63B.
//
// Decisiones criptográficas:
// - CSPRNG: crypto.getRandomValues (Web Crypto API, NIST SP 800-90A).
//   Se usa en TODA la generación aleatoria: muestreo de caracteres, selección
//   de posiciones de cobertura y barajado Fisher-Yates. Math.random() no se
//   usa en ninguna parte.
// - Muestreo con rechazo sobre el alfabeto para evitar sesgo de módulo.
// - textContent (no innerHTML) para volcar al DOM. Esto neutraliza XSS
//   A05:2025 por construcción, incluso si en el futuro el alfabeto aceptara
//   entrada del usuario.
// - Cero red, cero almacenamiento, cero dependencias externas en este archivo.
//
// Límites explícitos:
// - No usa eval, Function, setTimeout con string como primer argumento, ni
//   innerHTML con datos del usuario.
// - No llama fetch, XMLHttpRequest, WebSocket, sendBeacon.
// - No escribe en localStorage, sessionStorage, IndexedDB, cookies.

(function () {
    'use strict';

    // Alfabetos. Los ambiguos están separados para excluirlos sin tocar
    // el resto del charset.
    var LOWER = 'abcdefghijklmnopqrstuvwxyz';
    var UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var DIGITS = '0123456789';
    var SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>/?~';

    // Caracteres que generan confusión visual y errores de transcripción.
    // 0/O, 1/l/I son los clásicos; |, `, ', " se añaden por motivos similares
    // (pipes, acentos invertidos y comillas se confunden con L, ', " en
    // algunas tipografías y Copy&Paste).
    var AMBIGUOUS = {
        '0': true, 'O': true, 'o': true,
        '1': true, 'l': true, 'I': true,
        '|': true, '`': true, '\'': true, '"': true
    };

    // Filtro único de ambigüedad. Cualquier consumidor del alfabeto debe
    // pasar por aquí: centralizarlo evita divergencia entre buildAlphabet
    // (muestreo uniforme) y getCharsetParts (cobertura mínima).
    function filterAmbig(s) {
        return s.split('').filter(function (c) { return !AMBIGUOUS[c]; }).join('');
    }

    var $ = function (id) { return document.getElementById(id); };

    var ui = {
        out: $('output'),
        strength: $('strength'),
        bar: $('strengthBar'),
        sLabel: $('strengthLabel'),
        bits: $('entropyBits'),
        length: $('length'),
        lengthVal: $('lengthValue'),
        lower: $('lower'),
        upper: $('upper'),
        digits: $('digits'),
        symbols: $('symbols'),
        noAmbig: $('noambig'),
        generate: $('generate'),
        copy: $('copy'),
        toast: $('toast')
    };

    function refreshToggle(input) {
        var label = input.parentElement;
        if (input.checked) {
            label.classList.add('on');
        } else {
            label.classList.remove('on');
        }
    }

    [ui.lower, ui.upper, ui.digits, ui.symbols, ui.noAmbig].forEach(function (el) {
        refreshToggle(el);
        el.addEventListener('change', function () {
            refreshToggle(el);
            if (!anyCharsetEnabled() && ui.out.textContent && !ui.out.classList.contains('empty')) {
                generate();
            }
        });
    });

    ui.length.addEventListener('input', function () {
        ui.lengthVal.textContent = ui.length.value;
    });
    ui.length.addEventListener('change', function () {
        ui.lengthVal.textContent = ui.length.value;
    });

    function anyCharsetEnabled() {
        return ui.lower.checked || ui.upper.checked || ui.digits.checked || ui.symbols.checked;
    }

    // Construye el alfabeto efectivo según los toggles y la opción de ambigüedad.
    function buildAlphabet() {
        var alpha = '';
        if (ui.lower.checked) alpha += LOWER;
        if (ui.upper.checked) alpha += UPPER;
        if (ui.digits.checked) alpha += DIGITS;
        if (ui.symbols.checked) alpha += SYMBOLS;
        return ui.noAmbig.checked ? filterAmbig(alpha) : alpha;
    }

    // Sub-alfabetos por set, ya filtrados, para forzar cobertura mínima.
    // Usa el mismo filterAmbig que buildAlphabet: si en el futuro se añade
    // un set nuevo, basta con extender LOWER/UPPER/DIGITS/SYMBOLS; la cobertura
    // se ajusta automáticamente.
    function getCharsetParts() {
        return {
            lower: ui.noAmbig.checked ? filterAmbig(LOWER) : LOWER,
            upper: ui.noAmbig.checked ? filterAmbig(UPPER) : UPPER,
            digits: ui.noAmbig.checked ? filterAmbig(DIGITS) : DIGITS,
            symbols: ui.noAmbig.checked ? filterAmbig(SYMBOLS) : SYMBOLS
        };
    }

    // Genera 'len' valores aleatorios criptográficamente seguros en [0, 2^32).
    // crypto.getRandomValues cumple los requisitos de un CSPRNG (NIST SP 800-90A)
    // y está disponible en todos los navegadores modernos.
    function randomValues(len) {
        var buf = new Uint32Array(len);
        crypto.getRandomValues(buf);
        return buf;
    }

    // Muestreo con rechazo: garantiza uniformidad perfecta sobre el alfabeto.
    // El módulo n (donde n = alphabet.length) puede sesgar si no se descartan
    // los valores fuera de rango. Por eso descartamos.
    function pickUniform(alpha) {
        var size = alpha.length;
        if (size === 0) return '';
        // 2^32 es muy superior al alfabeto más grande (~85 con noAmbig),
        // así que el rechazo es raro. Pero se hace correctamente para no
        // introducir sesgo. Probabilísticamente, el bucle tiene < 0.000003%
        // de dispararse por carácter.
        var limit = Math.floor(0x100000000 / size) * size;
        var buf = randomValues(1);
        var r = buf[0];
        while (r >= limit) {
            buf = randomValues(1);
            r = buf[0];
        }
        return alpha.charAt(r % size);
    }

    // Índice uniforme en [0, n) usando CSPRNG y rechazo. Se usa dentro de
    // ensureCoverage para elegir las posiciones de cobertura sin filtrar
    // información (no usar Math.random: Mersenne-Twister es predecible).
    function pickIndexUniform(n) {
        if (n <= 0) return 0;
        var limit = Math.floor(0x100000000 / n) * n;
        var buf = randomValues(1);
        var r = buf[0];
        while (r >= limit) {
            buf = randomValues(1);
            r = buf[0];
        }
        return r % n;
    }

    // Garantiza que la contraseña contiene al menos un carácter de cada
    // charset activo. Sin esto, una longitud corta podría no incluir
    // mayúsculas o símbolos aunque estén activados.
    //
    // Comportamiento documentado: si la longitud pedida es menor que el
    // número de sets activos, sólo se cubren los primeros 'len' sets en
    // el orden de declaración (lower, upper, digits, symbols). Los restantes
    // se omiten silenciosamente. Se documenta en la UI del generador.
    function ensureCoverage(parts, len) {
        var sets = [];
        if (ui.lower.checked) sets.push('lower');
        if (ui.upper.checked) sets.push('upper');
        if (ui.digits.checked) sets.push('digits');
        if (ui.symbols.checked) sets.push('symbols');

        var out = new Array(len);
        var remaining = [];
        for (var i = 0; i < len; i++) remaining.push(i);

        var coverageCount = Math.min(sets.length, len);
        for (var s = 0; s < coverageCount; s++) {
            var idx = pickIndexUniform(remaining.length);
            var pos = remaining[idx];
            // Eliminar pos de remaining en O(1) sin splice.
            remaining[idx] = remaining[remaining.length - 1];
            remaining.pop();
            out[pos] = pickUniform(parts[sets[s]]);
        }

        return { out: out, remaining: remaining };
    }

    // Fisher-Yates con CSPRNG. Importante: NO usar Math.random aquí, o el
    // barajado sería predecible aunque la elección de caracteres sea segura.
    function shuffle(arr) {
        for (var i = arr.length - 1; i > 0; i--) {
            var limit = Math.floor(0x100000000 / (i + 1)) * (i + 1);
            var buf = randomValues(1);
            var r = buf[0];
            while (r >= limit) {
                buf = randomValues(1);
                r = buf[0];
            }
            var j = r % (i + 1);
            var tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
        return arr;
    }

    // Función principal de generación.
    function generate() {
        var len = parseInt(ui.length.value, 10);
        if (!Number.isFinite(len) || len < 8) len = 8;
        if (len > 64) len = 64;

        if (!anyCharsetEnabled()) {
            ui.out.classList.add('empty');
            ui.out.textContent = 'Activa al menos un conjunto de caracteres (a–z, A–Z, 0–9 o símbolos).';
            ui.bar.style.width = '0%';
            ui.sLabel.textContent = '—';
            ui.bits.textContent = '0';
            return;
        }

        var alpha = buildAlphabet();
        if (alpha.length < 2) {
            ui.out.classList.add('empty');
            ui.out.textContent = 'El alfabeto efectivo tiene menos de 2 caracteres. Activa más conjuntos.';
            return;
        }

        var parts = getCharsetParts();
        var covered = ensureCoverage(parts, len);

        for (var i = 0; i < covered.remaining.length; i++) {
            var pos = covered.remaining[i];
            covered.out[pos] = pickUniform(alpha);
        }

        shuffle(covered.out);

        ui.out.classList.remove('empty');
        ui.out.textContent = covered.out.join('');

        // Entropía estimada: log2(alphabetSize) * length (bits).
        // Asunción: símbolo equiprobable e independiente. La cobertura mínima
        // introduce una pequeña desviación de uniformidad, despreciable en
        // longitudes reales (>= 8) y documentada en la UI.
        var bits = Math.log2(alpha.length) * len;
        ui.bits.textContent = bits.toFixed(1);

        var level, label, pct;
        if (bits < 50) {
            level = 'weak'; label = 'Débil'; pct = 25;
        } else if (bits < 80) {
            level = 'fair'; label = 'Aceptable'; pct = 50;
        } else if (bits < 128) {
            level = 'strong'; label = 'Fuerte'; pct = 80;
        } else {
            level = 'epic'; label = 'Épica'; pct = 100;
        }
        ui.strength.setAttribute('data-level', level);
        // pct es un literal controlado (25/50/80/100). style.width con
        // concatenación numérica es seguro por construcción.
        ui.bar.style.width = pct + '%';
        ui.sLabel.textContent = label;
    }

    // Copia al portapapeles usando la API moderna, con fallback a execCommand.
    function copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        // Fallback legacy. Se usa cuando la página NO está en HTTPS o el
        // navegador no soporta Clipboard API. execCommand está deprecado,
        // pero sigue funcionando en navegadores actuales como último recurso.
        return new Promise(function (resolve, reject) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '-1000px';
            ta.style.opacity = '0';
            var inserted = false;
            try {
                document.body.appendChild(ta);
                inserted = true;
                ta.select();
                var ok = document.execCommand('copy');
                if (ok) {
                    resolve();
                } else {
                    reject(new Error('execCommand devolvió false'));
                }
            } catch (e) {
                reject(e);
            } finally {
                if (inserted && ta.parentNode) {
                    ta.parentNode.removeChild(ta);
                }
            }
        });
    }

    var toastTimer = null;
    function showToast(msg) {
        ui.toast.textContent = msg;
        ui.toast.classList.add('show');
        if (toastTimer) clearTimeout(toastTimer);
        // setTimeout con función como primer argumento (no string) es legítimo.
        toastTimer = setTimeout(function () {
            ui.toast.classList.remove('show');
        }, 1800);
    }

    // Listeners principales. El navegador ya dispara 'click' en <button> al
    // pulsar Enter o Espacio, así que no añadimos un listener de keydown
    // extra: provocaría doble generación (una por keydown, otra por el click
    // nativo posterior).
    ui.generate.addEventListener('click', generate);
    ui.copy.addEventListener('click', function () {
        if (ui.out.classList.contains('empty') || !ui.out.textContent) {
            showToast('Nada que copiar todavía');
            return;
        }
        copyToClipboard(ui.out.textContent).then(function () {
            showToast('Copiado al portapapeles');
        }).catch(function () {
            showToast('No se pudo copiar');
        });
    });

    // Generar una primera contraseña al cargar la página.
    generate();
})();
