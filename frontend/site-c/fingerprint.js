/**
 * Device Fingerprint Generator
 * Collects: Canvas, WebGL, UA, Screen, Fonts
 * Returns a hash representing the device fingerprint
 */
const DeviceFingerprint = (function() {
    'use strict';

    async function generate() {
        const components = {};

        // 1. Canvas fingerprint
        components.canvas = getCanvasFingerprint();

        // 2. WebGL fingerprint
        components.webgl = getWebGLFingerprint();

        // 3. User Agent
        components.ua = navigator.userAgent;

        // 4. Screen resolution
        components.screen = `${screen.width}x${screen.height}x${screen.colorDepth}`;

        // 5. Font stack detection
        components.fonts = detectFonts();

        // 6. Timezone
        components.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

        // 7. Language
        components.lang = navigator.language;

        // 8. Hardware concurrency
        components.cores = navigator.hardwareConcurrency || 0;

        // 9. Device memory (if available)
        components.memory = navigator.deviceMemory || 0;

        // 10. Platform
        components.platform = navigator.platform;

        // Generate hash from all components
        const raw = JSON.stringify(components);
        const hash = await sha256(raw);

        return { hash, components };
    }

    function getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');

            // Draw text with specific font
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(100, 5, 80, 25);
            ctx.fillStyle = '#069';
            ctx.fillText('Fingerprint@2x', 2, 15);

            // Draw geometric shapes
            ctx.beginPath();
            ctx.arc(50, 25, 10, 0, Math.PI * 2);
            ctx.fill();

            return canvas.toDataURL().substring(22); // Remove data URL prefix
        } catch (e) {
            return 'canvas-unavailable';
        }
    }

    function getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'webgl-unavailable';

            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
            const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';

            // Get supported extensions
            const extensions = gl.getSupportedExtensions();
            const extStr = extensions ? extensions.sort().join(',') : '';

            // Get max texture size
            const maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);

            return `${vendor}|${renderer}|${maxTexture}|${extStr.length}`;
        } catch (e) {
            return 'webgl-error';
        }
    }

    function detectFonts() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Courier New', 'Georgia', 'Helvetica', 'Times New Roman',
            'Verdana', 'Trebuchet MS', 'Palatino', 'Impact', 'Comic Sans MS',
            'Lucida Console', 'Monaco', 'Consolas', 'Tahoma', 'Arial Black',
            'Microsoft YaHei', 'SimHei', 'SimSun', 'KaiTi', 'FangSong'
        ];

        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        const span = document.createElement('span');
        span.style.position = 'absolute';
        span.style.left = '-9999px';
        span.style.fontSize = testSize;
        span.textContent = testString;
        document.body.appendChild(span);

        const baseWidths = {};
        for (const base of baseFonts) {
            span.style.fontFamily = base;
            baseWidths[base] = { w: span.offsetWidth, h: span.offsetHeight };
        }

        const detected = [];
        for (const font of testFonts) {
            let found = false;
            for (const base of baseFonts) {
                span.style.fontFamily = `'${font}', ${base}`;
                if (span.offsetWidth !== baseWidths[base].w || span.offsetHeight !== baseWidths[base].h) {
                    found = true;
                    break;
                }
            }
            if (found) detected.push(font);
        }

        document.body.removeChild(span);
        return detected.sort().join(',');
    }

    async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    return { generate };
})();
