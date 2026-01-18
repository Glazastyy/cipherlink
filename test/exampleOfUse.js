(async function () {
    const BASE = "https://h4f.me/url?ref=";
    const SELF_HOST = location.hostname;
    const SKIP_SCHEMES = ["mailto:", "tel:", "sms:", "whatsapp:", "tg:", "skype:", "javascript:"];
    const RECEIVER_PUBLIC_KEY = "TOKEN_HERE";

    function b64uToBuf(s) {
        s = s.replace(/-/g, "+").replace(/_/g, "/");
        s = s.padEnd(Math.ceil(s.length / 4) * 4, "=");
        return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    }

    function bufToB64u(b) {
        return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    async function encrypt(message) {
        const receiverKeyRaw = b64uToBuf(RECEIVER_PUBLIC_KEY);
        const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        const receiverKey = await crypto.subtle.importKey("raw", receiverKeyRaw, { name: "X25519" }, false, []);
        const shared = await crypto.subtle.deriveBits({ name: "X25519", public: receiverKey }, eph.privateKey, 256);
        const keyMaterial = await crypto.subtle.digest("SHA-256", shared);
        const aesKey = await crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, ["encrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            new TextEncoder().encode(message)
        ));
        const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
        const payload = new Uint8Array(ephPubRaw.length + iv.length + encrypted.length);
        payload.set(ephPubRaw, 0);
        payload.set(iv, 32);
        payload.set(encrypted, 44);
        return bufToB64u(payload);
    }

    function isInternal(href) {
        if (href.startsWith("/")) return true;
        try {
            const u = new URL(href, location.origin);
            return u.hostname === SELF_HOST;
        } catch {
            return true;
        }
    }

    async function rewrite() {
        const links = [...document.querySelectorAll("a[href]")];
        for (const a of links) {
            const href = a.getAttribute("href");
            if (!href) continue;
            if (href.startsWith("#")) continue;
            if (SKIP_SCHEMES.some(s => href.toLowerCase().startsWith(s))) continue;
            if (href.startsWith(BASE)) continue;
            if (isInternal(href)) continue;
            const encrypted = await encrypt(href);
            a.setAttribute("href", BASE + encrypted);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", rewrite);
    } else {
        rewrite();
    }
})();
